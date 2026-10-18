//! mTLS fleet server.

use crate::ca::FleetCa;
use crate::policy::FleetPolicy;
use crate::proto::{read_frame, write_frame, Request, Response};
use crate::store::Store;
use crate::{FleetError, FleetResult};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct FleetServer {
    pub ca: Arc<FleetCa>,
    pub store: Arc<Store>,
    pub policy: FleetPolicy,
    acceptor: TlsAcceptor,
}

pub(crate) fn parse_certs(pem: &str) -> FleetResult<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(FleetError::Io)
}

pub(crate) fn parse_key(pem: &str) -> FleetResult<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())?
        .ok_or_else(|| FleetError::Protocol("no private key in PEM".into()))
}

pub(crate) fn root_store(ca_pem: &str) -> FleetResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for c in parse_certs(ca_pem)? {
        roots.add(c)?;
    }
    Ok(roots)
}

/// Agent id = CN of a verified client certificate.
fn agent_id_from_cert(der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_string();
    Some(cn)
}

/// Verify a CSR's self-signature (proof of key possession) and return its
/// SubjectPublicKeyInfo as hex.
fn csr_spki_hex(csr_pem: &str) -> FleetResult<String> {
    use x509_parser::prelude::FromDer;
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|e| FleetError::Rejected(format!("bad CSR PEM: {e}")))?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|e| FleetError::Rejected(format!("bad CSR: {e}")))?;
    csr.verify_signature()
        .map_err(|_| FleetError::Rejected("CSR signature invalid".into()))?;
    Ok(hex::encode(csr.certification_request_info.subject_pki.raw))
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl FleetServer {
    pub fn new(
        ca: Arc<FleetCa>,
        store: Arc<Store>,
        server_cert_pem: &str,
        server_key_pem: &str,
        policy: FleetPolicy,
    ) -> FleetResult<Self> {
        crate::init_crypto();
        // Client certs are optional at the TLS layer (enrollment has none yet),
        // but any presented cert must chain to the fleet CA and be in date.
        // Heartbeats additionally require one (checked in `handle`).
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store(ca.cert_pem())?))
            .allow_unauthenticated()
            .build()
            .map_err(|e| FleetError::Protocol(e.to_string()))?;
        let cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(parse_certs(server_cert_pem)?, parse_key(server_key_pem)?)?;
        Ok(Self {
            ca,
            store,
            policy,
            acceptor: TlsAcceptor::from(Arc::new(cfg)),
        })
    }

    /// Accept connections forever.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> FleetResult<()> {
        loop {
            let (tcp, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Ok(tls) = me.acceptor.accept(tcp).await {
                    let _ = me.handle(tls).await;
                }
            });
        }
    }

    async fn handle(
        &self,
        mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> FleetResult<()> {
        let peer_agent = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(agent_id_from_cert);
        let req: Request = read_frame(&mut tls).await?;
        let resp = match self.dispatch(req, peer_agent).await {
            Ok(r) => r,
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        };
        write_frame(&mut tls, &resp).await
    }

    async fn dispatch(&self, req: Request, peer_agent: Option<String>) -> FleetResult<Response> {
        match req {
            Request::Enroll {
                token,
                csr_pem,
                hostname,
                cyberid_pubkey,
                hardware_backed,
            } => {
                if !hardware_backed
                    && (self.policy.require_hardware_keys || self.store.require_hardware_keys()?)
                {
                    // Checked before the token is consumed so it is not wasted.
                    return Err(FleetError::Rejected(
                        "this fleet requires hardware-backed (TPM) agent keys".into(),
                    ));
                }
                let spki = csr_spki_hex(&csr_pem)?;
                s2o_attest::parse_public_key(&cyberid_pubkey)
                    .map_err(|e| FleetError::Rejected(format!("bad cyberid_pubkey: {e}")))?;
                let agent_id = {
                    let mut b = [0u8; 16];
                    rand::Rng::fill(&mut rand::rngs::OsRng, &mut b);
                    format!("agent-{}", hex::encode(b))
                };
                // Burn the token first so a failure later cannot be retried with it.
                if let Err(e) = self.store.consume_token(&token, now(), &agent_id)? {
                    return Err(FleetError::Rejected(e.to_string()));
                }
                let (cert_pem, not_after) =
                    self.ca
                        .issue_client_cert(&csr_pem, &agent_id, self.policy.cert_ttl)?;
                self.store.add_agent(
                    &agent_id,
                    &hostname,
                    &cyberid_pubkey,
                    &spki,
                    hardware_backed,
                    now(),
                    not_after,
                )?;
                Ok(Response::Enrolled {
                    agent_id,
                    cert_pem,
                    not_after_unix: not_after,
                })
            }
            Request::Renew { agent_id, csr_pem } => {
                let (agent_id, via_mtls) = match (peer_agent, agent_id) {
                    (Some(id), _) => (id, true),
                    (None, Some(id)) => (id, false),
                    (None, None) => {
                        return Err(FleetError::Rejected(
                            "renew needs a client cert or agent_id".into(),
                        ))
                    }
                };
                let (spki, not_after, revoked) = self
                    .store
                    .agent_key(&agent_id)?
                    .ok_or_else(|| FleetError::Rejected("unknown agent".into()))?;
                if revoked {
                    return Err(FleetError::Rejected("agent revoked".into()));
                }
                if csr_spki_hex(&csr_pem)? != spki {
                    return Err(FleetError::Rejected(
                        "CSR key does not match the enrolled key".into(),
                    ));
                }
                if !via_mtls && !self.policy.within_grace(not_after, now()) {
                    return Err(FleetError::Rejected(
                        "offline grace period exceeded; re-enroll with a new token".into(),
                    ));
                }
                let (cert_pem, na) =
                    self.ca
                        .issue_client_cert(&csr_pem, &agent_id, self.policy.cert_ttl)?;
                self.store.set_cert_not_after(&agent_id, na)?;
                Ok(Response::Renewed {
                    agent_id,
                    cert_pem,
                    not_after_unix: na,
                })
            }
            Request::Heartbeat {
                posture,
                cyberid_token,
            } => {
                let agent_id = peer_agent.ok_or_else(|| {
                    FleetError::Rejected("heartbeat requires a client certificate".into())
                })?;
                let (pubkey, revoked) = self
                    .store
                    .agent_auth(&agent_id)?
                    .ok_or_else(|| FleetError::Rejected("unknown agent".into()))?;
                if revoked {
                    return Err(FleetError::Rejected("agent revoked".into()));
                }
                let vk = s2o_attest::parse_public_key(&pubkey)
                    .map_err(|e| FleetError::Protocol(e.to_string()))?;
                let claims = s2o_attest::verify(&vk, &cyberid_token, now())
                    .map_err(|e| FleetError::Rejected(format!("cyberid token: {e}")))?;
                let record = serde_json::json!({ "reported": posture, "attested": claims });
                self.store
                    .record_heartbeat(&agent_id, now(), &record.to_string())?;
                Ok(Response::HeartbeatAck {
                    agent_id,
                    server_time_unix: now(),
                })
            }
        }
    }
}
