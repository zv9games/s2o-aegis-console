//! mTLS fleet server.

use crate::ca::FleetCa;
use crate::policy::FleetPolicy;
use crate::proto::{read_frame, write_frame, Request, Response};
use crate::store::Store;
use crate::{FleetError, FleetResult};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use s2o_audit::{AuditLog, SignedHead};
use s2o_policy::{ActionClass, AdminRoster, SignedBundle};
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Body of a `RotateCa` bundle (decision D6).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RotateCaBody {
    pub new_ca_pem: String,
    /// Days both CAs stay pinned on agents (default 30).
    #[serde(default = "default_overlap")]
    pub overlap_days: i64,
}

fn default_overlap() -> i64 {
    30
}

struct TrustState {
    /// CA that issues new client certificates.
    issuer: Arc<FleetCa>,
    /// CA certificates accepted for client certs (old + new during overlap).
    trusted: Vec<String>,
    acceptor: TlsAcceptor,
}

pub struct FleetServer {
    pub store: Arc<Store>,
    pub policy: FleetPolicy,
    roster: RwLock<Option<AdminRoster>>,
    next_ca: Option<Arc<FleetCa>>,
    audit: Option<Mutex<(AuditLog, ed25519_dalek::SigningKey)>>,
    server_cert_pem: String,
    server_key_pem: String,
    state: RwLock<TrustState>,
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

fn build_acceptor(trusted: &[String], cert_pem: &str, key_pem: &str) -> FleetResult<TlsAcceptor> {
    // Client certs are optional at the TLS layer (enrollment has none yet),
    // but any presented cert must chain to a trusted fleet CA and be in date.
    // Heartbeats additionally require one (checked in `dispatch`).
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store(&trusted.concat())?))
        .allow_unauthenticated()
        .build()
        .map_err(|e| FleetError::Protocol(e.to_string()))?;
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(cert_pem)?, parse_key(key_pem)?)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
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
        let trusted = vec![ca.cert_pem().to_string()];
        let acceptor = build_acceptor(&trusted, server_cert_pem, server_key_pem)?;
        Ok(Self {
            store,
            policy,
            roster: RwLock::new(None),
            next_ca: None,
            audit: None,
            server_cert_pem: server_cert_pem.into(),
            server_key_pem: server_key_pem.into(),
            state: RwLock::new(TrustState {
                issuer: ca,
                trusted,
                acceptor,
            }),
        })
    }

    /// Admin roster used to verify submitted bundles (defense in depth; the
    /// real check happens on agents against their own pinned roster).
    pub fn with_roster(mut self, roster: AdminRoster) -> Self {
        self.roster = RwLock::new(Some(roster));
        self
    }

    /// Prepared next CA, activated only by a verified `RotateCa` bundle.
    pub fn with_next_ca(mut self, ca: Arc<FleetCa>) -> Self {
        self.next_ca = Some(ca);
        self
    }

    /// Hash-chained audit log + key that signs its heads.
    pub fn with_audit(mut self, log: AuditLog, head_key: ed25519_dalek::SigningKey) -> Self {
        self.audit = Some(Mutex::new((log, head_key)));
        self
    }

    /// PEMs of all CA certs currently trusted for client certificates.
    pub fn trusted_cas(&self) -> Vec<String> {
        self.state.read().unwrap().trusted.clone()
    }

    fn audit(&self, actor: &str, action: &str, data: serde_json::Value) {
        if let Some(a) = &self.audit {
            let mut g = a.lock().unwrap();
            if let Err(e) = g.0.append(now(), actor, action, data) {
                eprintln!("[aegis-fleet] AUDIT WRITE FAILED: {e}");
            }
        }
    }

    fn audit_head(&self) -> Option<SignedHead> {
        self.audit.as_ref().and_then(|a| {
            let g = a.lock().unwrap();
            g.0.sign_head(&g.1)
        })
    }

    /// Record an admin action performed outside the network protocol (CLI).
    pub fn audit_admin(&self, actor: &str, action: &str, data: serde_json::Value) {
        self.audit(actor, action, data)
    }

    /// Switch to dual trust (old + prepared next CA) for a verified
    /// `RotateCa` bundle; new client certs are issued by the next CA.
    fn activate_rotation(&self, sb: &SignedBundle) -> FleetResult<()> {
        let body: RotateCaBody = serde_json::from_value(sb.bundle.body.clone())
            .map_err(|e| FleetError::Rejected(format!("bad rotate_ca body: {e}")))?;
        let next = self
            .next_ca
            .clone()
            .ok_or_else(|| FleetError::Rejected("no prepared next CA on this server".into()))?;
        if next.cert_pem() != body.new_ca_pem {
            return Err(FleetError::Rejected(
                "rotate_ca bundle does not match the prepared CA".into(),
            ));
        }
        let mut st = self.state.write().unwrap();
        if st.trusted.contains(&body.new_ca_pem) {
            return Ok(());
        }
        let mut trusted = st.trusted.clone();
        trusted.push(body.new_ca_pem.clone());
        st.acceptor = build_acceptor(&trusted, &self.server_cert_pem, &self.server_key_pem)?;
        st.trusted = trusted;
        st.issuer = next;
        Ok(())
    }

    /// On startup: re-activate a rotation already recorded in the store
    /// (bundles were verified when submitted).
    pub fn restore_from_store(&self) -> FleetResult<()> {
        for j in self.store.bundles_after(0)? {
            if let Ok(sb) = serde_json::from_str::<SignedBundle>(&j) {
                match sb.bundle.action {
                    ActionClass::RotateCa => self.activate_rotation(&sb)?,
                    ActionClass::ChangeRoster => {
                        if let Ok(r) = serde_json::from_value(sb.bundle.body.clone()) {
                            *self.roster.write().unwrap() = Some(r);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Accept a signed bundle for distribution. Requires a roster; verifies
    /// quorum and monotonic version. A `RotateCa` bundle also activates the
    /// prepared next CA (dual trust for the overlap period).
    pub fn submit_bundle(&self, sb: &SignedBundle) -> FleetResult<()> {
        let roster =
            self.roster.read().unwrap().clone().ok_or_else(|| {
                FleetError::Rejected("server has no admin roster configured".into())
            })?;
        let last = self.store.max_bundle_version()?;
        let v = s2o_policy::verify(sb, &roster, last)
            .map_err(|e| FleetError::Rejected(format!("bundle rejected: {e}")))?;
        if sb.bundle.action == ActionClass::RotateCa {
            self.activate_rotation(sb)?;
        }
        if sb.bundle.action == ActionClass::ChangeRoster {
            let new: AdminRoster = serde_json::from_value(sb.bundle.body.clone())
                .map_err(|e| FleetError::Rejected(format!("bad change_roster body: {e}")))?;
            *self.roster.write().unwrap() = Some(new);
        }
        let json = serde_json::to_string(sb).map_err(|e| FleetError::Protocol(e.to_string()))?;
        let action = serde_json::to_value(sb.bundle.action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        self.store
            .add_bundle(sb.bundle.version, &action, &json, now())?;
        self.audit(
            "admin-quorum",
            "policy.submit",
            serde_json::json!({
                "version": sb.bundle.version,
                "action": action,
                "approved_by": v.valid_keys,
                "warning": v.warning,
            }),
        );
        Ok(())
    }

    /// Accept connections forever.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> FleetResult<()> {
        loop {
            let (tcp, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let acceptor = me.state.read().unwrap().acceptor.clone();
                if let Ok(tls) = acceptor.accept(tcp).await {
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
                let issuer = self.state.read().unwrap().issuer.clone();
                let (cert_pem, not_after) =
                    issuer.issue_client_cert(&csr_pem, &agent_id, self.policy.cert_ttl)?;
                self.store.add_agent(
                    &agent_id,
                    &hostname,
                    &cyberid_pubkey,
                    &spki,
                    hardware_backed,
                    now(),
                    not_after,
                )?;
                self.audit(
                    &format!("agent:{agent_id}"),
                    "agent.enroll",
                    serde_json::json!({"hostname": hostname, "hardware_backed": hardware_backed}),
                );
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
                let issuer = self.state.read().unwrap().issuer.clone();
                let (cert_pem, na) =
                    issuer.issue_client_cert(&csr_pem, &agent_id, self.policy.cert_ttl)?;
                self.store.set_cert_not_after(&agent_id, na)?;
                self.audit(
                    &format!("agent:{agent_id}"),
                    "agent.renew",
                    serde_json::json!({"via_mtls": via_mtls, "not_after": na}),
                );
                Ok(Response::Renewed {
                    agent_id,
                    cert_pem,
                    not_after_unix: na,
                })
            }
            Request::Heartbeat {
                posture,
                cyberid_token,
                last_policy_version,
                policy_results,
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
                for r in &policy_results {
                    let status = serde_json::to_value(&r.status)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default();
                    self.store.record_policy_result(
                        &agent_id,
                        r.version,
                        &status,
                        &r.detail,
                        now(),
                    )?;
                    self.audit(
                        &format!("agent:{agent_id}"),
                        "policy.result",
                        serde_json::json!({"version": r.version, "status": status, "detail": r.detail}),
                    );
                }
                let bundles = self
                    .store
                    .bundles_after(last_policy_version)?
                    .iter()
                    .filter_map(|j| serde_json::from_str::<SignedBundle>(j).ok())
                    .filter(|b| b.bundle.targets.is_empty() || b.bundle.targets.contains(&agent_id))
                    .collect();
                Ok(Response::HeartbeatAck {
                    agent_id,
                    server_time_unix: now(),
                    bundles,
                    audit_head: self.audit_head(),
                })
            }
        }
    }
}
