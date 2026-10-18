//! Agent-side enrollment and heartbeat client.

use crate::keystore::AgentKeyStore;
use crate::proto::{read_frame, write_frame, Request, Response};
use crate::server::{parse_certs, root_store};
use crate::{FleetError, FleetResult};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Where and how to reach the fleet server. `ca_pem` is pinned: it is the
/// only trust root, delivered out-of-band together with the enrollment token.
#[derive(Clone)]
pub struct FleetEndpoint {
    pub addr: String,
    pub server_name: String,
    pub ca_pem: String,
}

async fn exchange(
    ep: &FleetEndpoint,
    cfg: rustls::ClientConfig,
    req: &Request,
) -> FleetResult<Response> {
    let name = ServerName::try_from(ep.server_name.clone())
        .map_err(|e| FleetError::Protocol(e.to_string()))?;
    let tcp = TcpStream::connect(&ep.addr).await?;
    let mut tls = TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?;
    write_frame(&mut tls, req).await?;
    read_frame(&mut tls).await
}

pub struct Enrollment {
    pub agent_id: String,
    pub cert_pem: String,
    pub not_after_unix: i64,
}

pub async fn enroll(
    ep: &FleetEndpoint,
    keys: &dyn AgentKeyStore,
    token: &str,
    hostname: &str,
    cyberid_pubkey: &str,
) -> FleetResult<Enrollment> {
    crate::init_crypto();
    let csr_pem = csr(keys)?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store(&ep.ca_pem)?)
        .with_no_client_auth();
    let req = Request::Enroll {
        token: token.to_string(),
        csr_pem,
        hostname: hostname.to_string(),
        cyberid_pubkey: cyberid_pubkey.to_string(),
        hardware_backed: keys.is_hardware_backed(),
    };
    match exchange(ep, cfg, &req).await? {
        Response::Enrolled {
            agent_id,
            cert_pem,
            not_after_unix,
        } => Ok(Enrollment {
            agent_id,
            cert_pem,
            not_after_unix,
        }),
        Response::Error { message } => Err(FleetError::Rejected(message)),
        other => Err(FleetError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

fn csr(keys: &dyn AgentKeyStore) -> FleetResult<String> {
    Ok(rcgen::CertificateParams::new(Vec::<String>::new())?
        .serialize_request(keys.key_pair())?
        .pem()?)
}

fn mtls_config(
    ep: &FleetEndpoint,
    keys: &dyn AgentKeyStore,
    cert_pem: &str,
) -> FleetResult<rustls::ClientConfig> {
    let der = keys.private_key_der().ok_or_else(|| {
        FleetError::Protocol(
            "key store cannot export key; hardware signer not implemented yet".into(),
        )
    })?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store(&ep.ca_pem)?)
        .with_client_auth_cert(
            parse_certs(cert_pem)?,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        )?)
}

/// Renew the client certificate with the same key. Pass the current cert
/// while it is still valid (mTLS); pass `None` once it has expired, which is
/// accepted only within the server's offline grace period.
pub async fn renew(
    ep: &FleetEndpoint,
    keys: &dyn AgentKeyStore,
    agent_id: &str,
    current_cert_pem: Option<&str>,
) -> FleetResult<Enrollment> {
    crate::init_crypto();
    let cfg = match current_cert_pem {
        Some(c) => mtls_config(ep, keys, c)?,
        None => rustls::ClientConfig::builder()
            .with_root_certificates(root_store(&ep.ca_pem)?)
            .with_no_client_auth(),
    };
    let req = Request::Renew {
        agent_id: Some(agent_id.to_string()),
        csr_pem: csr(keys)?,
    };
    match exchange(ep, cfg, &req).await? {
        Response::Renewed {
            agent_id,
            cert_pem,
            not_after_unix,
        } => Ok(Enrollment {
            agent_id,
            cert_pem,
            not_after_unix,
        }),
        Response::Error { message } => Err(FleetError::Rejected(message)),
        other => Err(FleetError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

/// Heartbeat reporting policy progress; returns the server response.
pub async fn heartbeat_full(
    ep: &FleetEndpoint,
    keys: &dyn AgentKeyStore,
    cert_pem: &str,
    posture: serde_json::Value,
    cyberid_token: &str,
    last_policy_version: u64,
    policy_results: Vec<crate::proto::PolicyResult>,
) -> FleetResult<Response> {
    crate::init_crypto();
    let cfg = mtls_config(ep, keys, cert_pem)?;
    let req = Request::Heartbeat {
        posture,
        cyberid_token: cyberid_token.to_string(),
        last_policy_version,
        policy_results,
    };
    exchange(ep, cfg, &req).await
}

pub async fn heartbeat(
    ep: &FleetEndpoint,
    keys: &dyn AgentKeyStore,
    cert_pem: &str,
    posture: serde_json::Value,
    cyberid_token: &str,
) -> FleetResult<Response> {
    heartbeat_full(ep, keys, cert_pem, posture, cyberid_token, 0, Vec::new()).await
}
