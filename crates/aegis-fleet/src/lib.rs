//! S2O Aegis fleet server and agent enrollment client.
//!
//! Design (see ARCHITECTURE.md §5.1):
//! 1. An admin creates a one-time enrollment token (256-bit random, stored
//!    only as a SHA-256 hash, short TTL, single use).
//! 2. The agent generates a keypair in its [`keystore::AgentKeyStore`], builds
//!    a CSR, and sends `token + CSR + cyberid public key` over TLS, pinning the
//!    fleet CA certificate it received out-of-band with the token.
//! 3. The server burns the token and issues a short-lived client certificate
//!    (CN = server-assigned agent id, EKU clientAuth). Subject/SANs from the
//!    CSR are ignored; only its public key is used.
//! 4. All further traffic (heartbeats) is mutual TLS. The server derives the
//!    agent id from the verified client certificate, never from the payload.
//!
//! Self-hosted only, embedded SQLite. Not yet wired into `aegisd`.

pub mod agent;
pub mod ca;
pub mod keystore;
pub mod proto;
pub mod server;
pub mod store;

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("certificate error: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("enrollment rejected: {0}")]
    Rejected(String),
}

pub type FleetResult<T> = Result<T, FleetError>;

/// Install the ring crypto provider as the process default (idempotent).
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
