//! Wire protocol: 4-byte big-endian length prefix + JSON, max 1 MiB/frame.

use crate::{FleetError, FleetResult};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Enroll {
        token: String,
        csr_pem: String,
        hostname: String,
        /// Base64url Ed25519 key used to verify this agent's cyberid tokens.
        cyberid_pubkey: String,
        hardware_backed: bool,
    },
    /// Renew the client certificate, keeping the enrolled key.
    /// Over mTLS (valid cert): `agent_id` is ignored, identity comes from the cert.
    /// Without a client cert (cert expired while offline): `agent_id` is
    /// required and the CSR, which is self-signed by the agent key, must match
    /// the enrolled key and arrive within the offline grace period.
    Renew {
        agent_id: Option<String>,
        csr_pem: String,
    },
    Heartbeat {
        /// Free-form posture snapshot (informational; untrusted).
        posture: serde_json::Value,
        /// cyberid JWS; verified against the key pinned at enrollment.
        cyberid_token: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Enrolled {
        agent_id: String,
        cert_pem: String,
        not_after_unix: i64,
    },
    Renewed {
        agent_id: String,
        cert_pem: String,
        not_after_unix: i64,
    },
    HeartbeatAck {
        agent_id: String,
        server_time_unix: i64,
    },
    Error {
        message: String,
    },
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> FleetResult<()> {
    let body = serde_json::to_vec(msg).map_err(|e| FleetError::Protocol(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FleetError::Protocol("frame too large".into()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> FleetResult<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FleetError::Protocol("frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| FleetError::Protocol(e.to_string()))
}
