//! Embedded SQLite store: enrollment tokens (hashed) and agents.

use crate::FleetResult;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Unknown,
    Expired,
    AlreadyUsed,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Unknown => "unknown enrollment token",
            TokenError::Expired => "enrollment token expired",
            TokenError::AlreadyUsed => "enrollment token already used",
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub hostname: String,
    pub hardware_backed: bool,
    pub enrolled_at: i64,
    pub cert_not_after: i64,
    pub last_seen: Option<i64>,
    pub revoked: bool,
    pub last_posture: Option<String>,
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    used_by TEXT
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    cyberid_pubkey TEXT NOT NULL,
    hardware_backed INTEGER NOT NULL,
    enrolled_at INTEGER NOT NULL,
    cert_not_after INTEGER NOT NULL,
    last_seen INTEGER,
    last_posture TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);";

impl Store {
    pub fn open(path: &Path) -> FleetResult<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> FleetResult<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> FleetResult<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create a one-time token; returns the plaintext (shown once, never stored).
    pub fn create_token(&self, now: i64, ttl_secs: i64) -> FleetResult<String> {
        let mut raw = [0u8; 32];
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut raw);
        let token = hex::encode(raw);
        self.conn.lock().unwrap().execute(
            "INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![hash_token(&token), now, now + ttl_secs],
        )?;
        Ok(token)
    }

    /// Atomically mark a token used. Fails if unknown, expired or used.
    pub fn consume_token(
        &self,
        token: &str,
        now: i64,
        used_by: &str,
    ) -> FleetResult<Result<(), TokenError>> {
        let h = hash_token(token);
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE enrollment_tokens SET used_at = ?1, used_by = ?2
             WHERE token_hash = ?3 AND used_at IS NULL AND expires_at >= ?1",
            params![now, used_by, h],
        )?;
        if changed == 1 {
            return Ok(Ok(()));
        }
        let row: Option<(i64, Option<i64>)> = conn
            .query_row(
                "SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?1",
                params![h],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(Err(match row {
            None => TokenError::Unknown,
            Some((_, Some(_))) => TokenError::AlreadyUsed,
            Some(_) => TokenError::Expired,
        }))
    }

    pub fn add_agent(
        &self,
        agent_id: &str,
        hostname: &str,
        cyberid_pubkey: &str,
        hardware_backed: bool,
        now: i64,
        cert_not_after: i64,
    ) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO agents (agent_id, hostname, cyberid_pubkey, hardware_backed, enrolled_at, cert_not_after)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![agent_id, hostname, cyberid_pubkey, hardware_backed, now, cert_not_after],
        )?;
        Ok(())
    }

    /// (cyberid_pubkey, revoked) for an agent.
    pub fn agent_auth(&self, agent_id: &str) -> FleetResult<Option<(String, bool)>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT cyberid_pubkey, revoked FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn record_heartbeat(&self, agent_id: &str, now: i64, posture: &str) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE agents SET last_seen = ?1, last_posture = ?2 WHERE agent_id = ?3",
            params![now, posture, agent_id],
        )?;
        Ok(())
    }

    pub fn revoke(&self, agent_id: &str) -> FleetResult<bool> {
        Ok(self.conn.lock().unwrap().execute(
            "UPDATE agents SET revoked = 1 WHERE agent_id = ?1",
            params![agent_id],
        )? == 1)
    }

    pub fn list_agents(&self) -> FleetResult<Vec<AgentRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare(
            "SELECT agent_id, hostname, hardware_backed, enrolled_at, cert_not_after, last_seen, revoked, last_posture
             FROM agents ORDER BY enrolled_at",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(AgentRecord {
                    agent_id: r.get(0)?,
                    hostname: r.get(1)?,
                    hardware_backed: r.get(2)?,
                    enrolled_at: r.get(3)?,
                    cert_not_after: r.get(4)?,
                    last_seen: r.get(5)?,
                    revoked: r.get(6)?,
                    last_posture: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lifecycle() {
        let s = Store::in_memory().unwrap();
        let t = s.create_token(100, 60).unwrap();
        assert_eq!(
            s.consume_token("nope", 110, "a").unwrap(),
            Err(TokenError::Unknown)
        );
        assert_eq!(s.consume_token(&t, 110, "a").unwrap(), Ok(()));
        assert_eq!(
            s.consume_token(&t, 111, "b").unwrap(),
            Err(TokenError::AlreadyUsed)
        );
        let t2 = s.create_token(100, 60).unwrap();
        assert_eq!(
            s.consume_token(&t2, 161, "c").unwrap(),
            Err(TokenError::Expired)
        );
    }
}
