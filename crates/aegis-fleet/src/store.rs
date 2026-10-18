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
    key_spki TEXT NOT NULL,
    hardware_backed INTEGER NOT NULL,
    enrolled_at INTEGER NOT NULL,
    cert_not_after INTEGER NOT NULL,
    last_seen INTEGER,
    last_posture TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_pins (
    agent_id TEXT PRIMARY KEY,
    pins TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bundles (
    version INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    json TEXT NOT NULL,
    submitted_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_results (
    agent_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL,
    reported_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, version)
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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

    #[allow(clippy::too_many_arguments)]
    pub fn add_agent(
        &self,
        agent_id: &str,
        hostname: &str,
        cyberid_pubkey: &str,
        key_spki_hex: &str,
        hardware_backed: bool,
        now: i64,
        cert_not_after: i64,
    ) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO agents (agent_id, hostname, cyberid_pubkey, key_spki, hardware_backed, enrolled_at, cert_not_after)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![agent_id, hostname, cyberid_pubkey, key_spki_hex, hardware_backed, now, cert_not_after],
        )?;
        Ok(())
    }

    /// (key_spki_hex, cert_not_after, revoked) for an agent.
    pub fn agent_key(&self, agent_id: &str) -> FleetResult<Option<(String, i64, bool)>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT key_spki, cert_not_after, revoked FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    pub fn set_cert_not_after(&self, agent_id: &str, not_after: i64) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE agents SET cert_not_after = ?1 WHERE agent_id = ?2",
            params![not_after, agent_id],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> FleetResult<Option<String>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn max_bundle_version(&self) -> FleetResult<u64> {
        let v: Option<i64> =
            self.conn
                .lock()
                .unwrap()
                .query_row("SELECT MAX(version) FROM bundles", [], |r| r.get(0))?;
        Ok(v.unwrap_or(0) as u64)
    }

    pub fn add_bundle(&self, version: u64, action: &str, json: &str, now: i64) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO bundles (version, action, json, submitted_at) VALUES (?1, ?2, ?3, ?4)",
            params![version as i64, action, json, now],
        )?;
        Ok(())
    }

    /// Bundle JSON documents with version > `after`, oldest first.
    pub fn bundles_after(&self, after: u64) -> FleetResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut st =
            conn.prepare("SELECT json FROM bundles WHERE version > ?1 ORDER BY version")?;
        let rows = st
            .query_map(params![after as i64], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    pub fn record_policy_result(
        &self,
        agent_id: &str,
        version: u64,
        status: &str,
        detail: &str,
        now: i64,
    ) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO policy_results (agent_id, version, status, detail, reported_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![agent_id, version as i64, status, detail, now],
        )?;
        Ok(())
    }

    /// (agent_id, version, status, detail)
    pub fn policy_results(&self) -> FleetResult<Vec<(String, u64, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare(
            "SELECT agent_id, version, status, detail FROM policy_results ORDER BY reported_at",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Persisted `require_hardware_keys` setting (default false).
    pub fn require_hardware_keys(&self) -> FleetResult<bool> {
        Ok(self.get_setting("require_hardware_keys")?.as_deref() == Some("true"))
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

    pub fn set_agent_pins(&self, agent_id: &str, pins: &[String]) -> FleetResult<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO agent_pins (agent_id, pins) VALUES (?1, ?2)",
            params![agent_id, pins.join(",")],
        )?;
        Ok(())
    }

    /// Non-revoked agents that have not reported pinning `fingerprint`.
    pub fn agents_missing_pin(&self, fingerprint: &str) -> FleetResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare(
            "SELECT a.agent_id, p.pins FROM agents a LEFT JOIN agent_pins p ON a.agent_id = p.agent_id
             WHERE a.revoked = 0",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|(_, p)| {
                !p.as_deref()
                    .unwrap_or("")
                    .split(',')
                    .any(|x| x == fingerprint)
            })
            .map(|(a, _)| a)
            .collect())
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
