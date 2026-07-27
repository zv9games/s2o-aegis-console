//! Local file-backed session tokens (posture-gated login MVP).

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub token: String,
    pub user: String,
    pub host_id: String,
    pub posture_score: u32,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub revoked: bool,
    /// Last successful Gate (or verify) use; RFC3339
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
}

/// Verified session snapshot returned by `verify` / `touch`.
#[derive(Debug, Clone)]
pub struct VerifiedSession {
    pub id: String,
    pub user: String,
    pub posture_score: u32,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStore {
    pub sessions: Vec<Session>,
}

impl SessionStore {
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(
            path,
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into()),
        )
    }

    pub fn mint(
        &mut self,
        user: &str,
        host_id: &str,
        posture_score: u32,
        ttl_hours: i64,
    ) -> Session {
        let now = Utc::now();
        let exp = now + Duration::hours(ttl_hours.max(1));
        let token = format!("aegis_{}", Uuid::new_v4().to_string().replace('-', ""));
        let s = Session {
            id: Uuid::new_v4().to_string(),
            token: token.clone(),
            user: user.to_string(),
            host_id: host_id.to_string(),
            posture_score,
            issued_at: now.to_rfc3339(),
            expires_at: exp.to_rfc3339(),
            revoked: false,
            last_used: None,
        };
        self.sessions.push(s.clone());
        s
    }

    fn is_active(s: &Session, now: chrono::DateTime<Utc>) -> bool {
        if s.revoked {
            return false;
        }
        chrono::DateTime::parse_from_rfc3339(&s.expires_at)
            .map(|t| t.with_timezone(&Utc) > now)
            .unwrap_or(false)
    }

    pub fn active(&self) -> impl Iterator<Item = &Session> {
        let now = Utc::now();
        self.sessions
            .iter()
            .filter(move |s| Self::is_active(s, now))
    }

    pub fn revoke_token(&mut self, token: &str) -> bool {
        let mut hit = false;
        for s in &mut self.sessions {
            if s.token == token || s.id == token {
                s.revoked = true;
                hit = true;
            }
        }
        hit
    }

    pub fn verify(&self, token: &str) -> Option<&Session> {
        self.active().find(|s| s.token == token)
    }

    /// Verify and stamp `last_used`. Returns a snapshot if the token is active.
    pub fn touch(&mut self, token: &str) -> Option<VerifiedSession> {
        let now = Utc::now();
        let now_s = now.to_rfc3339();
        for s in &mut self.sessions {
            if s.token != token {
                continue;
            }
            if !Self::is_active(s, now) {
                return None;
            }
            s.last_used = Some(now_s);
            return Some(VerifiedSession {
                id: s.id.clone(),
                user: s.user.clone(),
                posture_score: s.posture_score,
                expires_at: s.expires_at.clone(),
            });
        }
        None
    }

    /// Drop expired and revoked sessions. Returns count removed.
    pub fn gc(&mut self) -> usize {
        let before = self.sessions.len();
        let now = Utc::now();
        self.sessions.retain(|s| Self::is_active(s, now));
        before.saturating_sub(self.sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn mint_verify_touch_revoke() {
        let mut store = SessionStore::default();
        let s = store.mint("alice", "host1", 80, 8);
        assert!(store.verify(&s.token).is_some());
        let v = store.touch(&s.token).expect("touch");
        assert_eq!(v.user, "alice");
        assert_eq!(v.posture_score, 80);
        assert!(store.verify(&s.token).unwrap().last_used.is_some());
        assert!(store.revoke_token(&s.token));
        assert!(store.verify(&s.token).is_none());
        assert!(store.touch(&s.token).is_none());
    }

    #[test]
    fn gc_removes_revoked() {
        let mut store = SessionStore::default();
        let s = store.mint("bob", "h", 50, 8);
        store.revoke_token(&s.token);
        assert_eq!(store.gc(), 1);
        assert!(store.sessions.is_empty());
        let _ = PathBuf::from("unused");
    }
}
