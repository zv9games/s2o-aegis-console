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
        };
        self.sessions.push(s.clone());
        s
    }

    pub fn active(&self) -> impl Iterator<Item = &Session> {
        let now = Utc::now();
        self.sessions.iter().filter(move |s| {
            if s.revoked {
                return false;
            }
            chrono::DateTime::parse_from_rfc3339(&s.expires_at)
                .map(|t| t.with_timezone(&Utc) > now)
                .unwrap_or(false)
        })
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
}
