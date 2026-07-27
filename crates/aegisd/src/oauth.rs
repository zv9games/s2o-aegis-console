//! Lab OAuth 2.0 device authorization grant (RFC 8628) — not a full IdP UI.
//!
//! Flow: device_authorization → user approve (CLI or form) → token poll → JWT access_token.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuth {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub status: DeviceStatus,
    #[serde(default)]
    pub user: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub access_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceStore {
    pub devices: Vec<DeviceAuth>,
}

impl DeviceStore {
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
        // prune expired
        let mut clean = self.clone();
        let now = Utc::now();
        clean.devices.retain(|d| {
            chrono::DateTime::parse_from_rfc3339(&d.expires_at)
                .map(|t| t.with_timezone(&Utc) > now)
                .unwrap_or(false)
                || d.status == DeviceStatus::Approved
        });
        fs::write(
            path,
            serde_json::to_string_pretty(&clean).unwrap_or_else(|_| "{}".into()),
        )
    }

    pub fn create(&mut self, client_id: &str, ttl_secs: i64) -> DeviceAuth {
        let now = Utc::now();
        let exp = now + Duration::seconds(ttl_secs.max(60));
        let device_code = format!("dev_{}", uuid_simple());
        let user_code = user_code_human();
        let d = DeviceAuth {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client_id.to_string(),
            status: DeviceStatus::Pending,
            user: None,
            created_at: now.to_rfc3339(),
            expires_at: exp.to_rfc3339(),
            access_token: None,
        };
        self.devices.push(d.clone());
        d
    }

    pub fn find_device_code(&self, code: &str) -> Option<&DeviceAuth> {
        self.devices.iter().find(|d| d.device_code == code)
    }

    #[allow(dead_code)]
    pub fn find_user_code(&self, code: &str) -> Option<&DeviceAuth> {
        let c = code.trim().to_ascii_uppercase().replace(' ', "-");
        self.devices.iter().find(|d| d.user_code == c || d.user_code.replace('-', "") == c.replace('-', ""))
    }

    pub fn approve(&mut self, user_code: &str, user: &str) -> Result<&DeviceAuth, String> {
        let c = user_code.trim().to_ascii_uppercase().replace(' ', "-");
        let now = Utc::now();
        for d in &mut self.devices {
            if d.user_code == c || d.user_code.replace('-', "") == c.replace('-', "") {
                let exp = chrono::DateTime::parse_from_rfc3339(&d.expires_at)
                    .map(|t| t.with_timezone(&Utc))
                    .ok();
                if exp.map(|e| e <= now).unwrap_or(true) {
                    d.status = DeviceStatus::Expired;
                    return Err("device code expired".into());
                }
                if d.status != DeviceStatus::Pending {
                    return Err(format!("device not pending (status={:?})", d.status));
                }
                d.status = DeviceStatus::Approved;
                d.user = Some(user.to_string());
                return Ok(d);
            }
        }
        Err("unknown user_code".into())
    }

    pub fn set_token(&mut self, device_code: &str, token: String) -> bool {
        for d in &mut self.devices {
            if d.device_code == device_code {
                d.access_token = Some(token);
                return true;
            }
        }
        false
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{t:x}")
}

fn user_code_human() -> String {
    // ABCD-EFGH style (no ambiguous 0/O/1/I)
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut out = String::new();
    for i in 0..8 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let idx = (seed >> 33) as usize % CHARS.len();
        out.push(CHARS[idx] as char);
        if i == 3 {
            out.push('-');
        }
    }
    out
}

/// Mint HS256 access token if no RSA key; prefer RS256 lab key.
pub fn mint_access_token(
    user: &str,
    issuer: &str,
    ttl_hours: i64,
    private_pem_path: &Path,
    jwt_secret: Option<&str>,
) -> Result<String, String> {
    if private_pem_path.exists() {
        let pem = fs::read_to_string(private_pem_path).map_err(|e| e.to_string())?;
        // kid from sibling jwks if present
        let kid = private_pem_path.parent().and_then(|dir| {
            let jwks = dir.join("jwks.json");
            fs::read_to_string(jwks)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|j| {
                    j.get("keys")
                        .and_then(|k| k.as_array())
                        .and_then(|a| a.first())
                        .and_then(|k| k.get("kid"))
                        .and_then(|k| k.as_str())
                        .map(|s| s.to_string())
                })
        });
        return mint_rs256(&pem, kid.as_deref(), user, ttl_hours, issuer);
    }
    if let Some(secret) = jwt_secret {
        return mint_hs256(secret, user, ttl_hours, issuer);
    }
    // ephemeral HS secret stored next to devices (dev only)
    let secret = "s2o-lab-oauth-dev-secret";
    mint_hs256(secret, user, ttl_hours, issuer)
}

fn mint_hs256(secret: &str, user: &str, ttl_hours: i64, issuer: &str) -> Result<String, String> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": user,
        "iss": issuer,
        "iat": now,
        "exp": now + ttl_hours.max(1) * 3600,
        "posture": 80,
    });
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

fn mint_rs256(
    private_pem: &str,
    kid: Option<&str>,
    user: &str,
    ttl_hours: i64,
    issuer: &str,
) -> Result<String, String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": user,
        "iss": issuer,
        "iat": now,
        "exp": now + ttl_hours.max(1) * 3600,
        "posture": 80,
    });
    let mut header = Header::new(Algorithm::RS256);
    if let Some(k) = kid {
        header.kid = Some(k.to_string());
    }
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

pub fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for pair in body.split('&') {
        let mut it = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            m.insert(
                urlencoding_decode(k),
                urlencoding_decode(v),
            );
        }
    }
    m
}

fn urlencoding_decode(s: &str) -> String {
    // minimal: + and %XX
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
            if let Ok(v) = u8::from_str_radix(h, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn device_approve_page(user_code: Option<&str>, message: Option<&str>) -> String {
    let prefill = user_code.unwrap_or("");
    let msg = message.unwrap_or("Enter the code shown on your device.");
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>S2O Device Login</title>
<style>body{{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:1rem}}
input,button{{font-size:1.1rem;padding:.5rem;width:100%;margin:.4rem 0}}
.msg{{color:#064;margin-bottom:1rem}}</style></head>
<body>
<h1>S2O Aegis device login</h1>
<p class="msg">{msg}</p>
<form method="POST" action="/oauth/device_approve">
<label>User code</label>
<input name="user_code" value="{prefill}" autocomplete="one-time-code" required>
<label>User name</label>
<input name="user" value="operator" required>
<button type="submit">Approve</button>
</form>
<p style="color:#666;font-size:.9rem">Lab flow only — not a production IdP.</p>
</body></html>"#
    )
}

#[allow(dead_code)]
pub fn default_devices_path() -> PathBuf {
    PathBuf::from(".aegis/oauth-devices.json")
}
