//! Lab OAuth 2.0 grants for aegisd IdP stub — not a production IdP.
//!
//! - Device (RFC 8628): device_authorization → approve → token poll
//! - Authorization code: /oauth/authorize → code → /oauth/token (lab HTML + JSON)

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

// ---------------------------------------------------------------------------
// Authorization code grant (lab)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user: String,
    #[serde(default)]
    pub state: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthCodeStore {
    pub codes: Vec<AuthCode>,
}

impl AuthCodeStore {
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
        let mut clean = self.clone();
        let now = Utc::now();
        clean.codes.retain(|c| {
            !c.used
                && chrono::DateTime::parse_from_rfc3339(&c.expires_at)
                    .map(|t| t.with_timezone(&Utc) > now)
                    .unwrap_or(false)
        });
        fs::write(
            path,
            serde_json::to_string_pretty(&clean).unwrap_or_else(|_| "{}".into()),
        )
    }

    pub fn issue(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        user: &str,
        state: Option<String>,
        ttl_secs: i64,
    ) -> AuthCode {
        let now = Utc::now();
        let exp = now + Duration::seconds(ttl_secs.max(60));
        let c = AuthCode {
            code: format!("ac_{}", uuid_simple()),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            user: user.to_string(),
            state,
            created_at: now.to_rfc3339(),
            expires_at: exp.to_rfc3339(),
            used: false,
        };
        self.codes.push(c.clone());
        c
    }

    /// Consume a code (single use). Returns user on success.
    pub fn consume(
        &mut self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<String, String> {
        let now = Utc::now();
        for c in &mut self.codes {
            if c.code != code {
                continue;
            }
            if c.used {
                return Err("code already used".into());
            }
            let exp = chrono::DateTime::parse_from_rfc3339(&c.expires_at)
                .map(|t| t.with_timezone(&Utc))
                .ok();
            if exp.map(|e| e <= now).unwrap_or(true) {
                return Err("code expired".into());
            }
            if c.client_id != client_id {
                return Err("client_id mismatch".into());
            }
            if c.redirect_uri != redirect_uri {
                return Err("redirect_uri mismatch".into());
            }
            c.used = true;
            return Ok(c.user.clone());
        }
        Err("unknown code".into())
    }
}

/// Default store path next to device store.
pub fn codes_path_beside_devices(devices: &Path) -> PathBuf {
    devices
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("oauth-codes.json")
}

pub fn is_oob_redirect(uri: &str) -> bool {
    uri.is_empty()
        || uri == "urn:ietf:wg:oauth:2.0:oob"
        || uri == "urn:ietf:wg:oauth:2.0:oob:auto"
}

pub fn authorize_page(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    scope: &str,
    message: Option<&str>,
) -> String {
    let msg = message.unwrap_or("Approve access for this lab client?");
    let redir = if redirect_uri.is_empty() {
        "urn:ietf:wg:oauth:2.0:oob"
    } else {
        redirect_uri
    };
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>S2O Authorize</title>
<style>body{{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:1rem}}
input,button{{font-size:1.05rem;padding:.5rem;width:100%;margin:.35rem 0}}
.msg{{color:#064;margin-bottom:1rem}} .meta{{color:#555;font-size:.9rem}}</style></head>
<body>
<h1>S2O Aegis authorize</h1>
<p class="msg">{msg}</p>
<p class="meta">client_id=<b>{client_id}</b><br>scope=<b>{scope}</b><br>redirect=<b>{redir}</b></p>
<form method="POST" action="/oauth/authorize">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redir}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="scope" value="{scope}">
<label>User name</label>
<input name="user" value="operator" required>
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny" style="background:#fee">Deny</button>
</form>
<p style="color:#666;font-size:.85rem">Lab authorization-code grant — not a production browser IdP.</p>
</body></html>"#
    )
}

pub fn authorize_code_result_page(code: &str, state: Option<&str>) -> String {
    let st = state.unwrap_or("");
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>S2O Code</title>
<style>body{{font-family:system-ui;max-width:32rem;margin:3rem auto;padding:1rem}}
code{{display:block;word-break:break-all;background:#f4f4f4;padding:.75rem;margin:1rem 0}}</style></head>
<body>
<h1>Authorization code</h1>
<p>Copy this code into your client (out-of-band redirect).</p>
<code>{code}</code>
<p>state: {st}</p>
</body></html>"#
    )
}

pub fn build_redirect_location(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut loc = format!("{redirect_uri}{sep}code={code}");
    if let Some(s) = state.filter(|s| !s.is_empty()) {
        loc.push_str("&state=");
        loc.push_str(s);
    }
    loc
}

#[allow(dead_code)]
pub fn default_devices_path() -> PathBuf {
    PathBuf::from(".aegis/oauth-devices.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_code_consume_once() {
        let mut s = AuthCodeStore::default();
        let c = s.issue("cli", "urn:ietf:wg:oauth:2.0:oob", "alice", Some("st".into()), 300);
        assert_eq!(
            s.consume(&c.code, "cli", "urn:ietf:wg:oauth:2.0:oob").unwrap(),
            "alice"
        );
        assert!(s.consume(&c.code, "cli", "urn:ietf:wg:oauth:2.0:oob").is_err());
    }
}
