//! S2O Aegis master daemon — suite kernel front door.
//!
//! Honesty: only engines that actually work report live data.
//! Demo labels require AEGIS_DEMO=1.
//!
//! Windows Service: `aegisd --run-as-service` (SCM entry). Interactive: `aegisd start`.

#[cfg(windows)]
mod service;
mod oauth;

use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::{
    apply_policy, collect_platform_status, create_firewall_engine, demo_mode, host_id,
    load_policy_file, FirewallEngineHandle, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{
    decode_event_json, AegisEvent, EventAction, EventKind, HealthState, ProductId, Severity,
    SCHEMA_VERSION,
};
use s2o_store::EventStore;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "aegisd")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O Aegis Platform: suite kernel / cyber-ops orchestrator", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Aegis daemon (Cyberwall probe + event store)
    Start {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Local health HTTP bind (empty to disable). Example: 127.0.0.1:9090
        #[arg(long, default_value = "127.0.0.1:9090")]
        health_bind: String,
        /// Disable the health HTTP endpoint
        #[arg(long)]
        no_health: bool,
        /// Fleet inventory store path (for /fleet HTTP)
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        /// Fleet policy bundle path (GET/POST /fleet/policy)
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        fleet_policy: PathBuf,
        /// Mesh peer directory for /mesh/peers
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        mesh_peers: PathBuf,
        /// Lab JWKS path for /.well-known OIDC stub (optional)
        #[arg(long, default_value = ".aegis/jwt/jwks.json")]
        jwks: PathBuf,
        /// RSA private key PEM for OAuth access_token mint (optional; falls back to HS)
        #[arg(long, default_value = ".aegis/jwt/jwt-private.pem")]
        jwt_private: PathBuf,
        /// Device-code store path
        #[arg(long, default_value = ".aegis/oauth-devices.json")]
        oauth_devices: PathBuf,
        /// Multi-process UDP event ingest bind (empty to disable). Default lab: 127.0.0.1:9091
        #[arg(long, default_value = "127.0.0.1:9091")]
        event_udp: String,
        /// Disable UDP event collector
        #[arg(long)]
        no_event_udp: bool,
    },
    /// Display platform status (honest matrix for all 9 worlds)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Apply a policy document (v0: firewall intents)
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Reload policy (placeholder — use `policy apply`)
    Reload,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Apply a JSON policy file through the kernel
    Apply {
        /// Path to policy JSON
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Print an example policy document
    Example {
        /// wall | edge
        #[arg(long, default_value = "edge")]
        kind: String,
    },
}

/// Minimal HTTP/1.0 health server: GET /health, /status, /metrics, /fleet
/// POST /fleet/heartbeat ; GET/POST /fleet/policy
async fn health_server(
    bind: String,
    fw: FirewallEngineHandle,
    event_log: PathBuf,
    fleet_path: PathBuf,
    fleet_policy_path: PathBuf,
    mesh_peers_path: PathBuf,
    jwks_path: PathBuf,
    jwt_private: PathBuf,
    oauth_devices: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&bind).await?;
    let public_base = format!("http://{bind}");
    loop {
        let (mut sock, peer) = listener.accept().await?;
        let fw = fw.clone();
        let event_log = event_log.clone();
        let fleet_path = fleet_path.clone();
        let fleet_policy_path = fleet_policy_path.clone();
        let mesh_peers_path = mesh_peers_path.clone();
        let jwks_path = jwks_path.clone();
        let jwt_private = jwt_private.clone();
        let oauth_devices = oauth_devices.clone();
        let public_base = public_base.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            let n = match sock.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let raw_path = parts.next().unwrap_or("/");
            // strip query
            let path_q = raw_path;
            let path = path_q.split('?').next().unwrap_or("/");
            // console API aliases
            let path = path
                .strip_prefix("/api/v1")
                .unwrap_or(path);
            let path = if path.is_empty() { "/" } else { path };

            // body after headers
            let body_bytes = req
                .split("\r\n\r\n")
                .nth(1)
                .or_else(|| req.split("\n\n").nth(1))
                .unwrap_or("");

            // query helpers
            let limit = path_q
                .split('?')
                .nth(1)
                .and_then(|q| {
                    q.split('&').find_map(|p| {
                        let mut kv = p.splitn(2, '=');
                        match (kv.next(), kv.next()) {
                            (Some("limit"), Some(v)) => v.parse::<usize>().ok(),
                            _ => None,
                        }
                    })
                })
                .unwrap_or(20);

            let (code, body, ctype) = if path == "/.well-known/openid-configuration"
                || path == "/api/v1/.well-known/openid-configuration"
            {
                let issuer = public_base.trim_end_matches('/').to_string();
                let jwks_uri = format!("{issuer}/jwks.json");
                let doc = serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                    "authorization_endpoint": format!("{issuer}/oauth/authorize"),
                    "token_endpoint": format!("{issuer}/oauth/token"),
                    "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
                    "grant_types_supported": [
                        "urn:ietf:params:oauth:grant-type:device_code",
                        "authorization_code",
                        "refresh_token"
                    ],
                    "response_types_supported": ["code", "id_token", "token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                    "scopes_supported": ["openid", "profile"],
                    "claims_supported": ["sub", "iss", "exp", "iat", "posture"],
                });
                match serde_json::to_string(&doc) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/jwks.json"
                || path == "/api/v1/jwks.json"
                || path == "/.well-known/jwks.json"
            {
                if jwks_path.exists() {
                    match fs::read_to_string(&jwks_path) {
                        Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                        Err(e) => (
                            "500 Internal Server Error",
                            format!("{{\"error\":\"{e}\"}}\n"),
                            "application/json",
                        ),
                    }
                } else {
                    (
                        "404 Not Found",
                        "{\"error\":\"no lab JWKS — run: cyberztna jwt keygen --dir .aegis/jwt\"}\n".into(),
                        "application/json",
                    )
                }
            } else if path == "/oauth/device_authorization"
                || path == "/oauth/device/code"
            {
                if method != "POST" {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"invalid_request\",\"error_description\":\"POST required\"}\n".into(),
                        "application/json",
                    )
                } else {
                    let form = oauth::parse_form(body_bytes);
                    let client_id = form
                        .get("client_id")
                        .cloned()
                        .unwrap_or_else(|| "s2o-gate".into());
                    let mut store = oauth::DeviceStore::load(&oauth_devices);
                    let d = store.create(&client_id, 600);
                    let _ = store.save(&oauth_devices);
                    let issuer = public_base.trim_end_matches('/');
                    let body = serde_json::json!({
                        "device_code": d.device_code,
                        "user_code": d.user_code,
                        "verification_uri": format!("{issuer}/oauth/device"),
                        "verification_uri_complete": format!("{issuer}/oauth/device?user_code={}", d.user_code),
                        "expires_in": 600,
                        "interval": 2,
                    });
                    match serde_json::to_string(&body) {
                        Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                        Err(e) => (
                            "500 Internal Server Error",
                            format!("{{\"error\":\"{e}\"}}\n"),
                            "application/json",
                        ),
                    }
                }
            } else if path == "/oauth/device" || path.starts_with("/oauth/device?") {
                // GET form; user_code from query
                let uc = path_q.split('?').nth(1).and_then(|q| {
                    q.split('&').find_map(|p| {
                        let mut kv = p.splitn(2, '=');
                        match (kv.next(), kv.next()) {
                            (Some("user_code"), Some(v)) => Some(oauth::parse_form(&format!("user_code={v}"))
                                .get("user_code")
                                .cloned()
                                .unwrap_or_else(|| v.to_string())),
                            _ => None,
                        }
                    })
                });
                let html = oauth::device_approve_page(uc.as_deref(), None);
                ("200 OK", html, "text/html; charset=utf-8")
            } else if path == "/oauth/device_approve" {
                if method != "POST" {
                    (
                        "405 Method Not Allowed",
                        "POST form required\n".into(),
                        "text/plain",
                    )
                } else {
                    let form = oauth::parse_form(body_bytes);
                    // also accept JSON
                    let (user_code, user) = if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_bytes) {
                        (
                            v.get("user_code").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            v.get("user").and_then(|x| x.as_str()).unwrap_or("operator").to_string(),
                        )
                    } else {
                        (
                            form.get("user_code").cloned().unwrap_or_default(),
                            form.get("user").cloned().unwrap_or_else(|| "operator".into()),
                        )
                    };
                    let mut store = oauth::DeviceStore::load(&oauth_devices);
                    match store.approve(&user_code, &user) {
                        Ok(d) => {
                            let code = d.user_code.clone();
                            let _ = store.save(&oauth_devices);
                            let html = oauth::device_approve_page(
                                Some(&code),
                                Some(&format!("Approved for user '{user}'. Return to your device.")),
                            );
                            ("200 OK", html, "text/html; charset=utf-8")
                        }
                        Err(e) => {
                            let html = oauth::device_approve_page(
                                Some(&user_code),
                                Some(&format!("Error: {e}")),
                            );
                            ("400 Bad Request", html, "text/html; charset=utf-8")
                        }
                    }
                }
            } else if path == "/oauth/authorize" || path.starts_with("/oauth/authorize?") {
                // Authorization code grant (lab): GET consent form; POST issue code.
                let q = path_q.split('?').nth(1).unwrap_or("");
                let qmap = oauth::parse_form(q);
                if method == "GET" {
                    let client_id = qmap
                        .get("client_id")
                        .cloned()
                        .unwrap_or_else(|| "s2o-gate".into());
                    let redirect_uri = qmap
                        .get("redirect_uri")
                        .cloned()
                        .unwrap_or_else(|| "urn:ietf:wg:oauth:2.0:oob".into());
                    let state = qmap.get("state").cloned().unwrap_or_default();
                    let scope = qmap
                        .get("scope")
                        .cloned()
                        .unwrap_or_else(|| "openid profile".into());
                    let response_type = qmap
                        .get("response_type")
                        .cloned()
                        .unwrap_or_else(|| "code".into());
                    let auto = qmap
                        .get("auto_approve")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let user = qmap
                        .get("user")
                        .cloned()
                        .unwrap_or_else(|| "operator".into());
                    if response_type != "code" {
                        (
                            "400 Bad Request",
                            "{\"error\":\"unsupported_response_type\"}\n".into(),
                            "application/json",
                        )
                    } else if auto {
                        // Lab automation: issue code immediately
                        let codes_path = oauth::codes_path_beside_devices(&oauth_devices);
                        let mut store = oauth::AuthCodeStore::load(&codes_path);
                        let issued = store.issue(
                            &client_id,
                            &redirect_uri,
                            &user,
                            if state.is_empty() {
                                None
                            } else {
                                Some(state.clone())
                            },
                            300,
                        );
                        let _ = store.save(&codes_path);
                        if oauth::is_oob_redirect(&redirect_uri) {
                            let body = serde_json::json!({
                                "code": issued.code,
                                "state": issued.state,
                                "redirect_uri": redirect_uri,
                            });
                            (
                                "200 OK",
                                format!(
                                    "{}\n",
                                    serde_json::to_string(&body).unwrap_or_default()
                                ),
                                "application/json",
                            )
                        } else {
                            let loc = oauth::build_redirect_location(
                                &redirect_uri,
                                &issued.code,
                                issued.state.as_deref(),
                            );
                            let html = format!(
                                r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={loc}"></head>
<body><p>Redirecting… <a href="{loc}">continue</a></p>
<p>code=<code>{}</code></p></body></html>"#,
                                issued.code
                            );
                            ("200 OK", html, "text/html; charset=utf-8")
                        }
                    } else {
                        let html = oauth::authorize_page(
                            &client_id,
                            &redirect_uri,
                            &state,
                            &scope,
                            None,
                        );
                        ("200 OK", html, "text/html; charset=utf-8")
                    }
                } else if method == "POST" {
                    let form = oauth::parse_form(body_bytes);
                    let json_body: Option<serde_json::Value> =
                        serde_json::from_str(body_bytes).ok();
                    let get = |k: &str| -> String {
                        form.get(k)
                            .cloned()
                            .or_else(|| {
                                json_body
                                    .as_ref()
                                    .and_then(|v| v.get(k))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                            })
                            .unwrap_or_default()
                    };
                    let client_id = {
                        let c = get("client_id");
                        if c.is_empty() {
                            "s2o-gate".into()
                        } else {
                            c
                        }
                    };
                    let redirect_uri = {
                        let r = get("redirect_uri");
                        if r.is_empty() {
                            "urn:ietf:wg:oauth:2.0:oob".into()
                        } else {
                            r
                        }
                    };
                    let state = get("state");
                    let user = {
                        let u = get("user");
                        if u.is_empty() {
                            "operator".into()
                        } else {
                            u
                        }
                    };
                    let decision = get("decision");
                    let want_json = body_bytes.trim_start().starts_with('{')
                        || get("format") == "json"
                        || form.get("format").map(|s| s == "json").unwrap_or(false);
                    if decision == "deny" {
                        (
                            "403 Forbidden",
                            "{\"error\":\"access_denied\"}\n".into(),
                            "application/json",
                        )
                    } else {
                        let codes_path = oauth::codes_path_beside_devices(&oauth_devices);
                        let mut store = oauth::AuthCodeStore::load(&codes_path);
                        let issued = store.issue(
                            &client_id,
                            &redirect_uri,
                            &user,
                            if state.is_empty() {
                                None
                            } else {
                                Some(state.clone())
                            },
                            300,
                        );
                        let _ = store.save(&codes_path);
                        if want_json {
                            let body = serde_json::json!({
                                "code": issued.code,
                                "state": issued.state,
                                "redirect_uri": redirect_uri,
                            });
                            (
                                "200 OK",
                                format!(
                                    "{}\n",
                                    serde_json::to_string(&body).unwrap_or_default()
                                ),
                                "application/json",
                            )
                        } else if oauth::is_oob_redirect(&redirect_uri) {
                            let html = oauth::authorize_code_result_page(
                                &issued.code,
                                issued.state.as_deref(),
                            );
                            ("200 OK", html, "text/html; charset=utf-8")
                        } else {
                            let loc = oauth::build_redirect_location(
                                &redirect_uri,
                                &issued.code,
                                issued.state.as_deref(),
                            );
                            let html = format!(
                                r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url={loc}"></head>
<body><p>Approved. <a href="{loc}">Return to client</a></p></body></html>"#
                            );
                            ("200 OK", html, "text/html; charset=utf-8")
                        }
                    }
                } else {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"invalid_request\"}\n".into(),
                        "application/json",
                    )
                }
            } else if path == "/oauth/token" {
                if method != "POST" {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"invalid_request\"}\n".into(),
                        "application/json",
                    )
                } else {
                    let form = oauth::parse_form(body_bytes);
                    let json_body: Option<serde_json::Value> =
                        serde_json::from_str(body_bytes).ok();
                    let form_or = |k: &str| -> String {
                        form.get(k)
                            .cloned()
                            .or_else(|| {
                                json_body
                                    .as_ref()
                                    .and_then(|v| v.get(k))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                            })
                            .unwrap_or_default()
                    };
                    let grant = form_or("grant_type");
                    if grant == "authorization_code" {
                        let code = form_or("code");
                        let client_id = {
                            let c = form_or("client_id");
                            if c.is_empty() {
                                "s2o-gate".into()
                            } else {
                                c
                            }
                        };
                        let redirect_uri = {
                            let r = form_or("redirect_uri");
                            if r.is_empty() {
                                "urn:ietf:wg:oauth:2.0:oob".into()
                            } else {
                                r
                            }
                        };
                        let codes_path = oauth::codes_path_beside_devices(&oauth_devices);
                        let mut store = oauth::AuthCodeStore::load(&codes_path);
                        match store.consume(&code, &client_id, &redirect_uri) {
                            Ok(user) => {
                                let _ = store.save(&codes_path);
                                let issuer = public_base.trim_end_matches('/').to_string();
                                match oauth::mint_access_token(
                                    &user,
                                    &issuer,
                                    8,
                                    &jwt_private,
                                    None,
                                ) {
                                    Ok(tok) => {
                                        let body = serde_json::json!({
                                            "access_token": tok,
                                            "token_type": "Bearer",
                                            "expires_in": 28800,
                                            "scope": "openid profile",
                                            "sub": user,
                                        });
                                        (
                                            "200 OK",
                                            format!(
                                                "{}\n",
                                                serde_json::to_string(&body).unwrap_or_default()
                                            ),
                                            "application/json",
                                        )
                                    }
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!(
                                            "{{\"error\":\"server_error\",\"error_description\":\"{e}\"}}\n"
                                        ),
                                        "application/json",
                                    ),
                                }
                            }
                            Err(e) => (
                                "400 Bad Request",
                                format!(
                                    "{{\"error\":\"invalid_grant\",\"error_description\":\"{e}\"}}\n"
                                ),
                                "application/json",
                            ),
                        }
                    } else if grant == "urn:ietf:params:oauth:grant-type:device_code"
                        || grant == "device_code"
                    {
                        let device_code = form_or("device_code");
                        let mut store = oauth::DeviceStore::load(&oauth_devices);
                        let now = chrono::Utc::now();
                        let outcome: Result<(String, String), (String, String)> = {
                            let d = store.find_device_code(&device_code);
                            match d {
                                None => Err((
                                    "invalid_grant".into(),
                                    "unknown device_code".into(),
                                )),
                                Some(d) => {
                                    let exp = chrono::DateTime::parse_from_rfc3339(&d.expires_at)
                                        .map(|t| t.with_timezone(&chrono::Utc))
                                        .ok();
                                    if exp.map(|e| e <= now).unwrap_or(true) {
                                        Err((
                                            "expired_token".into(),
                                            "device_code expired".into(),
                                        ))
                                    } else if d.status == oauth::DeviceStatus::Pending {
                                        Err((
                                            "authorization_pending".into(),
                                            "waiting for user".into(),
                                        ))
                                    } else if d.status == oauth::DeviceStatus::Denied {
                                        Err(("access_denied".into(), "user denied".into()))
                                    } else if d.status == oauth::DeviceStatus::Approved {
                                        if let Some(ref t) = d.access_token {
                                            Ok((t.clone(), d.user.clone().unwrap_or_default()))
                                        } else {
                                            let user =
                                                d.user.clone().unwrap_or_else(|| "operator".into());
                                            let issuer =
                                                public_base.trim_end_matches('/').to_string();
                                            match oauth::mint_access_token(
                                                &user,
                                                &issuer,
                                                8,
                                                &jwt_private,
                                                None,
                                            ) {
                                                Ok(tok) => Ok((tok, user)),
                                                Err(e) => Err(("server_error".into(), e)),
                                            }
                                        }
                                    } else {
                                        Err((
                                            "invalid_grant".into(),
                                            "device not usable".into(),
                                        ))
                                    }
                                }
                            }
                        };
                        match outcome {
                            Ok((tok, user)) => {
                                store.set_token(&device_code, tok.clone());
                                let _ = store.save(&oauth_devices);
                                let body = serde_json::json!({
                                    "access_token": tok,
                                    "token_type": "Bearer",
                                    "expires_in": 28800,
                                    "scope": "openid profile",
                                    "sub": user,
                                });
                                match serde_json::to_string(&body) {
                                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"{e}\"}}\n"),
                                        "application/json",
                                    ),
                                }
                            }
                            Err((code, desc)) => {
                                let body = serde_json::json!({
                                    "error": code,
                                    "error_description": desc,
                                });
                                (
                                    "400 Bad Request",
                                    format!(
                                        "{}\n",
                                        serde_json::to_string(&body).unwrap_or_default()
                                    ),
                                    "application/json",
                                )
                            }
                        }
                    } else {
                        (
                            "400 Bad Request",
                            "{\"error\":\"unsupported_grant_type\"}\n".into(),
                            "application/json",
                        )
                    }
                }
            } else if path == "/health" || path.starts_with("/health/") {
                (
                    "200 OK",
                    format!(
                        "{{\"ok\":true,\"platform\":\"S2O Aegis\",\"phase\":\"{PHASE_LABEL}\",\"kernel\":\"{KERNEL_VERSION}\"}}\n"
                    ),
                    "application/json",
                )
            } else if path == "/status" || path.starts_with("/status/") {
                match serde_json::to_string(&collect_platform_status(&fw).await) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/posture" || path.starts_with("/posture") {
                match s2o_kernel::compute_posture_score(&fw).await {
                    Ok(p) => match serde_json::to_string(&p) {
                        Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                        Err(e) => (
                            "500 Internal Server Error",
                            format!("{{\"error\":\"{e}\"}}\n"),
                            "application/json",
                        ),
                    },
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/events" || path.starts_with("/events") {
                if method == "POST" || method == "PUT" {
                    // Ingest: full AegisEvent JSON or compact EventIngest
                    match decode_event_json(body_bytes, &host_id()) {
                        Ok(mut ev) => {
                            ev = ev.with_attr("ingest", serde_json::json!("http"));
                            match EventStore::open(&event_log) {
                                Ok(store) => match store.append(&ev) {
                                    Ok(()) => {
                                        let body = serde_json::json!({
                                            "ok": true,
                                            "id": ev.id,
                                            "product": ev.product.as_str(),
                                            "severity": format!("{:?}", ev.severity).to_ascii_lowercase(),
                                        });
                                        (
                                            "201 Created",
                                            format!(
                                                "{}\n",
                                                serde_json::to_string(&body).unwrap_or_default()
                                            ),
                                            "application/json",
                                        )
                                    }
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"{e}\"}}\n"),
                                        "application/json",
                                    ),
                                },
                                Err(e) => (
                                    "500 Internal Server Error",
                                    format!("{{\"error\":\"{e}\"}}\n"),
                                    "application/json",
                                ),
                            }
                        }
                        Err(e) => (
                            "400 Bad Request",
                            format!(
                                "{{\"error\":\"invalid_event\",\"error_description\":\"{e}\"}}\n"
                            ),
                            "application/json",
                        ),
                    }
                } else {
                    match EventStore::open(&event_log) {
                        Ok(store) => match store.recent(limit) {
                            Ok(evs) => match serde_json::to_string(&evs) {
                                Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                Err(e) => (
                                    "500 Internal Server Error",
                                    format!("{{\"error\":\"{e}\"}}\n"),
                                    "application/json",
                                ),
                            },
                            Err(e) => (
                                "500 Internal Server Error",
                                format!("{{\"error\":\"{e}\"}}\n"),
                                "application/json",
                            ),
                        },
                        Err(e) => (
                            "500 Internal Server Error",
                            format!("{{\"error\":\"{e}\"}}\n"),
                            "application/json",
                        ),
                    }
                }
            } else if path == "/mesh/peers" || path.starts_with("/mesh/peers") {
                if method == "GET" {
                    if mesh_peers_path.exists() {
                        match fs::read_to_string(&mesh_peers_path) {
                            Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                            Err(e) => (
                                "500 Internal Server Error",
                                format!("{{\"error\":\"{e}\"}}\n"),
                                "application/json",
                            ),
                        }
                    } else {
                        (
                            "200 OK",
                            "{\"version\":\"0.1.0\",\"peers\":[]}\n".into(),
                            "application/json",
                        )
                    }
                } else if method == "POST" || method == "PUT" {
                    // accept single MeshPeer JSON and upsert into registry
                    #[derive(serde::Deserialize, serde::Serialize, Clone)]
                    struct MeshPeerIn {
                        name: String,
                        public_key: String,
                        #[serde(default)]
                        endpoint: Option<String>,
                        #[serde(default = "default_allowed_ips")]
                        allowed_ips: String,
                        #[serde(default = "default_ka")]
                        keepalive: u16,
                        #[serde(default)]
                        notes: Option<String>,
                    }
                    fn default_allowed_ips() -> String {
                        "10.220.0.0/24".into()
                    }
                    fn default_ka() -> u16 {
                        25
                    }
                    #[derive(serde::Deserialize, serde::Serialize, Clone, Default)]
                    struct MeshReg {
                        #[serde(default = "default_ver")]
                        version: String,
                        #[serde(default)]
                        peers: Vec<MeshPeerIn>,
                    }
                    fn default_ver() -> String {
                        "0.1.0".into()
                    }
                    match serde_json::from_str::<MeshPeerIn>(body_bytes) {
                        Ok(peer) => {
                            let mut reg: MeshReg = if mesh_peers_path.exists() {
                                fs::read_to_string(&mesh_peers_path)
                                    .ok()
                                    .and_then(|t| serde_json::from_str(&t).ok())
                                    .unwrap_or_default()
                            } else {
                                MeshReg::default()
                            };
                            if let Some(p) = reg.peers.iter_mut().find(|p| p.name == peer.name) {
                                *p = peer.clone();
                            } else {
                                reg.peers.push(peer.clone());
                            }
                            if reg.version.is_empty() {
                                reg.version = "0.1.0".into();
                            }
                            if let Some(parent) = mesh_peers_path.parent() {
                                let _ = fs::create_dir_all(parent);
                            }
                            match serde_json::to_string_pretty(&reg) {
                                Ok(text) => match fs::write(&mesh_peers_path, text) {
                                    Ok(()) => match serde_json::to_string(&peer) {
                                        Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                        Err(e) => (
                                            "500 Internal Server Error",
                                            format!("{{\"error\":\"{e}\"}}\n"),
                                            "application/json",
                                        ),
                                    },
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"save: {e}\"}}\n"),
                                        "application/json",
                                    ),
                                },
                                Err(e) => (
                                    "500 Internal Server Error",
                                    format!("{{\"error\":\"{e}\"}}\n"),
                                    "application/json",
                                ),
                            }
                        }
                        Err(e) => (
                            "400 Bad Request",
                            format!("{{\"error\":\"json: {e}\"}}\n"),
                            "application/json",
                        ),
                    }
                } else {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"GET or POST /mesh/peers\"}\n".into(),
                        "application/json",
                    )
                }
            } else if path == "/fleet" || path == "/fleet/" {
                let store = s2o_fleet::FleetStore::load(&fleet_path);
                match serde_json::to_string(&store) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/fleet/summary" || path.starts_with("/fleet/summary") {
                let store = s2o_fleet::FleetStore::load(&fleet_path);
                let pv = s2o_fleet::FleetPolicyBundle::load(&fleet_policy_path)
                    .map(|b| b.version)
                    .unwrap_or(0);
                let sum = store.summary_with_policy(60, pv);
                match serde_json::to_string(&sum) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/fleet/policy" || path.starts_with("/fleet/policy") {
                if method == "GET" {
                    match s2o_fleet::FleetPolicyBundle::load(&fleet_policy_path) {
                        Some(b) => match serde_json::to_string(&b) {
                            Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                            Err(e) => (
                                "500 Internal Server Error",
                                format!("{{\"error\":\"{e}\"}}\n"),
                                "application/json",
                            ),
                        },
                        None => (
                            "404 Not Found",
                            "{\"error\":\"no fleet policy set\"}\n".into(),
                            "application/json",
                        ),
                    }
                } else if method == "POST" || method == "PUT" {
                    // Accept either raw PolicyDocument or full FleetPolicyBundle
                    match serde_json::from_str::<serde_json::Value>(body_bytes) {
                        Ok(val) => {
                            let prev = s2o_fleet::FleetPolicyBundle::load(&fleet_policy_path);
                            let bundle_res = if val.get("document").is_some()
                                && val.get("version").is_some()
                            {
                                serde_json::from_value::<s2o_fleet::FleetPolicyBundle>(val)
                                    .map_err(|e| e.to_string())
                            } else {
                                Ok(s2o_fleet::FleetPolicyBundle::from_document(
                                    val,
                                    prev.as_ref(),
                                ))
                            };
                            match bundle_res {
                                Ok(bundle) => match bundle.save(&fleet_policy_path) {
                                    Ok(()) => match serde_json::to_string(&bundle) {
                                        Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                        Err(e) => (
                                            "500 Internal Server Error",
                                            format!("{{\"error\":\"{e}\"}}\n"),
                                            "application/json",
                                        ),
                                    },
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"save: {e}\"}}\n"),
                                        "application/json",
                                    ),
                                },
                                Err(e) => (
                                    "400 Bad Request",
                                    format!("{{\"error\":\"bundle: {e}\"}}\n"),
                                    "application/json",
                                ),
                            }
                        }
                        Err(e) => (
                            "400 Bad Request",
                            format!("{{\"error\":\"json: {e}\"}}\n"),
                            "application/json",
                        ),
                    }
                } else {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"GET or POST /fleet/policy\"}\n".into(),
                        "application/json",
                    )
                }
            } else if path == "/fleet/heartbeat" || path.starts_with("/fleet/heartbeat") {
                if method != "POST" && method != "PUT" {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"POST JSON HeartbeatPayload\"}\n".into(),
                        "application/json",
                    )
                } else {
                    match serde_json::from_str::<s2o_fleet::HeartbeatPayload>(body_bytes) {
                        Ok(mut hb) => {
                            if hb.last_ip.is_none() {
                                hb.last_ip = Some(peer.ip().to_string());
                            }
                            let mut store = s2o_fleet::FleetStore::load(&fleet_path);
                            let host = store.upsert_heartbeat(hb);
                            if let Err(e) = store.save(&fleet_path) {
                                (
                                    "500 Internal Server Error",
                                    format!("{{\"error\":\"save: {e}\"}}\n"),
                                    "application/json",
                                )
                            } else {
                                let desired = s2o_fleet::FleetPolicyBundle::load(&fleet_policy_path)
                                    .map(|b| b.version)
                                    .unwrap_or(0);
                                let resp = s2o_fleet::HeartbeatResponse {
                                    policy_stale: desired > 0 && host.policy_version < desired,
                                    desired_policy_version: desired,
                                    host,
                                };
                                match serde_json::to_string(&resp) {
                                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"{e}\"}}\n"),
                                        "application/json",
                                    ),
                                }
                            }
                        }
                        Err(e) => (
                            "400 Bad Request",
                            format!("{{\"error\":\"json: {e}\"}}\n"),
                            "application/json",
                        ),
                    }
                }
            } else if path == "/metrics" || path.starts_with("/metrics/") {
                let st = collect_platform_status(&fw).await;
                let mut implemented = 0u32;
                let mut partial = 0u32;
                let mut other = 0u32;
                for m in &st.modules {
                    match m.state.as_str() {
                        "implemented" => implemented += 1,
                        "partial" => partial += 1,
                        _ => other += 1,
                    }
                }
                let (events, bytes) = if event_log.exists() {
                    match EventStore::open(&event_log) {
                        Ok(s) => (
                            s.count().unwrap_or(0) as u64,
                            s.len_bytes().unwrap_or(0),
                        ),
                        Err(_) => (0, 0),
                    }
                } else {
                    (0, 0)
                };
                let fleet = s2o_fleet::FleetStore::load(&fleet_path);
                let pv = s2o_fleet::FleetPolicyBundle::load(&fleet_policy_path)
                    .map(|b| b.version)
                    .unwrap_or(0);
                let fsum = fleet.summary_with_policy(60, pv);
                let body = format!(
                    "# HELP aegis_up 1 if daemon health endpoint is serving\n\
                     # TYPE aegis_up gauge\n\
                     aegis_up 1\n\
                     # HELP aegis_modules Modules by honesty state\n\
                     # TYPE aegis_modules gauge\n\
                     aegis_modules{{state=\"implemented\"}} {implemented}\n\
                     aegis_modules{{state=\"partial\"}} {partial}\n\
                     aegis_modules{{state=\"other\"}} {other}\n\
                     # HELP aegis_events_total Events in local JSONL store\n\
                     # TYPE aegis_events_total gauge\n\
                     aegis_events_total {events}\n\
                     # HELP aegis_event_log_bytes Size of event log file\n\
                     # TYPE aegis_event_log_bytes gauge\n\
                     aegis_event_log_bytes {bytes}\n\
                     # HELP aegis_fleet_hosts Fleet roster size\n\
                     # TYPE aegis_fleet_hosts gauge\n\
                     aegis_fleet_hosts {fleet_total}\n\
                     # HELP aegis_fleet_online Hosts seen within stale window\n\
                     # TYPE aegis_fleet_online gauge\n\
                     aegis_fleet_online {fleet_online}\n\
                     # HELP aegis_fleet_policy_version Desired fleet policy version\n\
                     # TYPE aegis_fleet_policy_version gauge\n\
                     aegis_fleet_policy_version {policy_v}\n\
                     # HELP aegis_fleet_policy_behind Hosts behind desired policy\n\
                     # TYPE aegis_fleet_policy_behind gauge\n\
                     aegis_fleet_policy_behind {policy_behind}\n\
                     # HELP aegis_demo_mode 1 if AEGIS_DEMO is enabled\n\
                     # TYPE aegis_demo_mode gauge\n\
                     aegis_demo_mode {}\n",
                    if st.demo_mode { 1 } else { 0 },
                    fleet_total = fsum.total,
                    fleet_online = fsum.online,
                    policy_v = pv,
                    policy_behind = fsum.hosts_behind_policy,
                );
                ("200 OK", body, "text/plain; version=0.0.4")
            } else {
                (
                    "404 Not Found",
                    "try GET /health /status /events /oauth/* ; POST /events /oauth/* /fleet/*\n".into(),
                    "text/plain",
                )
            };

            let resp = format!(
                "HTTP/1.0 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

/// Shared start path for interactive console and Windows Service.
pub async fn run_daemon(
    event_log: PathBuf,
    health_bind: String,
    no_health: bool,
    as_service: bool,
    fleet_path: PathBuf,
    fleet_policy_path: PathBuf,
    mesh_peers_path: PathBuf,
    jwks_path: PathBuf,
    jwt_private: PathBuf,
    oauth_devices: PathBuf,
    event_udp: String,
    no_event_udp: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fw = create_firewall_engine();

    if !as_service {
        println!(
            "{}",
            "=========================================================".cyan()
        );
        println!(
            "{}",
            "     S2O AEGIS MASTER DAEMON  (Phase 2/3 shell)          "
                .bold()
                .green()
        );
        println!(
            "{}",
            "=========================================================".cyan()
        );
        println!(" Kernel version    : {}", KERNEL_VERSION);
        println!(" Schema version    : {}", SCHEMA_VERSION);
        println!(" Phase             : {}", PHASE_LABEL);
        println!(" Tier ceiling      : {}", TIER_CEILING.as_str());
        println!(
            " Demo mode         : {}",
            if demo_mode() {
                "ON (AEGIS_DEMO)".yellow().to_string()
            } else {
                "OFF".green().to_string()
            }
        );
    }

    if let Some(parent) = event_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let store = EventStore::open(&event_log)?;
    if !as_service {
        println!(" Event store       : {}", store.path().display());
        println!(" Host id           : {}", host_id());
    }

    let status = collect_platform_status(&fw).await;
    if !as_service {
        for (i, m) in status.modules.iter().enumerate() {
            let label = match m.state {
                HealthState::Implemented => m.state.as_str().green().bold().to_string(),
                HealthState::Partial => m.state.as_str().yellow().to_string(),
                HealthState::Demo => m.state.as_str().yellow().bold().to_string(),
                HealthState::Degraded => m.state.as_str().red().bold().to_string(),
                _ => m.state.as_str().red().to_string(),
            };
            println!(
                "[AEGISD] [{}/9] {} ... {}",
                i + 1,
                m.name,
                label
            );
            println!("         {}", m.detail);
        }
    }

    let wall = status
        .modules
        .iter()
        .find(|m| m.product == ProductId::Cyberwall);
    let mode = if as_service { "service" } else { "console" };
    let ev = AegisEvent::new(
        host_id(),
        ProductId::Aegis,
        EventKind::Health,
        EventAction::Observed,
        Severity::Info,
        format!(
            "aegisd start mode={mode}; phase={PHASE_LABEL}; wall={}",
            wall.map(|w| w.state.as_str()).unwrap_or("unknown")
        ),
    )
    .with_attr("phase", serde_json::json!(PHASE_LABEL))
    .with_attr("tier_ceiling", serde_json::json!(TIER_CEILING.as_str()))
    .with_attr("mode", serde_json::json!(mode))
    .with_attr(
        "wall_detail",
        serde_json::json!(wall.map(|w| w.detail.as_str()).unwrap_or("")),
    );
    store.append(&ev)?;
    if !as_service {
        println!("[AEGISD] health event written to store");
    }

    if !no_health && !health_bind.is_empty() {
        let bind = health_bind.clone();
        let fw_h = create_firewall_engine();
        let el = event_log.clone();
        let fl = fleet_path.clone();
        let fp = fleet_policy_path.clone();
        let mp = mesh_peers_path.clone();
        let jw = jwks_path.clone();
        let jp = jwt_private.clone();
        let od = oauth_devices.clone();
        tokio::spawn(async move {
            if let Err(e) = health_server(bind, fw_h, el, fl, fp, mp, jw, jp, od).await {
                eprintln!("[AEGISD] health server error: {e}");
            }
        });
        if !as_service {
            println!("[AEGISD] health HTTP     : http://{health_bind}/health");
            println!("[AEGISD] status JSON     : http://{health_bind}/status");
            println!("[AEGISD] posture         : http://{health_bind}/posture");
            println!("[AEGISD] events GET/POST : http://{health_bind}/events");
            println!("[AEGISD] metrics         : http://{health_bind}/metrics");
            println!("[AEGISD] fleet           : http://{health_bind}/fleet");
            println!("[AEGISD] fleet policy    : GET/POST http://{health_bind}/fleet/policy");
            println!("[AEGISD] fleet heartbeat : POST http://{health_bind}/fleet/heartbeat");
            println!("[AEGISD] mesh peers      : GET/POST http://{health_bind}/mesh/peers");
            println!("[AEGISD] OIDC discovery  : http://{health_bind}/.well-known/openid-configuration");
            println!("[AEGISD] JWKS            : http://{health_bind}/jwks.json");
            println!("[AEGISD] OAuth device    : POST http://{health_bind}/oauth/device_authorization");
            println!("[AEGISD] OAuth approve   : http://{health_bind}/oauth/device");
            println!("[AEGISD] OAuth auth-code : GET/POST http://{health_bind}/oauth/authorize");
            println!("[AEGISD] console API     : http://{health_bind}/api/v1/* (aliases)");
        }
    }

    if !no_event_udp && !event_udp.is_empty() {
        let el = event_log.clone();
        let bind = event_udp.clone();
        let hid = host_id();
        tokio::spawn(async move {
            let sock = match tokio::net::UdpSocket::bind(&bind).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[AEGISD] event UDP bind {bind} failed: {e}");
                    return;
                }
            };
            eprintln!("[AEGISD] event UDP listening on {bind}");
            let mut buf = vec![0u8; 65535];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        match s2o_bus::udp_decode(&buf[..n], &hid) {
                            Ok(mut ev) => {
                                ev = ev
                                    .with_attr("ingest", serde_json::json!("udp"))
                                    .with_attr("udp_peer", serde_json::json!(peer.to_string()));
                                if let Ok(store) = EventStore::open(&el) {
                                    let _ = store.append(&ev);
                                }
                            }
                            Err(e) => {
                                eprintln!("[AEGISD] event UDP decode from {peer}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[AEGISD] event UDP recv: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        });
        if !as_service {
            println!("[AEGISD] event UDP       : {event_udp} (JSON AegisEvent / EventIngest)");
        }
    }

    if !as_service {
        println!(
            "{}",
            "=========================================================".cyan()
        );
        println!(
            "{}",
            "  Suite kernel live. Ctrl+C to stop."
                .bold()
                .yellow()
        );
        println!(
            "{}",
            "=========================================================".cyan()
        );
        tokio::signal::ctrl_c().await?;
        println!("\n[AEGISD] shutdown complete.");
    } else {
        // Service mode: run until cancelled by caller (select in service.rs)
        std::future::pending::<()>().await;
    }
    Ok(())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Start {
            event_log,
            health_bind,
            no_health,
            fleet,
            fleet_policy,
            mesh_peers,
            jwks,
            jwt_private,
            oauth_devices,
            event_udp,
            no_event_udp,
        } => {
            run_daemon(
                event_log,
                health_bind,
                no_health,
                false,
                fleet,
                fleet_policy,
                mesh_peers,
                jwks,
                jwt_private,
                oauth_devices,
                event_udp,
                no_event_udp,
            )
            .await?;
        }
        Commands::Status { json } => {
            let status = collect_platform_status(&fw).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "    S2O AEGIS PLATFORM STATUS (honest)                   "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Phase        : {}", status.phase);
                println!(" OS           : {}", status.os.as_str());
                println!(" Tier ceiling : {}", status.tier_ceiling.as_str());
                println!(" Host         : {}", status.host_id);
                println!(
                    " Demo mode    : {}",
                    if status.demo_mode { "ON" } else { "OFF" }
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                for m in &status.modules {
                    let state_col = match m.state {
                        HealthState::Implemented => m.state.as_str().green().bold(),
                        HealthState::Partial => m.state.as_str().yellow().bold(),
                        HealthState::Demo => m.state.as_str().yellow().bold(),
                        HealthState::Degraded => m.state.as_str().red().bold(),
                        _ => m.state.as_str().red(),
                    };
                    println!(" Module  : {}", m.name.bold());
                    println!(" State   : {}", state_col);
                    println!(" Detail  : {}", m.detail);
                    if let Some(b) = &m.backend {
                        println!(" Backend : {}", b);
                    }
                    println!(
                        "{}",
                        "---------------------------------------------------------".cyan()
                    );
                }
            }
        }
        Commands::Policy { command } => match command {
            PolicyCmd::Example { kind } => {
                let doc = if kind.eq_ignore_ascii_case("wall") {
                    s2o_schema::PolicyDocument::example_wall_enable()
                } else {
                    s2o_schema::PolicyDocument::example_edge_pack()
                };
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            PolicyCmd::Apply { path, event_log } => {
                println!("[aegisd] loading policy {}", path.display());
                let doc = load_policy_file(&path)?;
                let store = Arc::new(EventStore::open(&event_log)?);
                let result = apply_policy(&doc, &fw, Some(store)).await?;
                if result.ok {
                    println!(
                        "{}",
                        format!("[aegisd] policy OK: {}", result.policy_name)
                            .green()
                            .bold()
                    );
                } else {
                    println!(
                        "{}",
                        format!("[aegisd] policy incomplete/failed: {}", result.policy_name)
                            .yellow()
                            .bold()
                    );
                }
                for a in &result.applied {
                    println!("  applied : {}", a.green());
                }
                for s in &result.skipped {
                    println!("  skipped : {}", s.dimmed());
                }
                for e in &result.errors {
                    println!("  error   : {}", e.red());
                }
                if !result.ok {
                    std::process::exit(1);
                }
            }
        },
        Commands::Reload => {
            eprintln!(
                "{}",
                "[AEGISD] Reload: use `aegisd policy apply <file>` (no daemon-held policy file yet)."
                    .yellow()
                    .bold()
            );
            std::process::exit(2);
        }
    }

    Ok(())
}

fn main() {
    // SCM entry: must run before clap (service dispatcher protocol).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--run-as-service") {
        #[cfg(windows)]
        {
            if let Err(e) = service::dispatch() {
                eprintln!("[aegisd] service dispatcher error: {e}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("[aegisd] --run-as-service is only supported on Windows");
            std::process::exit(2);
        }
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[aegisd] runtime error: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(async_main()) {
        eprintln!("[aegisd] error: {e}");
        std::process::exit(1);
    }
}
