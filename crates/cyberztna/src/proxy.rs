//! Posture-gated reverse proxy (axum + reqwest).

use crate::config::GateConfig;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use s2o_kernel::{compute_posture_score, create_firewall_engine, host_id};
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_session::SessionStore;
use s2o_store::EventStore;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    cfg: GateConfig,
    event_log: PathBuf,
    access_log: Option<PathBuf>,
    sessions_path: Option<PathBuf>,
    /// Require CyberID file session token
    require_session: bool,
    /// Local HS256 JWT secret (OIDC-lite); Bearer eyJ… tokens
    jwt_secret: Option<String>,
    /// Cached posture score with TTL
    cache: Arc<RwLock<Option<(Instant, u32)>>>,
    /// Per-IP rate window: (window_start, count)
    rate: Arc<RwLock<HashMap<IpAddr, (Instant, u32)>>>,
    client: reqwest::Client,
}

struct SessionOk {
    user: String,
    posture_score: u32,
    via: &'static str,
}

fn extract_session_token(req: &Request<Body>) -> Option<String> {
    if let Some(v) = req
        .headers()
        .get("x-aegis-session")
        .and_then(|v| v.to_str().ok())
    {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(v) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if let Some(rest) = v
            .strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
        {
            let t = rest.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    parts.next().is_some()
        && parts.next().is_some()
        && parts.next().is_some()
        && parts.next().is_none()
        && token.starts_with("eyJ")
}

/// Verify CyberID session or local JWT, optionally enforce mint posture >= min_score.
fn verify_auth(
    token: &str,
    sessions_path: Option<&Path>,
    jwt_secret: Option<&str>,
    require_session: bool,
    min_score: u32,
    enforce_session_posture: bool,
) -> Result<SessionOk, &'static str> {
    // Prefer JWT when it looks like one and secret is configured
    if let Some(secret) = jwt_secret {
        if looks_like_jwt(token) {
            return match crate::jwt::verify(secret, token) {
                Ok(c) => {
                    let posture = c.posture.unwrap_or(0);
                    if enforce_session_posture && posture < min_score {
                        return Err("session_posture");
                    }
                    Ok(SessionOk {
                        user: c.sub,
                        posture_score: posture,
                        via: "jwt",
                    })
                }
                Err(_) => Err("jwt"),
            };
        }
    }

    if let Some(path) = sessions_path {
        let mut store = SessionStore::load(path);
        if let Some(v) = store.touch(token) {
            if enforce_session_posture && v.posture_score < min_score {
                return Err("session_posture");
            }
            let _ = store.save(path);
            return Ok(SessionOk {
                user: v.user,
                posture_score: v.posture_score,
                via: "session",
            });
        }
        if require_session || jwt_secret.is_none() {
            return Err("session");
        }
    }

    if jwt_secret.is_some() {
        return Err("jwt");
    }
    Err("session")
}

fn access_log_line(path: &Option<PathBuf>, line: &str) {
    let Some(p) = path else {
        return;
    };
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "{line}");
    }
}

fn emit(
    event_log: &PathBuf,
    action: EventAction,
    severity: Severity,
    message: impl Into<String>,
    attrs: &[(&str, serde_json::Value)],
) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::Gate,
            EventKind::Auth,
            action,
            severity,
            message,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, v.clone());
        }
        let _ = store.append(&ev);
    }
}

async fn current_score(state: &AppState) -> Result<u32, StatusCode> {
    {
        let guard = state.cache.read().await;
        if let Some((at, score)) = *guard {
            if at.elapsed().as_secs() < 15 {
                return Ok(score);
            }
        }
    }
    let fw = create_firewall_engine();
    let report = compute_posture_score(&fw)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut guard = state.cache.write().await;
    *guard = Some((Instant::now(), report.score));
    Ok(report.score)
}

/// Returns true if allowed, false if over limit.
async fn check_rate(state: &AppState, ip: IpAddr) -> bool {
    let limit = state.cfg.rate_limit_per_minute;
    if limit == 0 {
        return true;
    }
    let mut map = state.rate.write().await;
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // opportunistic prune when map grows
    if map.len() > 10_000 {
        map.retain(|_, (start, _)| now.duration_since(*start) < window);
    }
    let entry = map.entry(ip).or_insert((now, 0));
    if now.duration_since(entry.0) >= window {
        *entry = (now, 1);
        return true;
    }
    entry.1 = entry.1.saturating_add(1);
    entry.1 <= limit
}

fn client_ip(req: &Request<Body>, connect: Option<SocketAddr>) -> IpAddr {
    // Prefer X-Forwarded-For first hop only when present (operator-trusted edge)
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    connect
        .map(|s| s.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

async fn proxy_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let method = req.method().clone();
    let req_path = req.uri().path().to_string();
    let ip = client_ip(&req, Some(addr));

    // IP allowlist
    if !state.cfg.ip_allowed(ip) {
        emit(
            &state.event_log,
            EventAction::Blocked,
            Severity::High,
            format!("gate deny path={req_path} reason=ip ip={ip}"),
            &[
                ("path", serde_json::json!(req_path)),
                ("reason", serde_json::json!("ip")),
                ("ip", serde_json::json!(ip.to_string())),
            ],
        );
        access_log_line(
            &state.access_log,
            &format!(
                "{} DENY {} reason=ip ip={}",
                chrono::Utc::now().to_rfc3339(),
                req_path,
                ip
            ),
        );
        let body = format!("S2O Gate DENY: client IP {ip} not on allowlist\n");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(body))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Rate limit
    if !check_rate(&state, ip).await {
        emit(
            &state.event_log,
            EventAction::Blocked,
            Severity::Medium,
            format!("gate deny path={req_path} reason=rate_limit ip={ip}"),
            &[
                ("path", serde_json::json!(req_path)),
                ("reason", serde_json::json!("rate_limit")),
                ("ip", serde_json::json!(ip.to_string())),
            ],
        );
        access_log_line(
            &state.access_log,
            &format!(
                "{} DENY {} reason=rate_limit ip={}",
                chrono::Utc::now().to_rfc3339(),
                req_path,
                ip
            ),
        );
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::RETRY_AFTER, "60")
            .body(Body::from("S2O Gate DENY: rate limit exceeded\n"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Optional CyberID session and/or local JWT (OIDC-lite)
    let mut session_user: Option<String> = None;
    let mut session_score: Option<u32> = None;
    let auth_required = state.require_session || state.jwt_secret.is_some();
    if auth_required {
        let token = extract_session_token(&req);
        let result = match token.as_deref() {
            Some(t) => verify_auth(
                t,
                state.sessions_path.as_deref(),
                state.jwt_secret.as_deref(),
                state.require_session,
                state.cfg.min_score,
                state.cfg.enforce_session_posture,
            ),
            None => Err("session"),
        };
        match result {
            Ok(ok) => {
                session_user = Some(ok.user);
                session_score = Some(ok.posture_score);
                // stash via in a local for logging via score path
                let _via = ok.via;
            }
            Err(reason) => {
                let (status, msg) = match reason {
                    "session_posture" => (
                        StatusCode::FORBIDDEN,
                        "S2O Gate DENY: token posture below min_score\n",
                    ),
                    "jwt" => (
                        StatusCode::UNAUTHORIZED,
                        "S2O Gate DENY: missing or invalid JWT (Authorization: Bearer)\n",
                    ),
                    _ => (
                        StatusCode::UNAUTHORIZED,
                        "S2O Gate DENY: missing or invalid session/JWT (X-Aegis-Session / Bearer)\n",
                    ),
                };
                emit(
                    &state.event_log,
                    EventAction::Blocked,
                    Severity::High,
                    format!("gate deny path={req_path} reason={reason}"),
                    &[
                        ("path", serde_json::json!(req_path)),
                        ("reason", serde_json::json!(reason)),
                    ],
                );
                access_log_line(
                    &state.access_log,
                    &format!(
                        "{} DENY {} reason={} ip={}",
                        chrono::Utc::now().to_rfc3339(),
                        req_path,
                        reason,
                        ip
                    ),
                );
                let mut builder = Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
                if status == StatusCode::UNAUTHORIZED {
                    builder = builder.header(header::WWW_AUTHENTICATE, "Bearer realm=\"s2o-gate\"");
                }
                return builder
                    .body(Body::from(msg))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    let score = current_score(&state).await?;
    if score < state.cfg.min_score {
        emit(
            &state.event_log,
            EventAction::Blocked,
            Severity::High,
            format!(
                "gate deny path={} score={} min={}",
                req_path, score, state.cfg.min_score
            ),
            &[
                ("path", serde_json::json!(req_path)),
                ("score", serde_json::json!(score)),
                ("min_score", serde_json::json!(state.cfg.min_score)),
            ],
        );
        access_log_line(
            &state.access_log,
            &format!(
                "{} DENY {} score={} min={} ip={}",
                chrono::Utc::now().to_rfc3339(),
                req_path,
                score,
                state.cfg.min_score,
                ip
            ),
        );
        let body = format!(
            "S2O Gate DENY: posture score {score} < min {}\n",
            state.cfg.min_score
        );
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-aegis-posture-score", score.to_string())
            .body(Body::from(body))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let route_name;
    let upstream_base;
    let path_prefix;
    {
        let route = state
            .cfg
            .match_route(&path)
            .ok_or(StatusCode::NOT_FOUND)?;
        route_name = route.name.clone();
        upstream_base = route.upstream.trim_end_matches('/').to_string();
        path_prefix = route.path_prefix.clone();
    }

    // Strip route prefix when not root
    let forward_path = if path_prefix != "/" && path_and_query.starts_with(&path_prefix) {
        let rest = &path_and_query[path_prefix.len()..];
        if rest.is_empty() {
            "/".to_string()
        } else if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        }
    } else {
        path_and_query
    };

    let url = format!("{upstream_base}{forward_path}");

    let headers = req.headers().clone();
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_bytes();

    let mut builder = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET),
        &url,
    );

    for (name, value) in headers.iter() {
        // hop-by-hop
        if matches!(
            name.as_str(),
            "host" | "connection" | "transfer-encoding" | "content-length"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }
    builder = builder.header("x-aegis-posture-score", score.to_string());
    builder = builder.header("x-aegis-gate", "s2o-gate");
    builder = builder.header("x-aegis-client-ip", ip.to_string());
    if let Some(ref u) = session_user {
        builder = builder.header("x-aegis-user", u.as_str());
    }
    if let Some(ss) = session_score {
        builder = builder.header("x-aegis-session-score", ss.to_string());
    }

    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.clone());
    }

    let upstream_res = builder.send().await.map_err(|e| {
        eprintln!("[gate] upstream error {url}: {e}");
        StatusCode::BAD_GATEWAY
    })?;

    let status_code = upstream_res.status().as_u16();
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_builder = Response::builder().status(status);
    // Copy headers via bytes to avoid http crate version mismatch (reqwest vs axum)
    for (name, value) in upstream_res.headers().iter() {
        if matches!(
            name.as_str(),
            "connection" | "transfer-encoding" | "content-length"
        ) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()),
            axum::http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response_builder = response_builder.header(n, v);
        }
    }
    response_builder = response_builder.header("x-aegis-posture-score", score.to_string());

    let bytes = upstream_res
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    emit(
        &state.event_log,
        EventAction::Allowed,
        Severity::Info,
        format!("gate allow path={path} route={route_name} upstream_status={status_code}"),
        &[
            ("path", serde_json::json!(path)),
            ("route", serde_json::json!(route_name)),
            ("score", serde_json::json!(score)),
            ("upstream_status", serde_json::json!(status_code)),
            ("ip", serde_json::json!(ip.to_string())),
        ],
    );
    access_log_line(
        &state.access_log,
        &format!(
            "{} ALLOW {} {} route={} status={} score={} user={} ip={}",
            chrono::Utc::now().to_rfc3339(),
            method,
            path,
            route_name,
            status_code,
            score,
            session_user.as_deref().unwrap_or("-"),
            ip
        ),
    );

    response_builder
        .body(Body::from(Bytes::from(bytes)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// When set, require client certificates signed by this CA (mTLS)
    pub mtls_ca: Option<PathBuf>,
}

pub struct AuthOptions {
    pub require_session: bool,
    pub sessions_path: Option<PathBuf>,
    pub jwt_secret: Option<String>,
}

pub async fn run(
    cfg: GateConfig,
    event_log: PathBuf,
    tls: Option<TlsFiles>,
    access_log: Option<PathBuf>,
    auth: AuthOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        cfg: cfg.clone(),
        event_log,
        access_log,
        sessions_path: auth.sessions_path,
        require_session: auth.require_session,
        jwt_secret: auth.jwt_secret,
        cache: Arc::new(RwLock::new(None)),
        rate: Arc::new(RwLock::new(HashMap::new())),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
    };

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(state);

    let addr: std::net::SocketAddr = cfg.listen.parse()?;

    if let Some(tls) = tls {
        if tls.mtls_ca.is_none() {
            crate::tls::ensure_self_signed(&tls.cert, &tls.key)?;
        }
        let server_config = crate::tls::build_server_config(
            &tls.cert,
            &tls.key,
            tls.mtls_ca.as_deref(),
        )?;
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
        if let Some(ref ca) = tls.mtls_ca {
            println!(
                "[gate] listening on https://{} (mTLS ca={})",
                cfg.listen,
                ca.display()
            );
        } else {
            println!(
                "[gate] listening on https://{} (cert {})",
                cfg.listen,
                tls.cert.display()
            );
        }
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        println!("[gate] listening on http://{}", cfg.listen);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}
