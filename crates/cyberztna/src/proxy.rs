//! Posture-gated reverse proxy (axum + reqwest).

use crate::config::GateConfig;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use s2o_kernel::{compute_posture_score, create_firewall_engine, host_id};
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    cfg: GateConfig,
    event_log: PathBuf,
    /// Cached posture score with TTL
    cache: Arc<RwLock<Option<(std::time::Instant, u32)>>>,
    client: reqwest::Client,
}

fn emit(event_log: &PathBuf, action: EventAction, severity: Severity, message: impl Into<String>, attrs: &[(&str, serde_json::Value)]) {
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
    *guard = Some((std::time::Instant::now(), report.score));
    Ok(report.score)
}

async fn proxy_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let score = current_score(&state).await?;
    if score < state.cfg.min_score {
        emit(
            &state.event_log,
            EventAction::Blocked,
            Severity::High,
            format!(
                "gate deny path={} score={} min={}",
                req.uri().path(),
                score,
                state.cfg.min_score
            ),
            &[
                ("path", serde_json::json!(req.uri().path())),
                ("score", serde_json::json!(score)),
                ("min_score", serde_json::json!(state.cfg.min_score)),
            ],
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

    let method = req.method().clone();
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
        format!(
            "gate allow path={path} route={route_name} upstream_status={status_code}"
        ),
        &[
            ("path", serde_json::json!(path)),
            ("route", serde_json::json!(route_name)),
            ("score", serde_json::json!(score)),
            ("upstream_status", serde_json::json!(status_code)),
        ],
    );

    response_builder
        .body(Body::from(Bytes::from(bytes)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub async fn run(
    cfg: GateConfig,
    event_log: PathBuf,
    tls: Option<TlsFiles>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        cfg: cfg.clone(),
        event_log,
        cache: Arc::new(RwLock::new(None)),
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
        crate::tls::ensure_self_signed(&tls.cert, &tls.key)?;
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        println!(
            "[gate] listening on https://{} (cert {})",
            cfg.listen,
            tls.cert.display()
        );
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        println!("[gate] listening on http://{}", cfg.listen);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    Ok(())
}
