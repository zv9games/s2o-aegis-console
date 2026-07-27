//! Gate policy fragment — updates gate-routes.json with ZTNA defaults.

use std::fs;
use std::path::Path;

use s2o_schema::GatePolicyIntent;
use s2o_store::EventStore;

use crate::policy::{KernelError, KernelResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GateRoutesFile {
    listen: String,
    min_score: u32,
    routes: Vec<GateRouteFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    rate_limit_per_minute: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    require_session: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    enforce_session_posture: bool,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GateRouteFile {
    name: String,
    path_prefix: String,
    upstream: String,
}

pub fn apply_gate_intent(
    intent: &GatePolicyIntent,
    _store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    let path = Path::new(
        intent
            .config_path
            .as_deref()
            .unwrap_or(".aegis/gate-routes.json"),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut cfg = if path.exists() {
        let text = fs::read_to_string(path)?;
        serde_json::from_str::<GateRoutesFile>(&text).unwrap_or_else(|_| default_gate())
    } else {
        default_gate()
    };

    let mut applied = Vec::new();
    if let Some(m) = intent.min_score {
        cfg.min_score = m;
        applied.push(format!("gate.min_score={m}"));
    }
    if let Some(r) = intent.require_session {
        cfg.require_session = r;
        applied.push(format!("gate.require_session={r}"));
    }
    if let Some(rl) = intent.rate_limit_per_minute {
        cfg.rate_limit_per_minute = rl;
        applied.push(format!("gate.rate_limit_per_minute={rl}"));
    }
    if !intent.allow_ips.is_empty() {
        cfg.allow_ips = intent.allow_ips.clone();
        applied.push(format!("gate.allow_ips={}", intent.allow_ips.len()));
    }
    if applied.is_empty() {
        return Ok(applied);
    }

    let text = serde_json::to_string_pretty(&cfg).map_err(KernelError::Json)?;
    fs::write(path, text)?;
    applied.push(format!("gate.config={}", path.display()));
    Ok(applied)
}

fn default_gate() -> GateRoutesFile {
    GateRoutesFile {
        listen: "127.0.0.1:18443".into(),
        min_score: 50,
        routes: vec![GateRouteFile {
            name: "demo".into(),
            path_prefix: "/".into(),
            upstream: "https://example.com".into(),
        }],
        allow_ips: vec![],
        rate_limit_per_minute: 0,
        require_session: false,
        enforce_session_posture: false,
    }
}
