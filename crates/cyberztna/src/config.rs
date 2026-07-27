use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRoute {
    pub name: String,
    /// Path prefix on the gate listener (e.g. `/app` or `/`)
    pub path_prefix: String,
    /// Upstream base URL (e.g. `http://127.0.0.1:8080`)
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    pub listen: String,
    pub min_score: u32,
    pub routes: Vec<GateRoute>,
}

pub fn default_config() -> GateConfig {
    GateConfig {
        listen: "127.0.0.1:18443".into(),
        min_score: 50,
        routes: vec![GateRoute {
            name: "demo".into(),
            path_prefix: "/".into(),
            upstream: "https://example.com".into(),
        }],
    }
}

pub fn load_config(path: &Path) -> Result<GateConfig, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_config(path: &Path, cfg: &GateConfig) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

impl GateConfig {
    pub fn match_route(&self, path: &str) -> Option<&GateRoute> {
        let mut best: Option<&GateRoute> = None;
        let mut best_len = 0usize;
        for r in &self.routes {
            let prefix = if r.path_prefix.is_empty() {
                "/"
            } else {
                r.path_prefix.as_str()
            };
            if path == prefix || path.starts_with(prefix) || (prefix == "/" && path.starts_with('/'))
            {
                let len = prefix.len();
                if len >= best_len {
                    best_len = len;
                    best = Some(r);
                }
            }
        }
        best
    }
}
