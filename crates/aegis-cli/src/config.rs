//! Optional suite config: `.aegis/config.json`

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_event_log")]
    pub event_log: String,
    #[serde(default = "default_health_bind")]
    pub health_bind: String,
    #[serde(default = "default_min_posture")]
    pub min_posture: u32,
    #[serde(default = "default_playbooks")]
    pub playbooks: String,
    #[serde(default = "default_gate_config")]
    pub gate_config: String,
}

fn default_data_dir() -> String {
    ".aegis".into()
}
fn default_event_log() -> String {
    ".aegis/events.jsonl".into()
}
fn default_health_bind() -> String {
    "127.0.0.1:9090".into()
}
fn default_min_posture() -> u32 {
    40
}
fn default_playbooks() -> String {
    ".aegis/playbooks.json".into()
}
fn default_gate_config() -> String {
    ".aegis/gate-routes.json".into()
}

impl Default for SuiteConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            event_log: default_event_log(),
            health_bind: default_health_bind(),
            min_posture: default_min_posture(),
            playbooks: default_playbooks(),
            gate_config: default_gate_config(),
        }
    }
}

impl SuiteConfig {
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        if !path.exists() {
            return Self::default();
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(path, serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into()))
    }
}
