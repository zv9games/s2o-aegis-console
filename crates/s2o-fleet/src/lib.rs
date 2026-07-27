//! Local fleet host inventory (file-backed JSON).
//!
//! T0 multi-host roster: enroll/heartbeat/list. Not a full fleet control plane.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHost {
    pub host_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub posture_score: u32,
    #[serde(default)]
    pub modules_implemented: u32,
    #[serde(default)]
    pub modules_partial: u32,
    #[serde(default)]
    pub modules_other: u32,
    #[serde(default)]
    pub tags: Vec<String>,
    pub enrolled_at: String,
    pub last_seen: String,
    #[serde(default)]
    pub last_ip: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStore {
    pub version: String,
    pub hosts: Vec<FleetHost>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub host_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub posture_score: Option<u32>,
    #[serde(default)]
    pub modules_implemented: Option<u32>,
    #[serde(default)]
    pub modules_partial: Option<u32>,
    #[serde(default)]
    pub modules_other: Option<u32>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub last_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    pub total: usize,
    pub online: usize,
    pub stale: usize,
    pub avg_posture: f64,
}

impl FleetStore {
    pub fn new() -> Self {
        Self {
            version: "0.1.0".into(),
            hosts: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::new();
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_else(Self::new)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        let mut out = self.clone();
        if out.version.is_empty() {
            out.version = "0.1.0".into();
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()),
        )
    }

    pub fn upsert_heartbeat(&mut self, hb: HeartbeatPayload) -> FleetHost {
        let now = Utc::now().to_rfc3339();
        if let Some(h) = self.hosts.iter_mut().find(|h| h.host_id == hb.host_id) {
            if let Some(v) = hb.display_name {
                if !v.is_empty() {
                    h.display_name = v;
                }
            }
            if let Some(v) = hb.os {
                h.os = v;
            }
            if let Some(v) = hb.phase {
                h.phase = v;
            }
            if let Some(v) = hb.kernel {
                h.kernel = v;
            }
            if let Some(v) = hb.posture_score {
                h.posture_score = v;
            }
            if let Some(v) = hb.modules_implemented {
                h.modules_implemented = v;
            }
            if let Some(v) = hb.modules_partial {
                h.modules_partial = v;
            }
            if let Some(v) = hb.modules_other {
                h.modules_other = v;
            }
            if let Some(v) = hb.tags {
                h.tags = v;
            }
            if hb.last_ip.is_some() {
                h.last_ip = hb.last_ip;
            }
            h.last_seen = now;
            return h.clone();
        }
        let host = FleetHost {
            host_id: hb.host_id,
            display_name: hb.display_name.unwrap_or_default(),
            os: hb.os.unwrap_or_default(),
            phase: hb.phase.unwrap_or_default(),
            kernel: hb.kernel.unwrap_or_default(),
            posture_score: hb.posture_score.unwrap_or(0),
            modules_implemented: hb.modules_implemented.unwrap_or(0),
            modules_partial: hb.modules_partial.unwrap_or(0),
            modules_other: hb.modules_other.unwrap_or(0),
            tags: hb.tags.unwrap_or_default(),
            enrolled_at: now.clone(),
            last_seen: now,
            last_ip: hb.last_ip,
            notes: None,
        };
        self.hosts.push(host.clone());
        host
    }

    pub fn remove(&mut self, host_id: &str) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|h| h.host_id != host_id && h.display_name != host_id);
        self.hosts.len() < before
    }

    pub fn get(&self, id: &str) -> Option<&FleetHost> {
        self.hosts
            .iter()
            .find(|h| h.host_id == id || h.display_name == id)
    }

    /// Hosts with last_seen older than `stale_minutes` are stale.
    pub fn summary(&self, stale_minutes: i64) -> FleetSummary {
        let now = Utc::now();
        let mut online = 0usize;
        let mut stale = 0usize;
        let mut posture_sum = 0u64;
        for h in &self.hosts {
            posture_sum += h.posture_score as u64;
            let ls = chrono::DateTime::parse_from_rfc3339(&h.last_seen)
                .map(|t| t.with_timezone(&Utc))
                .ok();
            let is_stale = match ls {
                Some(t) => now.signed_duration_since(t) > Duration::minutes(stale_minutes.max(1)),
                None => true,
            };
            if is_stale {
                stale += 1;
            } else {
                online += 1;
            }
        }
        let total = self.hosts.len();
        FleetSummary {
            total,
            online,
            stale,
            avg_posture: if total == 0 {
                0.0
            } else {
                posture_sum as f64 / total as f64
            },
        }
    }

    pub fn is_stale(host: &FleetHost, stale_minutes: i64) -> bool {
        let now = Utc::now();
        chrono::DateTime::parse_from_rfc3339(&host.last_seen)
            .map(|t| now.signed_duration_since(t.with_timezone(&Utc)) > Duration::minutes(stale_minutes.max(1)))
            .unwrap_or(true)
    }
}

impl Default for FleetStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_summary() {
        let mut s = FleetStore::new();
        s.upsert_heartbeat(HeartbeatPayload {
            host_id: "h1".into(),
            display_name: Some("alpha".into()),
            os: Some("windows".into()),
            phase: Some("phase3_access".into()),
            kernel: Some("0.1.0".into()),
            posture_score: Some(80),
            modules_implemented: Some(3),
            modules_partial: Some(5),
            modules_other: Some(1),
            tags: Some(vec!["lab".into()]),
            last_ip: Some("127.0.0.1".into()),
        });
        assert_eq!(s.hosts.len(), 1);
        s.upsert_heartbeat(HeartbeatPayload {
            host_id: "h1".into(),
            display_name: None,
            os: None,
            phase: None,
            kernel: None,
            posture_score: Some(90),
            modules_implemented: None,
            modules_partial: None,
            modules_other: None,
            tags: None,
            last_ip: None,
        });
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].posture_score, 90);
        let sum = s.summary(60);
        assert_eq!(sum.total, 1);
        assert_eq!(sum.online, 1);
        assert!(s.remove("h1"));
        assert!(s.hosts.is_empty());
    }
}
