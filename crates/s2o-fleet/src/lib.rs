//! Local fleet host inventory + policy distribution (file-backed JSON).
//!
//! T0 multi-host roster: enroll/heartbeat/list + shared policy pack push/pull.
//! Not a full multi-tenant control plane.

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
    /// Last fleet policy version this host reported as applied
    #[serde(default)]
    pub policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStore {
    pub version: String,
    pub hosts: Vec<FleetHost>,
}

/// Distributed policy pack for fleet agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPolicyBundle {
    /// Monotonic version (bump on each set)
    pub version: u64,
    pub name: String,
    pub updated_at: String,
    /// Full PolicyDocument JSON
    pub document: serde_json::Value,
}

impl FleetPolicyBundle {
    pub fn load(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
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

    /// Create or bump version from a policy JSON value.
    pub fn from_document(document: serde_json::Value, prev: Option<&Self>) -> Self {
        let name = document
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("fleet-policy")
            .to_string();
        let version = prev.map(|p| p.version.saturating_add(1)).unwrap_or(1);
        Self {
            version,
            name,
            updated_at: Utc::now().to_rfc3339(),
            document,
        }
    }
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
    /// Policy version the agent has applied
    #[serde(default)]
    pub policy_version: Option<u64>,
}

/// Heartbeat response includes desired policy version so agents know to pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub host: FleetHost,
    pub desired_policy_version: u64,
    pub policy_stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    pub total: usize,
    pub online: usize,
    pub stale: usize,
    pub avg_posture: f64,
    #[serde(default)]
    pub policy_version: u64,
    #[serde(default)]
    pub hosts_on_policy: usize,
    #[serde(default)]
    pub hosts_behind_policy: usize,
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
            if let Some(v) = hb.policy_version {
                h.policy_version = v;
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
            policy_version: hb.policy_version.unwrap_or(0),
        };
        self.hosts.push(host.clone());
        host
    }

    pub fn remove(&mut self, host_id: &str) -> bool {
        let before = self.hosts.len();
        self.hosts
            .retain(|h| h.host_id != host_id && h.display_name != host_id);
        self.hosts.len() < before
    }

    pub fn get(&self, id: &str) -> Option<&FleetHost> {
        self.hosts
            .iter()
            .find(|h| h.host_id == id || h.display_name == id)
    }

    pub fn summary(&self, stale_minutes: i64) -> FleetSummary {
        self.summary_with_policy(stale_minutes, 0)
    }

    pub fn summary_with_policy(&self, stale_minutes: i64, policy_version: u64) -> FleetSummary {
        let now = Utc::now();
        let mut online = 0usize;
        let mut stale = 0usize;
        let mut posture_sum = 0u64;
        let mut on_policy = 0usize;
        let mut behind = 0usize;
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
            if policy_version > 0 {
                if h.policy_version >= policy_version {
                    on_policy += 1;
                } else {
                    behind += 1;
                }
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
            policy_version,
            hosts_on_policy: on_policy,
            hosts_behind_policy: behind,
        }
    }

    pub fn is_stale(host: &FleetHost, stale_minutes: i64) -> bool {
        let now = Utc::now();
        chrono::DateTime::parse_from_rfc3339(&host.last_seen)
            .map(|t| {
                now.signed_duration_since(t.with_timezone(&Utc))
                    > Duration::minutes(stale_minutes.max(1))
            })
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
    fn upsert_policy_and_summary() {
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
            policy_version: Some(1),
        });
        let sum = s.summary_with_policy(60, 2);
        assert_eq!(sum.hosts_behind_policy, 1);
        assert_eq!(sum.hosts_on_policy, 0);
        let doc = serde_json::json!({"name": "p1", "schema_version": "0.1.0"});
        let b = FleetPolicyBundle::from_document(doc, None);
        assert_eq!(b.version, 1);
        let b2 = FleetPolicyBundle::from_document(serde_json::json!({"name": "p2"}), Some(&b));
        assert_eq!(b2.version, 2);
    }
}
