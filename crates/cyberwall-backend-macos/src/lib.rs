//! macOS Application Firewall backend — Phase 1/3 partial.
//!
//! Status + enable/disable via `socketfilterfw`. Managed apply blocks apps by path
//! (`--blockapp`) with state file for replace cycle. Full NEFilter is T1+ / entitlements.

use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
    MANAGED_RULE_PREFIX,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SFFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

pub struct MacosFirewallEngine;

impl MacosFirewallEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosFirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MacosManagedState {
    version: String,
    /// App paths previously blocked by apply_policy
    blocked_apps: Vec<String>,
}

fn managed_state_path() -> PathBuf {
    PathBuf::from(".aegis/macos-fw-managed.json")
}

fn load_state() -> MacosManagedState {
    let p = managed_state_path();
    if !p.exists() {
        return MacosManagedState::default();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(st: &MacosManagedState) -> Result<(), String> {
    if let Some(parent) = managed_state_path().parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        managed_state_path(),
        serde_json::to_string_pretty(st).unwrap_or_else(|_| "{}".into()),
    )
    .map_err(|e| e.to_string())
}

fn sffw(args: &[&str]) -> Result<String, String> {
    let out = Command::new(SFFW)
        .args(args)
        .output()
        .map_err(|e| format!("socketfilterfw spawn: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(format!(
            "socketfilterfw {} failed: {}{}",
            args.join(" "),
            stdout,
            stderr
        ));
    }
    Ok(stdout)
}

fn apply_policy_macos(policy: &FirewallPolicy) -> Result<(), String> {
    let policy = policy.clone().ensure_managed_names();
    let mut st = load_state();

    // Clear previously managed app blocks
    for app in &st.blocked_apps {
        let _ = sffw(&["--unblockapp", app]);
    }
    st.blocked_apps.clear();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }
        let Some(app) = rule.application.as_ref().filter(|s| !s.is_empty()) else {
            // Port rules not supported by Application Firewall — skip with note
            continue;
        };
        // Ensure app is registered then block/allow
        let _ = sffw(&["--add", app]);
        match rule.action {
            cyberwall_core::RuleAction::Block => {
                sffw(&["--blockapp", app])?;
                st.blocked_apps.push(app.clone());
            }
            cyberwall_core::RuleAction::Allow => {
                let _ = sffw(&["--unblockapp", app]);
            }
        }
        let _ = rule.name.starts_with(MANAGED_RULE_PREFIX);
    }

    st.version = policy.version.clone();
    save_state(&st)?;
    Ok(())
}

#[async_trait]
impl FirewallEngine for MacosFirewallEngine {
    async fn get_status(&self) -> EngineResult<FirewallStatus> {
        let output = tokio::process::Command::new(SFFW)
            .arg("--getglobalstate")
            .output()
            .await;

        let (enabled, detail_ok) = match output {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_lowercase();
                let on = stdout.contains("enabled") && !stdout.contains("disabled");
                (on, true)
            }
            _ => (false, false),
        };

        let managed = load_state().blocked_apps.len();
        Ok(FirewallStatus {
            enabled,
            outbound_blocked: false,
            defender_active: false,
            profile_private: enabled,
            profile_public: enabled,
            profile_domain: false,
            platform: "macOS".into(),
            backend_driver: if detail_ok {
                format!(
                    "macOS socketfilterfw (managed app blocks: {managed})"
                )
            } else {
                "macOS socketfilterfw (probe failed — partial)".into()
            },
        })
    }

    async fn set_enabled(&self, enabled: bool) -> EngineResult<()> {
        let flag = if enabled { "on" } else { "off" };
        let output = tokio::process::Command::new(SFFW)
            .arg("--setglobalstate")
            .arg(flag)
            .output()
            .await
            .map_err(|e| EngineError(format!("socketfilterfw failed: {e}")))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(EngineError(format!(
                "socketfilterfw --setglobalstate {flag} failed: {err} (may need root)"
            )));
        }
        Ok(())
    }

    async fn set_outbound_block(&self, _blocked: bool) -> EngineResult<()> {
        Err(EngineError(
            "outbound isolation not implemented on macOS (use per-app block via apply_policy)"
                .into(),
        ))
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        // Best-effort: listapps text → synthetic rules
        let text = tokio::task::spawn_blocking(|| sffw(&["--listapps"]))
            .await
            .map_err(|e| EngineError(e.to_string()))?
            .unwrap_or_default();
        let mut rules = Vec::new();
        for line in text.lines().take(64) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            rules.push(FirewallRule {
                name: line.to_string(),
                enabled: true,
                action: cyberwall_core::RuleAction::Allow,
                direction: cyberwall_core::RuleDirection::Outbound,
                profile: cyberwall_core::ProfileType::All,
                application: None,
                protocol: None,
                local_port: None,
                remote_ip: None,
            });
        }
        Ok(rules)
    }

    async fn apply_policy(&self, policy: &FirewallPolicy) -> EngineResult<()> {
        let policy = policy.clone();
        tokio::task::spawn_blocking(move || apply_policy_macos(&policy))
            .await
            .map_err(|e| EngineError(e.to_string()))?
            .map_err(EngineError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberwall_core::{FirewallRule, RuleAction, RuleDirection};

    #[test]
    fn state_roundtrip() {
        let st = MacosManagedState {
            version: "0.1".into(),
            blocked_apps: vec!["/Applications/Test.app".into()],
        };
        let s = serde_json::to_string(&st).unwrap();
        let back: MacosManagedState = serde_json::from_str(&s).unwrap();
        assert_eq!(back.blocked_apps.len(), 1);
    }

    #[test]
    fn managed_names() {
        let r = FirewallRule::simple("lab-app", RuleAction::Block, RuleDirection::Outbound);
        let p = cyberwall_core::FirewallPolicy {
            name: "t".into(),
            version: "1".into(),
            rules: vec![r],
        }
        .ensure_managed_names();
        assert!(p.rules[0].name.starts_with(MANAGED_RULE_PREFIX));
    }
}
