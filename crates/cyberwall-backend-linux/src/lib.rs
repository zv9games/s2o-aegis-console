//! Linux Cyberwall backend — Phase 1 partial (honest nft/firewalld probes).
//!
//! Does **not** flush rulesets or blindly DROP OUTPUT. Prefer firewalld when present;
//! otherwise report nft presence without destructive defaults.

use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
    ProfileType, RuleAction, RuleDirection,
};

pub struct LinuxFirewallEngine;

impl LinuxFirewallEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxFirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

async fn cmd_ok(program: &str, args: &[&str]) -> bool {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn cmd_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[async_trait]
impl FirewallEngine for LinuxFirewallEngine {
    async fn get_status(&self) -> EngineResult<FirewallStatus> {
        let firewalld = cmd_ok("firewall-cmd", &["--state"]).await;
        let nft = cmd_ok("nft", &["list", "ruleset"]).await;

        let (enabled, driver) = if firewalld {
            (true, "Linux firewalld (partial)".to_string())
        } else if nft {
            // nft present ≠ “enabled policy product”; mark enabled if ruleset non-empty-ish
            let ruleset = cmd_stdout("nft", &["list", "ruleset"]).await.unwrap_or_default();
            let has_rules = ruleset.lines().count() > 3;
            (
                has_rules,
                "Linux nftables (partial status)".to_string(),
            )
        } else {
            (false, "Linux: no firewalld/nft detected".to_string())
        };

        Ok(FirewallStatus {
            enabled,
            outbound_blocked: false,
            defender_active: false,
            profile_private: enabled,
            profile_public: enabled,
            profile_domain: enabled,
            platform: "Linux".into(),
            backend_driver: driver,
        })
    }

    async fn set_enabled(&self, enabled: bool) -> EngineResult<()> {
        // Prefer firewalld — never `nft flush ruleset`.
        if cmd_ok("firewall-cmd", &["--state"]).await {
            let arg = if enabled { "--set-default-zone=public" } else { "--panic-on" };
            // panic-on is emergency block-all; for disable we use panic-off and leave zone.
            // Honest partial: only support enable via ensuring firewalld running message.
            if enabled {
                let out = tokio::process::Command::new("firewall-cmd")
                    .args(["--set-default-zone=public"])
                    .output()
                    .await
                    .map_err(|e| EngineError(e.to_string()))?;
                if !out.status.success() {
                    return Err(EngineError(
                        "firewall-cmd enable path failed (need root?)".into(),
                    ));
                }
                let _ = arg;
                return Ok(());
            } else {
                return Err(EngineError(
                    "refusing to disable host firewall via destructive path in Phase 1; use OS tools"
                        .into(),
                ));
            }
        }

        Err(EngineError(
            "set_enabled: no safe firewalld path; nft auto-config not implemented (partial)".into(),
        ))
    }

    async fn set_outbound_block(&self, blocked: bool) -> EngineResult<()> {
        if !blocked {
            // Try firewalld panic off if we had panic on — best effort.
            if cmd_ok("firewall-cmd", &["--state"]).await {
                let _ = tokio::process::Command::new("firewall-cmd")
                    .arg("--panic-off")
                    .output()
                    .await;
                return Ok(());
            }
            return Err(EngineError(
                "outbound unlock: no firewalld; manual nft cleanup required".into(),
            ));
        }

        // Isolation: firewalld panic mode is the least-bad portable "lock".
        if cmd_ok("firewall-cmd", &["--state"]).await {
            let out = tokio::process::Command::new("firewall-cmd")
                .arg("--panic-on")
                .output()
                .await
                .map_err(|e| EngineError(e.to_string()))?;
            if out.status.success() {
                return Ok(());
            }
            return Err(EngineError(
                "firewall-cmd --panic-on failed (need root?)".into(),
            ));
        }

        Err(EngineError(
            "outbound block: firewalld not available; refusing raw iptables DROP in Phase 1".into(),
        ))
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        if let Some(text) = cmd_stdout("firewall-cmd", &["--list-all"]).await {
            let mut rules = Vec::new();
            for line in text.lines().take(32) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                rules.push(FirewallRule {
                    name: line.to_string(),
                    enabled: true,
                    action: RuleAction::Allow,
                    direction: RuleDirection::Inbound,
                    profile: ProfileType::All,
                    application: None,
                    protocol: None,
                    local_port: None,
                    remote_ip: None,
                });
            }
            return Ok(rules);
        }

        if let Some(text) = cmd_stdout("nft", &["list", "ruleset"]).await {
            let mut rules = Vec::new();
            for line in text.lines().filter(|l| l.contains("rule") || l.contains("accept") || l.contains("drop")).take(32) {
                rules.push(FirewallRule {
                    name: line.trim().to_string(),
                    enabled: true,
                    action: if line.contains("drop") {
                        RuleAction::Block
                    } else {
                        RuleAction::Allow
                    },
                    direction: RuleDirection::Inbound,
                    profile: ProfileType::All,
                    application: None,
                    protocol: None,
                    local_port: None,
                    remote_ip: None,
                });
            }
            return Ok(rules);
        }

        Ok(vec![])
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Err(EngineError(
            "apply_policy not implemented on Linux (Phase 1 partial)".into(),
        ))
    }
}
