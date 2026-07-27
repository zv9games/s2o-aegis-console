//! Linux Cyberwall backend — Phase 1/3 partial (firewalld/nft probes + managed rules).
//!
//! Does **not** flush rulesets or blindly DROP OUTPUT. Prefer firewalld when present;
//! managed apply uses firewalld rich rules or an isolated `inet s2o_aegis` nft table.

use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
    ProfileType, RuleAction, RuleDirection, MANAGED_RULE_PREFIX,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

    async fn apply_policy(&self, policy: &FirewallPolicy) -> EngineResult<()> {
        let policy = policy.clone().ensure_managed_names();
        tokio::task::spawn_blocking(move || apply_policy_linux(&policy))
            .await
            .map_err(|e| EngineError(e.to_string()))?
    }
}

// ---------------------------------------------------------------------------
// Managed declarative rules (firewalld rich-rule or nft table s2o_aegis)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LinuxManagedState {
    version: String,
    /// firewalld rich-rule strings previously applied
    rich_rules: Vec<String>,
    /// true if nft table inet s2o_aegis was created
    nft_table: bool,
}

fn managed_state_path() -> PathBuf {
    PathBuf::from(".aegis/linux-fw-managed.json")
}

fn load_state() -> LinuxManagedState {
    let p = managed_state_path();
    if !p.exists() {
        return LinuxManagedState::default();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(st: &LinuxManagedState) -> Result<(), String> {
    if let Some(parent) = managed_state_path().parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        managed_state_path(),
        serde_json::to_string_pretty(st).unwrap_or_else(|_| "{}".into()),
    )
    .map_err(|e| e.to_string())
}

fn firewalld_running() -> bool {
    Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn rich_rule_for(rule: &FirewallRule) -> Result<String, String> {
    let port = rule
        .local_port
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            format!(
                "linux apply: rule {} needs local_port (app rules not supported)",
                rule.name
            )
        })?;
    let proto = rule
        .protocol
        .as_deref()
        .filter(|p| !p.is_empty())
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let action = match rule.action {
        RuleAction::Allow => "accept",
        RuleAction::Block => "reject",
    };
    // comment carries managed name for operators; firewalld may ignore unknown attrs
    let mut parts = vec![
        r#"rule family="ipv4""#.to_string(),
        format!(r#"port port="{port}" protocol="{proto}""#),
    ];
    if matches!(rule.direction, RuleDirection::Outbound) {
        parts.insert(1, r#"direction="out""#.to_string());
    }
    parts.push(action.to_string());
    Ok(parts.join(" "))
}

fn firewalld_remove_rich(rule: &str) {
    let _ = Command::new("firewall-cmd")
        .args(["--permanent", &format!("--remove-rich-rule={rule}")])
        .output();
}

fn firewalld_add_rich(rule: &str) -> Result<(), String> {
    let out = Command::new("firewall-cmd")
        .args(["--permanent", &format!("--add-rich-rule={rule}")])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "firewall-cmd add-rich-rule failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn firewalld_reload() -> Result<(), String> {
    let out = Command::new("firewall-cmd")
        .arg("--reload")
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "firewall-cmd --reload failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn apply_via_firewalld(policy: &FirewallPolicy) -> Result<(), String> {
    let mut st = load_state();
    for old in &st.rich_rules {
        firewalld_remove_rich(old);
    }
    st.rich_rules.clear();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }
        let rich = rich_rule_for(rule)?;
        firewalld_add_rich(&rich)?;
        st.rich_rules.push(rich);
    }
    firewalld_reload()?;
    st.version = policy.version.clone();
    st.nft_table = false;
    save_state(&st)?;
    let _ = MANAGED_RULE_PREFIX; // documented prefix used on Windows; Linux uses rich-rule state
    Ok(())
}

fn nft_delete_table() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "s2o_aegis"])
        .output();
}

fn apply_via_nft(policy: &FirewallPolicy) -> Result<(), String> {
    nft_delete_table();
    let mut script = String::from("table inet s2o_aegis {\n");
    script.push_str("  chain input {\n    type filter hook input priority 0; policy accept;\n");
    let mut out_rules = String::new();
    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }
        let port = rule
            .local_port
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| format!("nft apply: rule {} needs local_port", rule.name))?;
        let proto = rule
            .protocol
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        let verb = match rule.action {
            RuleAction::Allow => "accept",
            RuleAction::Block => "drop",
        };
        let line = format!(
            "    {proto} dport {{ {port} }} {verb} comment \"{}\"\n",
            rule.name.replace('"', "")
        );
        match rule.direction {
            RuleDirection::Inbound => script.push_str(&line),
            RuleDirection::Outbound => out_rules.push_str(&line.replace("dport", "dport")), // still dport for dest
        }
    }
    script.push_str("  }\n");
    if !out_rules.is_empty() {
        script.push_str("  chain output {\n    type filter hook output priority 0; policy accept;\n");
        // for outbound block of dest ports use dport on output chain
        script.push_str(&out_rules);
        script.push_str("  }\n");
    }
    script.push_str("}\n");

    let tmp = PathBuf::from(".aegis/linux-fw-nft.rules");
    if let Some(p) = tmp.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    fs::write(&tmp, &script).map_err(|e| e.to_string())?;
    let out = Command::new("nft")
        .args(["-f", tmp.to_str().unwrap_or(".aegis/linux-fw-nft.rules")])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "nft -f failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let st = LinuxManagedState {
        version: policy.version.clone(),
        rich_rules: vec![],
        nft_table: true,
    };
    save_state(&st)?;
    Ok(())
}

fn apply_policy_linux(policy: &FirewallPolicy) -> EngineResult<()> {
    if firewalld_running() {
        apply_via_firewalld(policy).map_err(EngineError)?;
        return Ok(());
    }
    if nft_available() {
        apply_via_nft(policy).map_err(EngineError)?;
        return Ok(());
    }
    Err(EngineError(
        "linux apply_policy: need firewalld or nft (and privileges)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_rule_block_port() {
        let mut r = FirewallRule::simple(
            format!("{MANAGED_RULE_PREFIX}lab-445"),
            RuleAction::Block,
            RuleDirection::Inbound,
        );
        r.local_port = Some("445".into());
        r.protocol = Some("TCP".into());
        let s = rich_rule_for(&r).unwrap();
        assert!(s.contains("445"));
        assert!(s.contains("tcp") || s.contains("TCP") || s.contains("protocol=\"tcp\""));
        assert!(s.contains("reject"));
    }
}
