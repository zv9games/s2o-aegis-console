use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
    ProfileType, RuleAction, RuleDirection, MANAGED_RULE_PREFIX,
};
use std::process::Command;

pub struct WindowsFirewallEngine;

impl WindowsFirewallEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsFirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn profile_netsh(p: ProfileType) -> &'static str {
    match p {
        ProfileType::Private => "private",
        ProfileType::Public => "public",
        ProfileType::Domain => "domain",
        ProfileType::All => "any",
    }
}

fn action_netsh(a: RuleAction) -> &'static str {
    match a {
        RuleAction::Allow => "allow",
        RuleAction::Block => "block",
    }
}

fn dir_netsh(d: RuleDirection) -> &'static str {
    match d {
        RuleDirection::Inbound => "in",
        RuleDirection::Outbound => "out",
    }
}

/// Build netsh advfirewall arguments for one managed rule (without the `netsh` binary).
pub fn netsh_add_args(rule: &FirewallRule) -> Result<Vec<String>, String> {
    if rule.name.trim().is_empty() {
        return Err("rule name empty".into());
    }
    let mut args = vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={}", rule.name),
        format!("dir={}", dir_netsh(rule.direction)),
        format!("action={}", action_netsh(rule.action)),
        format!(
            "enable={}",
            if rule.enabled { "yes" } else { "no" }
        ),
        format!("profile={}", profile_netsh(rule.profile)),
    ];
    if let Some(app) = rule.application.as_ref().filter(|s| !s.is_empty()) {
        args.push(format!("program={app}"));
    }
    if let Some(proto) = rule.protocol.as_ref().filter(|s| !s.is_empty()) {
        args.push(format!("protocol={proto}"));
    }
    if let Some(port) = rule.local_port.as_ref().filter(|s| !s.is_empty()) {
        args.push(format!("localport={port}"));
    }
    if let Some(ip) = rule.remote_ip.as_ref().filter(|s| !s.is_empty()) {
        args.push(format!("remoteip={ip}"));
    }
    // Port rules without protocol confuse netsh — default tcp when port set
    if rule.local_port.as_ref().is_some_and(|p| !p.is_empty())
        && rule.protocol.as_ref().map(|s| s.is_empty()).unwrap_or(true)
    {
        args.push("protocol=TCP".into());
    }
    Ok(args)
}

fn run_netsh(args: &[String]) -> EngineResult<String> {
    let out = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| EngineError(format!("netsh spawn failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(EngineError(format!(
            "netsh {} failed: {} {}",
            args.join(" "),
            stdout,
            stderr
        )));
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

fn apply_policy_sync(policy: &FirewallPolicy) -> EngineResult<usize> {
    let policy = policy.clone().ensure_managed_names();

    // Remove previously managed S2O rules (replace cycle).
    let existing = s2o_net_lib::firewall::FirewallController::get_rules()
        .map_err(|e| EngineError(format!("list for apply: {e:?}")))?;
    for r in existing
        .iter()
        .filter(|r| r.name.starts_with(MANAGED_RULE_PREFIX))
    {
        let _ = s2o_net_lib::firewall::FirewallController::remove_firewall_rule_by_name(&r.name);
    }

    let mut added = 0usize;
    for rule in &policy.rules {
        let args = netsh_add_args(rule).map_err(EngineError)?;
        run_netsh(&args)?;
        added += 1;
    }
    Ok(added)
}

#[async_trait]
impl FirewallEngine for WindowsFirewallEngine {
    async fn get_status(&self) -> EngineResult<FirewallStatus> {
        let profiles = tokio::task::spawn_blocking(|| {
            s2o_net_lib::firewall::FirewallController::get_profile_status()
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
        .map_err(|e| EngineError(format!("COM profile status: {e:?}")))?;

        let outbound_blocked = tokio::task::spawn_blocking(|| {
            s2o_net_lib::firewall::FirewallController::is_outbound_blocked().unwrap_or(false)
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?;

        let defender_active = tokio::task::spawn_blocking(|| {
            s2o_net_lib::defender::DefenderController::is_defender_active()
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?;

        Ok(FirewallStatus {
            enabled: profiles.any_interactive_enabled(),
            outbound_blocked,
            defender_active,
            profile_private: profiles.private,
            profile_public: profiles.public,
            profile_domain: profiles.domain,
            platform: "Windows".to_string(),
            backend_driver: "Win32 COM INetFwPolicy2 + netsh managed rules (S2O-Aegis-*)".to_string(),
        })
    }

    async fn set_enabled(&self, enabled: bool) -> EngineResult<()> {
        tokio::task::spawn_blocking(move || {
            if enabled {
                s2o_net_lib::firewall::FirewallController::enable_firewall()
            } else {
                s2o_net_lib::firewall::FirewallController::disable_firewall()
            }
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
        .map_err(|e| EngineError(format!("set_enabled({enabled}) failed: {e:?}")))?;

        Ok(())
    }

    async fn set_outbound_block(&self, blocked: bool) -> EngineResult<()> {
        tokio::task::spawn_blocking(move || {
            if blocked {
                s2o_net_lib::firewall::FirewallController::airplane_mode_enable()
            } else {
                s2o_net_lib::firewall::FirewallController::airplane_mode_disable()
            }
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
        .map_err(|e| EngineError(format!("set_outbound_block({blocked}) failed: {e:?}")))?;

        Ok(())
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        let rules = tokio::task::spawn_blocking(|| {
            s2o_net_lib::firewall::FirewallController::get_rules()
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
        .map_err(|e| EngineError(format!("list rules failed: {e:?}")))?;

        Ok(rules
            .into_iter()
            .map(|r| FirewallRule {
                name: r.name,
                enabled: r.enabled,
                action: match r.action.as_str() {
                    "Block" => RuleAction::Block,
                    _ => RuleAction::Allow,
                },
                // OS enumeration does not currently expose direction; default inbound.
                direction: RuleDirection::Inbound,
                profile: ProfileType::All,
                application: None,
                protocol: None,
                local_port: None,
                remote_ip: None,
            })
            .collect())
    }

    async fn apply_policy(&self, policy: &FirewallPolicy) -> EngineResult<()> {
        let policy = policy.clone();
        let n = tokio::task::spawn_blocking(move || apply_policy_sync(&policy))
            .await
            .map_err(|e| EngineError(e.to_string()))??;
        let _ = n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberwall_core::FirewallRule;

    #[test]
    fn netsh_args_port_block() {
        let mut r = FirewallRule::simple("S2O-Aegis-lab-445", RuleAction::Block, RuleDirection::Inbound);
        r.local_port = Some("445".into());
        let args = netsh_add_args(&r).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("name=S2O-Aegis-lab-445"));
        assert!(joined.contains("dir=in"));
        assert!(joined.contains("action=block"));
        assert!(joined.contains("localport=445"));
        assert!(joined.contains("protocol=TCP"));
    }
}
