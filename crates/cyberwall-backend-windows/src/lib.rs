use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
    ProfileType, RuleAction, RuleDirection,
};

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
            backend_driver: "Win32 COM INetFwPolicy2 (netsh fallback on set)".to_string(),
            substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
        })
    }

    fn driver_capabilities(&self) -> cyberwall_core::DriverCapabilities {
        cyberwall_core::DriverCapabilities {
            substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
            os: cyberwall_core::OperatingSystem::Windows,
            supports_packet_injection: false,
            supports_process_lineage: true,
            supports_kernel_bypass: false,
            driver_version: Some("Tier-0 WFP/COM Userspace Substrate".to_string()),
        }
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
                direction: RuleDirection::Inbound,
                profile: ProfileType::All,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                remote_addresses: None,
                application: None,
            })
            .collect())
    }

    async fn add_rule(&self, rule: &FirewallRule) -> EngineResult<()> {
        let rule_clone = rule.clone();
        tokio::task::spawn_blocking(move || {
            let action_str = match rule_clone.action {
                RuleAction::Allow => "allow",
                RuleAction::Block => "block",
            };
            let dir_str = match rule_clone.direction {
                RuleDirection::Inbound => "in",
                RuleDirection::Outbound => "out",
            };
            let mut cmd = std::process::Command::new("netsh");
            cmd.args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_clone.name),
                &format!("dir={}", dir_str),
                &format!("action={}", action_str),
                &format!("enable={}", if rule_clone.enabled { "yes" } else { "no" }),
            ]);

            if let Some(ref proto) = rule_clone.protocol {
                let p_str = match proto {
                    cyberwall_core::RuleProtocol::Tcp => "TCP",
                    cyberwall_core::RuleProtocol::Udp => "UDP",
                    cyberwall_core::RuleProtocol::Icmp => "ICMPv4",
                    cyberwall_core::RuleProtocol::Any => "any",
                };
                cmd.arg(format!("protocol={}", p_str));
            }

            if let Some(ref lp) = rule_clone.local_ports {
                cmd.arg(format!("localport={}", lp));
            }

            if let Some(ref rp) = rule_clone.remote_ports {
                cmd.arg(format!("remoteport={}", rp));
            }

            if let Some(ref ra) = rule_clone.remote_addresses {
                cmd.arg(format!("remoteip={}", ra));
            }

            if let Some(ref app) = rule_clone.application {
                cmd.arg(format!("program={}", app));
            }

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }

            let output = cmd.output().map_err(|e| {
                EngineError(format!("Failed to execute netsh add rule: {}", e))
            })?;

            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                Err(EngineError(format!(
                    "netsh add rule failed: {stderr} {stdout}"
                )))
            }
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
    }

    async fn delete_rule(&self, rule_name: &str) -> EngineResult<()> {
        let name = rule_name.to_string();
        tokio::task::spawn_blocking(move || {
            // First try COM removal via s2o_net_lib
            if let Ok(()) = s2o_net_lib::firewall::FirewallController::remove_firewall_rule_by_name(&name) {
                return Ok(());
            }

            // Fallback to netsh
            let mut cmd = std::process::Command::new("netsh");
            cmd.args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", name),
            ]);

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000);
            }

            let output = cmd.output().map_err(|e| {
                EngineError(format!("Failed to execute netsh delete rule: {}", e))
            })?;

            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                Err(EngineError(format!(
                    "netsh delete rule failed: {stderr} {stdout}"
                )))
            }
        })
        .await
        .map_err(|e| EngineError(e.to_string()))?
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Err(EngineError(
            "apply_policy not implemented yet (Phase 1)".into(),
        ))
    }
}
