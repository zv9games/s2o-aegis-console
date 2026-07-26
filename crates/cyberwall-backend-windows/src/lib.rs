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
            })
            .collect())
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Err(EngineError(
            "apply_policy not implemented yet (Phase 1)".into(),
        ))
    }
}
