use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
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

#[async_trait]
impl FirewallEngine for LinuxFirewallEngine {
    async fn get_status(&self) -> EngineResult<FirewallStatus> {
        let is_nft_active = tokio::process::Command::new("nft")
            .arg("list")
            .arg("ruleset")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        Ok(FirewallStatus {
            enabled: is_nft_active,
            outbound_blocked: false,
            defender_active: false,
            profile_private: is_nft_active,
            profile_public: is_nft_active,
            profile_domain: is_nft_active,
            platform: "Linux".to_string(),
            backend_driver: "Linux nftables (read-only status; no eBPF)".to_string(),
            substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
        })
    }

    fn driver_capabilities(&self) -> cyberwall_core::DriverCapabilities {
        cyberwall_core::DriverCapabilities {
            substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
            os: cyberwall_core::OperatingSystem::Linux,
            supports_packet_injection: true,
            supports_process_lineage: true,
            supports_kernel_bypass: false,
            driver_version: Some("nftables / ProcFS Userspace Substrate".to_string()),
        }
    }

    // NOTE: the previous set_enabled ran `nft flush ruleset` regardless of the
    // requested state (wiping the host firewall even when "enabling"), and
    // set_outbound_block / list_rules ignored errors or returned a fabricated
    // rule. They now fail loudly until a real nftables implementation exists.
    async fn set_enabled(&self, _enabled: bool) -> EngineResult<()> {
        Err(EngineError("Linux set_enabled not implemented yet".into()))
    }

    async fn set_outbound_block(&self, _blocked: bool) -> EngineResult<()> {
        Err(EngineError(
            "Linux set_outbound_block not implemented yet".into(),
        ))
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        Err(EngineError("Linux list_rules not implemented yet".into()))
    }

    async fn add_rule(&self, _rule: &FirewallRule) -> EngineResult<()> {
        Err(EngineError("Linux add_rule not yet implemented".into()))
    }

    async fn delete_rule(&self, _rule_name: &str) -> EngineResult<()> {
        Err(EngineError("Linux delete_rule not yet implemented".into()))
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Err(EngineError("Linux apply_policy not implemented yet".into()))
    }
}
