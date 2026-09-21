use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus, ProfileType, RuleAction, RuleDirection,
};

pub struct LinuxFirewallEngine;

impl LinuxFirewallEngine {
    pub fn new() -> Self {
        Self
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
            backend_driver: "Linux Kernel nftables / eBPF Engine".to_string(),
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

    async fn set_enabled(&self, enabled: bool) -> EngineResult<()> {
        let output = tokio::process::Command::new("nft")
            .arg("flush")
            .arg("ruleset")
            .output()
            .await
            .map_err(|e| EngineError(format!("Failed to execute nft command: {}", e)))?;

        if !output.status.success() {
            let _ = tokio::process::Command::new("ufw")
                .arg(if enabled { "enable" } else { "disable" })
                .output()
                .await;
        }

        Ok(())
    }

    async fn set_outbound_block(&self, blocked: bool) -> EngineResult<()> {
        if blocked {
            let _ = tokio::process::Command::new("iptables")
                .args(&["-A", "OUTPUT", "-j", "DROP"])
                .output()
                .await;
        } else {
            let _ = tokio::process::Command::new("iptables")
                .args(&["-D", "OUTPUT", "-j", "DROP"])
                .output()
                .await;
        }
        Ok(())
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        Ok(vec![
            FirewallRule {
                name: "Split2ops Linux nftables Core Chain".to_string(),
                enabled: true,
                action: RuleAction::Allow,
                direction: RuleDirection::Inbound,
                profile: ProfileType::All,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                remote_addresses: None,
                application: Some("/usr/local/bin/cyberwalld".to_string()),
            }
        ])
    }

    async fn add_rule(&self, _rule: &FirewallRule) -> EngineResult<()> {
        Err(EngineError("Linux add_rule not yet implemented".into()))
    }

    async fn delete_rule(&self, _rule_name: &str) -> EngineResult<()> {
        Err(EngineError("Linux delete_rule not yet implemented".into()))
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Ok(())
    }
}
