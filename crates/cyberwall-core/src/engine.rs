use crate::models::{FirewallPolicy, FirewallRule, FirewallStatus};
use async_trait::async_trait;
use std::fmt;

#[derive(Debug)]
pub struct EngineError(pub String);

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for EngineError {}

pub type EngineResult<T> = Result<T, EngineError>;

#[async_trait]
pub trait FirewallEngine: Send + Sync {
    /// Returns the current OS firewall status & profile states
    async fn get_status(&self) -> EngineResult<FirewallStatus>;

    /// Enables or disables the OS firewall across all profiles
    async fn set_enabled(&self, enabled: bool) -> EngineResult<()>;

    /// Enables or disables outbound airplane/isolation mode shield
    async fn set_outbound_block(&self, blocked: bool) -> EngineResult<()>;

    /// Lists active OS firewall rules
    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>>;

    /// Lists rules matching a filter
    async fn list_rules_filtered(&self, filter: &crate::models::RuleFilter) -> EngineResult<Vec<FirewallRule>> {
        let rules = self.list_rules().await?;
        Ok(rules.into_iter().filter(|r| {
            if let Some(dir) = filter.direction {
                if r.direction != dir { return false; }
            }
            if let Some(act) = filter.action {
                if r.action != act { return false; }
            }
            if let Some(ref s) = filter.search {
                if !r.name.to_lowercase().contains(&s.to_lowercase()) { return false; }
            }
            true
        }).collect())
    }

    /// Adds a new firewall rule
    async fn add_rule(&self, rule: &FirewallRule) -> EngineResult<()>;

    /// Deletes a firewall rule by name
    async fn delete_rule(&self, rule_name: &str) -> EngineResult<()>;

    /// Returns the active driver capabilities & substrate (Userspace vs Kernel)
    fn driver_capabilities(&self) -> crate::models::DriverCapabilities {
        crate::models::DriverCapabilities {
            substrate: crate::models::DriverSubstrate::UserspaceNative,
            os: crate::models::OperatingSystem::current(),
            supports_packet_injection: false,
            supports_process_lineage: true,
            supports_kernel_bypass: false,
            driver_version: None,
        }
    }

    /// Check whether a kernel-mode driver / eBPF program is actively attached
    fn is_kernel_driver_active(&self) -> bool {
        self.driver_capabilities().substrate == crate::models::DriverSubstrate::KernelDriver
    }

    /// Applies a declarative policy configuration
    async fn apply_policy(&self, policy: &FirewallPolicy) -> EngineResult<()>;
}
