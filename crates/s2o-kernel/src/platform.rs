//! OS-selected Cyberwall engine handle.

use std::sync::Arc;

use cyberwall_core::FirewallEngine;

/// Shared engine handle used by status + policy apply.
pub type FirewallEngineHandle = Arc<dyn FirewallEngine>;

/// Construct the platform firewall engine for this build target.
pub fn create_firewall_engine() -> FirewallEngineHandle {
    #[cfg(windows)]
    {
        return Arc::new(cyberwall_backend_windows::WindowsFirewallEngine::new());
    }
    #[cfg(target_os = "linux")]
    {
        return Arc::new(cyberwall_backend_linux::LinuxFirewallEngine::new());
    }
    #[cfg(target_os = "macos")]
    {
        return Arc::new(cyberwall_backend_macos::MacosFirewallEngine::new());
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        return Arc::new(UnsupportedFirewallEngine);
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct UnsupportedFirewallEngine;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[async_trait::async_trait]
impl FirewallEngine for UnsupportedFirewallEngine {
    async fn get_status(&self) -> cyberwall_core::EngineResult<cyberwall_core::FirewallStatus> {
        Ok(cyberwall_core::FirewallStatus {
            enabled: false,
            outbound_blocked: false,
            defender_active: false,
            profile_private: false,
            profile_public: false,
            profile_domain: false,
            platform: "unsupported".into(),
            backend_driver: "none".into(),
        })
    }

    async fn set_enabled(&self, _enabled: bool) -> cyberwall_core::EngineResult<()> {
        Err(cyberwall_core::EngineError(
            "Cyberwall unsupported on this OS".into(),
        ))
    }

    async fn set_outbound_block(&self, _blocked: bool) -> cyberwall_core::EngineResult<()> {
        Err(cyberwall_core::EngineError(
            "Cyberwall unsupported on this OS".into(),
        ))
    }

    async fn list_rules(&self) -> cyberwall_core::EngineResult<Vec<cyberwall_core::FirewallRule>> {
        Ok(vec![])
    }

    async fn apply_policy(
        &self,
        _policy: &cyberwall_core::FirewallPolicy,
    ) -> cyberwall_core::EngineResult<()> {
        Err(cyberwall_core::EngineError(
            "Cyberwall unsupported on this OS".into(),
        ))
    }
}
