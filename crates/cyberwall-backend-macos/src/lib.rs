//! macOS Application Firewall backend — Phase 1 partial (status + limited control).
//!
//! Full network extension / NEFilter is T1+ and entitlement-heavy; not in scope.

use async_trait::async_trait;
use cyberwall_core::{
    EngineError, EngineResult, FirewallEngine, FirewallPolicy, FirewallRule, FirewallStatus,
};

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

#[async_trait]
impl FirewallEngine for MacosFirewallEngine {
    async fn get_status(&self) -> EngineResult<FirewallStatus> {
        // `socketfilterfw --getglobalstate` prints e.g. "Firewall is enabled. (State = 1)"
        let output = tokio::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
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

        Ok(FirewallStatus {
            enabled,
            outbound_blocked: false,
            defender_active: false,
            profile_private: enabled,
            profile_public: enabled,
            profile_domain: false,
            platform: "macOS".into(),
            backend_driver: if detail_ok {
                "macOS socketfilterfw (status partial)".into()
            } else {
                "macOS socketfilterfw (probe failed — partial)".into()
            },
        })
    }

    async fn set_enabled(&self, enabled: bool) -> EngineResult<()> {
        let arg = if enabled {
            "--setglobalstate on"
        } else {
            "--setglobalstate off"
        };
        // split args properly
        let flag = if enabled { "on" } else { "off" };
        let output = tokio::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
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
        let _ = arg;
        Ok(())
    }

    async fn set_outbound_block(&self, _blocked: bool) -> EngineResult<()> {
        Err(EngineError(
            "outbound isolation not implemented on macOS in Phase 1".into(),
        ))
    }

    async fn list_rules(&self) -> EngineResult<Vec<FirewallRule>> {
        // No structured rule enum in Phase 1.
        Ok(vec![])
    }

    async fn apply_policy(&self, _policy: &FirewallPolicy) -> EngineResult<()> {
        Err(EngineError(
            "apply_policy not implemented on macOS (Phase 1 partial)".into(),
        ))
    }
}
