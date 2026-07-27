//! Platform honesty matrix collector.

use s2o_schema::{
    HealthState, ModuleStatus, OsFamily, PlatformStatus, ProductId, SCHEMA_VERSION,
};

use crate::host::{demo_mode, host_id};
use crate::platform::FirewallEngineHandle;
use crate::registry::{world_baseline, PHASE_LABEL, TIER_CEILING};

/// Build full platform status (9 worlds + live Cyberwall probe when possible).
pub async fn collect_platform_status(fw: &FirewallEngineHandle) -> PlatformStatus {
    let os = OsFamily::detect();
    let mut modules: Vec<ModuleStatus> = ProductId::worlds()
        .iter()
        .copied()
        .map(|p| world_baseline(p, os))
        .collect();

    // Live Cyberwall probe replaces baseline for wall row.
    if let Some(wall) = modules.iter_mut().find(|m| m.product == ProductId::Cyberwall) {
        match cyberwall_core::FirewallEngine::get_status(fw.as_ref()).await {
            Ok(st) => {
                wall.detail = format!(
                    "enabled={} private={} public={} domain={} outbound_blocked={} defender={}",
                    st.enabled,
                    st.profile_private,
                    st.profile_public,
                    st.profile_domain,
                    st.outbound_blocked,
                    st.defender_active
                );
                wall.backend = Some(st.backend_driver.clone());
                // Keep baseline state unless probe implies degradation impossible —
                // if we got status, backend is alive.
                if matches!(
                    wall.state,
                    HealthState::NotImplemented | HealthState::UnsupportedOnOs
                ) {
                    // leave as-is
                } else if !st.enabled
                    && matches!(os, OsFamily::Windows | OsFamily::Linux | OsFamily::Macos)
                {
                    // disabled firewall is still "implemented" — operator choice
                    wall.state = match os {
                        OsFamily::Windows => HealthState::Implemented,
                        OsFamily::Linux | OsFamily::Macos => HealthState::Partial,
                        _ => wall.state,
                    };
                }
            }
            Err(e) => {
                wall.state = HealthState::Degraded;
                wall.detail = format!("probe failed: {e}");
            }
        }
    }

    PlatformStatus {
        platform: "S2O Aegis".into(),
        schema_version: SCHEMA_VERSION.to_string(),
        phase: PHASE_LABEL.to_string(),
        tier_ceiling: TIER_CEILING,
        os,
        host_id: host_id(),
        demo_mode: demo_mode(),
        modules,
    }
}

/// Kernel self-row (optional append for verbose views).
#[allow(dead_code)]
pub fn kernel_module_row(os: OsFamily) -> ModuleStatus {
    world_baseline(ProductId::Aegis, os).with_backend(format!(
        "s2o-kernel {}",
        crate::KERNEL_VERSION
    ))
}


