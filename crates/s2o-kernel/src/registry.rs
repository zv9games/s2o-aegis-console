//! Static world registry — the nine rooms marked on the slab.

use s2o_schema::{
    CapabilityTier, HealthState, ModuleStatus, OsFamily, ProductId,
};

use crate::host::demo_mode;

/// Phase label for status envelopes.
pub const PHASE_LABEL: &str = "phase2_shell";

/// Active tier ceiling for this milestone (T0 only).
pub const TIER_CEILING: CapabilityTier = CapabilityTier::T0;

/// Baseline (no live probe) status for a world on the current OS.
pub fn world_baseline(product: ProductId, os: OsFamily) -> ModuleStatus {
    let demo = demo_mode();
    match product {
        ProductId::Cyberwall => wall_baseline(os, demo),
        ProductId::CyberDns => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            if demo {
                "DEMO: DoH resolve + local blocklist"
            } else {
                "partial: DoH resolve + file blocklist; local proxy serve not production"
            },
        ),
        ProductId::CyberDefender => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            "partial: SHA-256 scan scaffold; no YARA/RT shield product",
        ),
        ProductId::CyberEdr => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else if matches!(os, OsFamily::Windows) {
                HealthState::Partial
            } else {
                HealthState::NotImplemented
            },
            os,
            CapabilityTier::T1,
            if matches!(os, OsFamily::Windows) {
                "partial: IP Helper TCP table; no ETW/eBPF"
            } else {
                "not implemented on this OS yet (Phase 2)"
            },
        ),
        ProductId::CyberLog => ModuleStatus::new(
            product,
            HealthState::Partial,
            os,
            CapabilityTier::T0,
            "partial: local JSONL store reader; no collectors/correlation",
        ),
        ProductId::ThreatGrid => stub(product, os, demo, "not implemented (Phase 2); IOC store planned"),
        ProductId::CyberId => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else if matches!(os, OsFamily::Windows) {
                HealthState::Partial
            } else {
                HealthState::NotImplemented
            },
            os,
            CapabilityTier::T0,
            if matches!(os, OsFamily::Windows) {
                "partial: posture from firewall/Defender signals only"
            } else {
                "not implemented on this OS yet"
            },
        ),
        ProductId::CyberMesh => stub(product, os, demo, "not implemented (Phase 3); orchestrate WireGuard later"),
        ProductId::Gate => stub(product, os, demo, "not implemented (Phase 3); ZT app access later"),
        ProductId::Aegis => ModuleStatus::new(
            product,
            HealthState::Implemented,
            os,
            CapabilityTier::T0,
            format!("suite kernel {PHASE_LABEL}; tier ceiling {}", TIER_CEILING.as_str()),
        ),
    }
}

fn stub(product: ProductId, os: OsFamily, demo: bool, detail: &str) -> ModuleStatus {
    ModuleStatus::new(
        product,
        if demo {
            HealthState::Demo
        } else {
            HealthState::NotImplemented
        },
        os,
        CapabilityTier::T0,
        detail,
    )
}

fn wall_baseline(os: OsFamily, demo: bool) -> ModuleStatus {
    // Live probe overwrites this on Windows/Linux in status collector.
    let (state, detail, backend) = match os {
        OsFamily::Windows => (
            HealthState::Implemented,
            "Windows Firewall COM (INetFwPolicy2); live probe follows".to_string(),
            Some("win32_com_inetfwpolicy2".to_string()),
        ),
        OsFamily::Linux => (
            HealthState::Partial,
            "Linux nftables/firewalld partial backend; live probe follows".to_string(),
            Some("linux_nft_firewalld".to_string()),
        ),
        OsFamily::Macos => (
            HealthState::Partial,
            "macOS Application Firewall status only (socketfilterfw); no full policy control yet"
                .to_string(),
            Some("macos_socketfilterfw".to_string()),
        ),
        OsFamily::Freebsd => (
            HealthState::UnsupportedOnOs,
            "FreeBSD pf backend not in Phase 1".to_string(),
            None,
        ),
        OsFamily::Unknown => (
            HealthState::UnsupportedOnOs,
            "unknown OS — no Cyberwall backend".to_string(),
            None,
        ),
    };

    let state = if demo && !matches!(state, HealthState::Implemented | HealthState::Partial) {
        HealthState::Demo
    } else {
        state
    };

    let mut m = ModuleStatus::new(ProductId::Cyberwall, state, os, CapabilityTier::T0, detail);
    if let Some(b) = backend {
        m = m.with_backend(b);
    }
    m
}
