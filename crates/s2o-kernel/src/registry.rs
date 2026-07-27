//! Static world registry — the nine rooms marked on the slab.

use s2o_schema::{
    CapabilityTier, HealthState, ModuleStatus, OsFamily, ProductId,
};

use crate::host::demo_mode;

/// Phase label for status envelopes.
pub const PHASE_LABEL: &str = "phase3_access";

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
                "DEMO: DoH + blocklist + UDP proxy"
            } else {
                "partial: DoH + allowlist/blocklist + IOC + UDP proxy + system-dns; no DoT/redirector"
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
            "partial: SHA-256 + IOC + yara-lite + YARA-X lab rules + Defender probe; no minifilter/cloud feed",
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
                "partial: TCP + listen inventory + process/baseline/drift + heuristics; no ETW/eBPF"
            } else {
                "partial: process inventory/baseline (ps); TCP needs Windows net_lib"
            },
        ),
        ProductId::CyberLog => ModuleStatus::new(
            product,
            HealthState::Partial,
            os,
            CapabilityTier::T0,
            "partial: JSONL read/export/filter/stats/correlate + UDP syslog collect; no remote EPS",
        ),
        ProductId::ThreatGrid => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            "partial: local IOC + capped multi-feed online sync (URLHaus/OpenPhish); no commercial TIP/ML",
        ),
        ProductId::CyberId => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            "partial: posture + local session tokens; no OIDC/FIDO2/PAM",
        ),
        ProductId::CyberMesh => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            "partial: X25519 keys + conf/peers + doctor + wg show/wg-quick; no boringtun embed",
        ),
        ProductId::Gate => ModuleStatus::new(
            product,
            if demo {
                HealthState::Demo
            } else {
                HealthState::Partial
            },
            os,
            CapabilityTier::T0,
            "partial: posture+session+mTLS+JWT/JWKS/OIDC+OAuth device+auth-code lab; no prod IdP UI",
        ),
        ProductId::Aegis => ModuleStatus::new(
            product,
            HealthState::Implemented,
            os,
            CapabilityTier::T0,
            format!("suite kernel {PHASE_LABEL}; tier ceiling {}", TIER_CEILING.as_str()),
        ),
    }
}

#[allow(dead_code)]
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
            "Windows Firewall COM + netsh managed rules (S2O-Aegis-*); live probe follows".to_string(),
            Some("win32_com_inetfwpolicy2_netsh".to_string()),
        ),
        OsFamily::Linux => (
            HealthState::Partial,
            "Linux firewalld/nft managed rules (s2o_aegis / rich-rule state); live probe follows"
                .to_string(),
            Some("linux_firewalld_nft_managed".to_string()),
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
