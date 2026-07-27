//! S2O Aegis shared schema — the suite data package contract.
//!
//! Every product engine should emit [`AegisEvent`] values rather than inventing
//! ad-hoc log lines. Version the schema carefully; consumers (CyberLog, ThreatGrid,
//! Console) depend on stability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "0.1.0";
pub const POLICY_SCHEMA_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Identity & platform
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductId {
    Cyberwall,
    CyberMesh,
    CyberDefender,
    CyberEdr,
    CyberLog,
    ThreatGrid,
    CyberDns,
    CyberId,
    Gate,
    Aegis,
}

impl ProductId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cyberwall => "cyberwall",
            Self::CyberMesh => "cybermesh",
            Self::CyberDefender => "cyberdefender",
            Self::CyberEdr => "cyberedr",
            Self::CyberLog => "cybersiem",
            Self::ThreatGrid => "cyberintel",
            Self::CyberDns => "cyberdns",
            Self::CyberId => "cyberid",
            Self::Gate => "cyberztna",
            Self::Aegis => "aegis",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Cyberwall => "S2O Cyberwall",
            Self::CyberMesh => "S2O CyberMesh",
            Self::CyberDefender => "S2O CyberDefender",
            Self::CyberEdr => "S2O CyberEDR",
            Self::CyberLog => "S2O CyberLog",
            Self::ThreatGrid => "S2O ThreatGrid",
            Self::CyberDns => "S2O CyberDNS",
            Self::CyberId => "S2O CyberID",
            Self::Gate => "S2O Gate",
            Self::Aegis => "S2O Aegis Kernel",
        }
    }

    /// The nine product worlds (excludes the suite kernel itself).
    pub fn worlds() -> &'static [ProductId] {
        &[
            Self::Cyberwall,
            Self::CyberMesh,
            Self::CyberDefender,
            Self::CyberEdr,
            Self::CyberLog,
            Self::ThreatGrid,
            Self::CyberDns,
            Self::CyberId,
            Self::Gate,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Linux,
    Macos,
    Freebsd,
    Unknown,
}

impl OsFamily {
    pub fn detect() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "freebsd") {
            Self::Freebsd
        } else {
            Self::Unknown
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Freebsd => "freebsd",
            Self::Unknown => "unknown",
        }
    }
}

/// Capability depth ceiling (not a per-world ladder inside a phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTier {
    /// Portable userspace (OS policy APIs, CLIs, JSON store).
    T0,
    /// Hardened host (services, ETW/auditd, installers).
    T1,
    /// Kernel / advanced network (drivers, divert product).
    T2,
}

impl CapabilityTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::T0 => "t0",
            Self::T1 => "t1",
            Self::T2 => "t2",
        }
    }
}

// ---------------------------------------------------------------------------
// Honesty / health matrix
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Real OS effect for claimed commands.
    Implemented,
    /// Some commands real; others not.
    Partial,
    /// Slot exists; no real engine yet.
    NotImplemented,
    /// Will not ship on this OS (by design or platform limit).
    UnsupportedOnOs,
    /// Implemented but failing (perms, missing tool).
    Degraded,
    /// Only when AEGIS_DEMO=1 — never default.
    Demo,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Partial => "partial",
            Self::NotImplemented => "not_implemented",
            Self::UnsupportedOnOs => "unsupported_on_os",
            Self::Degraded => "degraded",
            Self::Demo => "demo",
        }
    }
}

/// Per-world (or kernel) status row for the front-door matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub id: String,
    pub name: String,
    pub product: ProductId,
    pub state: HealthState,
    pub os: OsFamily,
    pub tier_ceiling: CapabilityTier,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

impl ModuleStatus {
    pub fn new(
        product: ProductId,
        state: HealthState,
        os: OsFamily,
        tier_ceiling: CapabilityTier,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            id: product.as_str().to_string(),
            name: product.display_name().to_string(),
            product,
            state,
            os,
            tier_ceiling,
            detail: detail.as_ref().to_string(),
            backend: None,
        }
    }

    pub fn with_backend(mut self, backend: impl AsRef<str>) -> Self {
        self.backend = Some(backend.as_ref().to_string());
        self
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Process,
    File,
    NetFlow,
    Dns,
    Auth,
    Policy,
    Alert,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Observed,
    Blocked,
    Quarantined,
    Allowed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ioc {
    Ip(String),
    Domain(String),
    Hash(String),
    Url(String),
}

/// Canonical security event for the Aegis data package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisEvent {
    pub schema_version: String,
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub host_id: String,
    pub product: ProductId,
    pub severity: Severity,
    pub kind: EventKind,
    pub action: EventAction,
    pub message: String,
    #[serde(default)]
    pub attrs: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub iocs: Vec<Ioc>,
}

impl AegisEvent {
    pub fn new(
        host_id: impl Into<String>,
        product: ProductId,
        kind: EventKind,
        action: EventAction,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            id: Uuid::new_v4(),
            ts: Utc::now(),
            host_id: host_id.into(),
            product,
            severity,
            kind,
            action,
            message: message.into(),
            attrs: serde_json::Map::new(),
            iocs: Vec::new(),
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }

    pub fn with_ioc(mut self, ioc: Ioc) -> Self {
        self.iocs.push(ioc);
        self
    }
}

// ---------------------------------------------------------------------------
// Policy document v0 (kernel-routed intents)
// ---------------------------------------------------------------------------

/// Portable policy pack — kernel validates and routes fragments to worlds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub schema_version: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub firewall: Option<FirewallPolicyIntent>,
}

impl PolicyDocument {
    pub fn example_wall_enable() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            name: "example-wall-enable".into(),
            description: Some("Enable host firewall on interactive profiles".into()),
            firewall: Some(FirewallPolicyIntent {
                enabled: Some(true),
                outbound_block: Some(false),
            }),
        }
    }
}

/// Firewall intents the Cyberwall engine can apply at T0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicyIntent {
    /// Enable/disable OS firewall (where the backend supports it).
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Outbound isolation / airplane-style block.
    #[serde(default)]
    pub outbound_block: Option<bool>,
}

/// Result of applying one policy document through the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApplyResult {
    pub policy_name: String,
    pub ok: bool,
    pub applied: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Platform status envelope (front door)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStatus {
    pub platform: String,
    pub schema_version: String,
    pub phase: String,
    pub tier_ceiling: CapabilityTier,
    pub os: OsFamily,
    pub host_id: String,
    pub demo_mode: bool,
    pub modules: Vec<ModuleStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let ev = AegisEvent::new(
            "host-1",
            ProductId::Cyberwall,
            EventKind::Policy,
            EventAction::Allowed,
            Severity::Info,
            "firewall enabled",
        )
        .with_attr("profile", serde_json::json!("private"));
        let s = serde_json::to_string(&ev).unwrap();
        let back: AegisEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.product, ProductId::Cyberwall);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn nine_worlds() {
        assert_eq!(ProductId::worlds().len(), 9);
    }

    #[test]
    fn policy_roundtrip() {
        let p = PolicyDocument::example_wall_enable();
        let s = serde_json::to_string_pretty(&p).unwrap();
        let back: PolicyDocument = serde_json::from_str(&s).unwrap();
        assert_eq!(back.firewall.unwrap().enabled, Some(true));
    }

    #[test]
    fn health_state_serde() {
        let m = ModuleStatus::new(
            ProductId::Cyberwall,
            HealthState::Implemented,
            OsFamily::Windows,
            CapabilityTier::T0,
            "ok",
        );
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("implemented"));
        assert!(s.contains("t0"));
    }
}
