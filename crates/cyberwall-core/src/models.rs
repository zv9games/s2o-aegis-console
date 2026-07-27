use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileType {
    Private,
    Public,
    Domain,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub enabled: bool,
    pub outbound_blocked: bool,
    pub defender_active: bool,
    pub profile_private: bool,
    pub profile_public: bool,
    pub profile_domain: bool,
    pub platform: String,
    pub backend_driver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub profile: ProfileType,
    pub application: Option<String>,
    /// `any` | `tcp` | `udp` | `icmp` (optional; netsh protocol)
    #[serde(default)]
    pub protocol: Option<String>,
    /// Local port or range, e.g. `445` or `8000-8010`
    #[serde(default)]
    pub local_port: Option<String>,
    /// Remote address / CIDR filter when supported
    #[serde(default)]
    pub remote_ip: Option<String>,
}

impl FirewallRule {
    pub fn simple(
        name: impl Into<String>,
        action: RuleAction,
        direction: RuleDirection,
    ) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            action,
            direction,
            profile: ProfileType::All,
            application: None,
            protocol: None,
            local_port: None,
            remote_ip: None,
        }
    }
}

/// Prefix for rules managed by S2O Aegis apply_policy (safe replace cycle).
pub const MANAGED_RULE_PREFIX: &str = "S2O-Aegis-";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

impl FirewallPolicy {
    pub fn ensure_managed_names(mut self) -> Self {
        for r in &mut self.rules {
            if !r.name.starts_with(MANAGED_RULE_PREFIX) {
                r.name = format!("{MANAGED_RULE_PREFIX}{}", r.name);
            }
        }
        self
    }
}
