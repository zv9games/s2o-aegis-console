//! Firewall enforcement for the `ChangeFirewall` policy class.
//!
//! Safety properties:
//! - Only rules whose name starts with [`PREFIX`] are ever listed for
//!   deletion, deleted or added. Foreign rules are never touched.
//! - Bundles are declarative: the body is the complete desired set of Aegis
//!   rules. Before applying, the previously confirmed set is kept as the
//!   snapshot.
//! - After applying, the change must be confirmed by a successful server
//!   heartbeat within `confirm_secs` (default 300). Otherwise the snapshot is
//!   restored automatically and a `rolled_back` result is reported. A change
//!   that locks the agent out of the fleet server therefore undoes itself.

use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "S2O-Aegis-";
pub const DEFAULT_CONFIRM_SECS: i64 = 300;
const MAX_RULES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

/// One Aegis-owned rule. `name` is the suffix; the OS name is `PREFIX+name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FwRule {
    pub name: String,
    pub direction: Direction,
    pub action: Action,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub local_ports: Option<String>,
    #[serde(default)]
    pub remote_ports: Option<String>,
    #[serde(default)]
    pub remote_addresses: Option<String>,
}

impl FwRule {
    pub fn os_name(&self) -> String {
        format!("{PREFIX}{}", self.name)
    }

    /// Strict allow-lists: these values end up as `netsh` arguments.
    pub fn validate(&self) -> Result<(), String> {
        let ok_name = !self.name.is_empty()
            && self.name.len() <= 64
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if !ok_name {
            return Err(format!("invalid rule name {:?}", self.name));
        }
        let ports = |v: &Option<String>, what: &str| match v {
            Some(p)
                if p.is_empty()
                    || p.len() > 128
                    || !p.chars().all(|c| c.is_ascii_digit() || ",-".contains(c)) =>
            {
                Err(format!("invalid {what} {p:?}"))
            }
            _ => Ok(()),
        };
        ports(&self.local_ports, "local_ports")?;
        ports(&self.remote_ports, "remote_ports")?;
        if (self.local_ports.is_some() || self.remote_ports.is_some())
            && !matches!(self.protocol, Some(Protocol::Tcp | Protocol::Udp))
        {
            return Err("ports require protocol tcp or udp".into());
        }
        if let Some(a) = &self.remote_addresses {
            if a.is_empty()
                || a.len() > 512
                || !a
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || ".:/,-".contains(c))
            {
                return Err(format!("invalid remote_addresses {a:?}"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallBody {
    pub rules: Vec<FwRule>,
    #[serde(default)]
    pub confirm_secs: Option<i64>,
}

impl FirewallBody {
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() > MAX_RULES {
            return Err(format!("too many rules (max {MAX_RULES})"));
        }
        let mut names = std::collections::BTreeSet::new();
        for r in &self.rules {
            r.validate()?;
            if !names.insert(&r.name) {
                return Err(format!("duplicate rule name {}", r.name));
            }
        }
        if let Some(s) = self.confirm_secs {
            if !(30..=3600).contains(&s) {
                return Err("confirm_secs must be 30..=3600".into());
            }
        }
        Ok(())
    }
}

/// OS firewall operations used by the enforcer. Implementations must be
/// blocking-safe (they are called from the agent loop).
pub trait AegisFirewall: Send + Sync {
    /// Names of ALL rules currently present (the enforcer filters by prefix).
    fn list_names(&self) -> Result<Vec<String>, String>;
    fn add(&self, rule: &FwRule) -> Result<(), String>;
    fn delete(&self, os_name: &str) -> Result<(), String>;
}

/// Pending (unconfirmed) firewall change, persisted in agent state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FwPending {
    pub version: u64,
    pub deadline: i64,
    pub applied_at: i64,
    pub snapshot: Vec<FwRule>,
    pub new_rules: Vec<FwRule>,
}

/// Replace the Aegis-owned rule set with `rules`. Touches only `PREFIX` rules.
pub fn replace_owned(fw: &dyn AegisFirewall, rules: &[FwRule]) -> Result<(), String> {
    for r in rules {
        r.validate()?;
    }
    for name in fw.list_names()? {
        if name.starts_with(PREFIX) {
            fw.delete(&name)?;
        }
    }
    for r in rules {
        fw.add(r)?;
    }
    Ok(())
}

#[cfg(windows)]
pub mod windows {
    //! Windows adapter over the existing cyberwall/s2o-platform firewall APIs
    //! (netsh advfirewall under the hood).
    use super::*;
    use cyberwall_core::{
        FirewallEngine, FirewallRule, ProfileType, RuleAction, RuleDirection, RuleProtocol,
    };

    pub struct WindowsAegisFirewall;

    fn run<F: std::future::Future<Output = T> + Send, T: Send>(f: F) -> T {
        // Own runtime on a scoped thread: safe to call from inside tokio.
        std::thread::scope(|s| {
            s.spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime")
                    .block_on(f)
            })
            .join()
            .expect("firewall thread")
        })
    }

    impl AegisFirewall for WindowsAegisFirewall {
        fn list_names(&self) -> Result<Vec<String>, String> {
            s2o_platform::firewall::get_rules()
                .map(|v| v.into_iter().map(|r| r.name).collect())
                .map_err(|e| format!("list rules: {e:?}"))
        }

        fn add(&self, r: &FwRule) -> Result<(), String> {
            r.validate()?;
            let rule = FirewallRule {
                name: r.os_name(),
                enabled: true,
                action: match r.action {
                    Action::Allow => RuleAction::Allow,
                    Action::Block => RuleAction::Block,
                },
                direction: match r.direction {
                    Direction::In => RuleDirection::Inbound,
                    Direction::Out => RuleDirection::Outbound,
                },
                profile: ProfileType::All,
                protocol: r.protocol.map(|p| match p {
                    Protocol::Tcp => RuleProtocol::Tcp,
                    Protocol::Udp => RuleProtocol::Udp,
                    Protocol::Any => RuleProtocol::Any,
                }),
                local_ports: r.local_ports.clone(),
                remote_ports: r.remote_ports.clone(),
                remote_addresses: r.remote_addresses.clone(),
                application: None,
            };
            let eng = cyberwall_backend_windows::WindowsFirewallEngine::new();
            run(async move { eng.add_rule(&rule).await }).map_err(|e| e.to_string())
        }

        fn delete(&self, os_name: &str) -> Result<(), String> {
            if !os_name.starts_with(PREFIX) {
                return Err(format!("refusing to delete non-Aegis rule {os_name:?}"));
            }
            s2o_platform::firewall::remove_firewall_rule_by_name(os_name).map_err(|e| e.to_string())
        }
    }
}
