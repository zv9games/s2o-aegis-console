//! Cyberwall operations with suite event emission.

use std::sync::Arc;

use cyberwall_core::FirewallEngine;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;

use crate::host::host_id;
use crate::platform::FirewallEngineHandle;
use crate::policy::{KernelError, KernelResult};

/// Enable/disable host firewall and emit a Cyberwall policy event.
pub async fn wall_set_enabled(
    fw: &FirewallEngineHandle,
    enabled: bool,
    store: Option<&EventStore>,
) -> KernelResult<()> {
    FirewallEngine::set_enabled(fw.as_ref(), enabled)
        .await
        .map_err(|e| KernelError::Engine(e.to_string()))?;

    if let Some(store) = store {
        let st = FirewallEngine::get_status(fw.as_ref())
            .await
            .map_err(|e| KernelError::Engine(e.to_string()))?;
        let ev = AegisEvent::new(
            host_id(),
            ProductId::Cyberwall,
            EventKind::Policy,
            if enabled {
                EventAction::Allowed
            } else {
                EventAction::Observed
            },
            Severity::Info,
            format!("firewall set_enabled={enabled} reported_enabled={}", st.enabled),
        )
        .with_attr("enabled", serde_json::json!(enabled))
        .with_attr("reported_enabled", serde_json::json!(st.enabled))
        .with_attr("backend", serde_json::json!(st.backend_driver));
        store.append(&ev)?;
    }
    Ok(())
}

/// Set outbound isolation and emit a Cyberwall policy event.
pub async fn wall_set_outbound_block(
    fw: &FirewallEngineHandle,
    blocked: bool,
    store: Option<&EventStore>,
) -> KernelResult<()> {
    FirewallEngine::set_outbound_block(fw.as_ref(), blocked)
        .await
        .map_err(|e| KernelError::Engine(e.to_string()))?;

    if let Some(store) = store {
        let st = FirewallEngine::get_status(fw.as_ref())
            .await
            .map_err(|e| KernelError::Engine(e.to_string()))?;
        let ev = AegisEvent::new(
            host_id(),
            ProductId::Cyberwall,
            EventKind::Policy,
            if blocked {
                EventAction::Blocked
            } else {
                EventAction::Allowed
            },
            if blocked {
                Severity::High
            } else {
                Severity::Info
            },
            format!(
                "firewall outbound_block={blocked} reported={}",
                st.outbound_blocked
            ),
        )
        .with_attr("outbound_block", serde_json::json!(blocked))
        .with_attr("reported_outbound_blocked", serde_json::json!(st.outbound_blocked))
        .with_attr("backend", serde_json::json!(st.backend_driver));
        store.append(&ev)?;
    }
    Ok(())
}

/// Apply declarative managed firewall rules (Windows: netsh `S2O-Aegis-*`).
pub async fn wall_apply_rules(
    fw: &FirewallEngineHandle,
    rules: &[s2o_schema::FirewallRuleIntent],
    store: Option<&EventStore>,
) -> KernelResult<usize> {
    use cyberwall_core::{
        FirewallEngine, FirewallPolicy, FirewallRule, ProfileType, RuleAction, RuleDirection,
    };

    let mut converted = Vec::with_capacity(rules.len());
    for r in rules {
        let action = match r.action.to_ascii_lowercase().as_str() {
            "allow" | "permit" => RuleAction::Allow,
            _ => RuleAction::Block,
        };
        let direction = match r.direction.to_ascii_lowercase().as_str() {
            "out" | "outbound" => RuleDirection::Outbound,
            _ => RuleDirection::Inbound,
        };
        let profile = match r
            .profile
            .as_deref()
            .unwrap_or("any")
            .to_ascii_lowercase()
            .as_str()
        {
            "private" => ProfileType::Private,
            "public" => ProfileType::Public,
            "domain" => ProfileType::Domain,
            _ => ProfileType::All,
        };
        converted.push(FirewallRule {
            name: r.name.clone(),
            enabled: r.enabled,
            action,
            direction,
            profile,
            application: r.application.clone(),
            protocol: r.protocol.clone(),
            local_port: r.local_port.clone(),
            remote_ip: r.remote_ip.clone(),
        });
    }
    let n = converted.len();
    let policy = FirewallPolicy {
        name: "suite-policy-rules".into(),
        version: "0.1".into(),
        rules: converted,
    }
    .ensure_managed_names();

    FirewallEngine::apply_policy(fw.as_ref(), &policy)
        .await
        .map_err(|e| KernelError::Engine(e.to_string()))?;

    if let Some(store) = store {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::Cyberwall,
            EventKind::Policy,
            EventAction::Allowed,
            Severity::Info,
            format!("firewall apply_policy rules={n}"),
        )
        .with_attr("rules", serde_json::json!(n))
        .with_attr("managed_prefix", serde_json::json!("S2O-Aegis-"));
        store.append(&ev)?;
    }
    Ok(n)
}

/// Convenience: open default event log if present/parent creatable.
pub fn open_default_store(path: impl AsRef<std::path::Path>) -> KernelResult<Arc<EventStore>> {
    Ok(Arc::new(EventStore::open(path)?))
}
