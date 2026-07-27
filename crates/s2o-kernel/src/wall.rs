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

/// Convenience: open default event log if present/parent creatable.
pub fn open_default_store(path: impl AsRef<std::path::Path>) -> KernelResult<Arc<EventStore>> {
    Ok(Arc::new(EventStore::open(path)?))
}
