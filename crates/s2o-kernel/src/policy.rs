//! Policy document load + route (v0: firewall intents only).

use std::path::Path;
use std::sync::Arc;

use s2o_schema::{
    AegisEvent, EventAction, EventKind, PolicyApplyResult, PolicyDocument, ProductId, Severity,
    POLICY_SCHEMA_VERSION,
};
use s2o_store::EventStore;
use thiserror::Error;

use crate::host::host_id;
use crate::platform::FirewallEngineHandle;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy: {0}")]
    Policy(String),
    #[error("store: {0}")]
    Store(#[from] s2o_store::StoreError),
    #[error("engine: {0}")]
    Engine(String),
}

pub type KernelResult<T> = Result<T, KernelError>;

/// Load a policy document from JSON (YAML later).
pub fn load_policy_file(path: impl AsRef<Path>) -> KernelResult<PolicyDocument> {
    let text = std::fs::read_to_string(path)?;
    let doc: PolicyDocument = serde_json::from_str(&text)?;
    if doc.schema_version != POLICY_SCHEMA_VERSION {
        // Accept only exact v0 for now; soft-warn via error if wildly wrong.
        if !doc.schema_version.starts_with('0') {
            return Err(KernelError::Policy(format!(
                "unsupported policy schema_version {} (expected {})",
                doc.schema_version, POLICY_SCHEMA_VERSION
            )));
        }
    }
    Ok(doc)
}

/// Apply policy through the kernel: firewall fragment (v0) with per-world events.
pub async fn apply_policy(
    doc: &PolicyDocument,
    fw: &FirewallEngineHandle,
    store: Option<Arc<EventStore>>,
) -> KernelResult<PolicyApplyResult> {
    use crate::wall::{wall_set_enabled, wall_set_outbound_block};

    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();
    let store_ref = store.as_ref().map(|s| s.as_ref());

    if let Some(fw_intent) = &doc.firewall {
        if let Some(enabled) = fw_intent.enabled {
            match wall_set_enabled(fw, enabled, store_ref).await {
                Ok(()) => applied.push(format!("firewall.enabled={enabled}")),
                Err(e) => errors.push(format!("firewall.enabled: {e}")),
            }
        }
        if let Some(blocked) = fw_intent.outbound_block {
            match wall_set_outbound_block(fw, blocked, store_ref).await {
                Ok(()) => applied.push(format!("firewall.outbound_block={blocked}")),
                Err(e) => errors.push(format!("firewall.outbound_block: {e}")),
            }
        }
        if fw_intent.enabled.is_none() && fw_intent.outbound_block.is_none() {
            skipped.push("firewall: empty intent".into());
        }
    } else {
        skipped.push("firewall: no fragment".into());
    }

    // DNS blocklist is CLI-driven in Phase 2; policy routing later.
    skipped.push("dns: use cyberdns block/unblock (policy DNS fragment later)".into());
    skipped.push("other worlds: not routed in policy v0".into());

    let ok = errors.is_empty() && !applied.is_empty();
    let result = PolicyApplyResult {
        policy_name: doc.name.clone(),
        ok,
        applied: applied.clone(),
        skipped,
        errors: errors.clone(),
    };

    if let Some(store) = store {
        let action = if ok {
            EventAction::Allowed
        } else if applied.is_empty() {
            EventAction::Observed
        } else {
            EventAction::Failed
        };
        let severity = if ok { Severity::Info } else { Severity::Medium };
        let ev = AegisEvent::new(
            host_id(),
            ProductId::Aegis,
            EventKind::Policy,
            action,
            severity,
            format!(
                "policy apply name={} ok={} applied={}",
                doc.name,
                ok,
                applied.join(",")
            ),
        )
        .with_attr("policy_name", serde_json::json!(doc.name))
        .with_attr("ok", serde_json::json!(ok))
        .with_attr("applied", serde_json::json!(applied))
        .with_attr("errors", serde_json::json!(errors));
        store.append(&ev)?;
    }

    Ok(result)
}
