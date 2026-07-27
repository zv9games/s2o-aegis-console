//! Lightweight posture check for policy gate (kernel-side).

use std::path::Path;

use s2o_schema::{
    AegisEvent, EventAction, EventKind, PosturePolicyIntent, ProductId, Severity,
};
use s2o_store::EventStore;

use crate::host::host_id;
use crate::platform::FirewallEngineHandle;
use crate::policy::{KernelError, KernelResult};
use cyberwall_core::FirewallEngine;

pub async fn apply_posture_intent(
    intent: &PosturePolicyIntent,
    fw: &FirewallEngineHandle,
    store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    let min = intent.min_score.unwrap_or(0);
    let st = FirewallEngine::get_status(fw.as_ref())
        .await
        .map_err(|e| KernelError::Engine(e.to_string()))?;

    let mut score = 0u32;
    if st.enabled {
        score += 30;
    }
    if st.defender_active || !cfg!(windows) {
        score += 25;
    }
    if Path::new(".aegis/ioc-store.json").exists() {
        score += 15;
    }
    if Path::new(".aegis/dns-blocklist.txt").exists() {
        score += 15;
    }
    // disk encryption not re-probed here (cyberid does deeper); give partial credit if files present
    if Path::new(".aegis").exists() {
        score += 15;
    }

    let pass = score >= min;
    let mut applied = vec![format!("posture.score={score}"), format!("posture.min={min}")];
    if pass {
        applied.push("posture.gate=allow".into());
    } else {
        applied.push("posture.gate=deny".into());
    }

    if let Some(store) = store {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::CyberId,
            EventKind::Auth,
            if pass {
                EventAction::Allowed
            } else {
                EventAction::Blocked
            },
            if pass {
                Severity::Info
            } else {
                Severity::High
            },
            format!("policy posture score={score} min={min} pass={pass}"),
        )
        .with_attr("score", serde_json::json!(score))
        .with_attr("min_score", serde_json::json!(min))
        .with_attr("pass", serde_json::json!(pass));
        store.append(&ev)?;
    }

    if !pass {
        return Err(KernelError::Policy(format!(
            "posture gate failed: score={score} < min={min}"
        )));
    }

    Ok(applied)
}
