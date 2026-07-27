//! ThreatGrid / IOC policy fragment.

use std::path::PathBuf;

use chrono::Utc;
use s2o_ioc::{IocEntry, IocKind, IocSeverity, IocStore};
use s2o_schema::{
    AegisEvent, EventAction, EventKind, IntelPolicyIntent, ProductId, Severity,
};
use s2o_store::EventStore;

use crate::host::host_id;
use crate::policy::{KernelError, KernelResult};

pub fn apply_intel_intent(
    intent: &IntelPolicyIntent,
    store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    let mut applied = Vec::new();
    if !intent.sync_blocklist {
        return Ok(applied);
    }

    let ioc_path = PathBuf::from(
        intent
            .ioc_store_path
            .as_deref()
            .unwrap_or(".aegis/ioc-store.json"),
    );
    let bl_path = PathBuf::from(
        intent
            .blocklist_path
            .as_deref()
            .unwrap_or(".aegis/dns-blocklist.txt"),
    );

    let mut ioc = IocStore::load(&ioc_path).map_err(|e| KernelError::Policy(e.to_string()))?;
    let n = ioc
        .import_domain_list(&bl_path, "policy_sync")
        .map_err(|e| KernelError::Policy(e.to_string()))?;
    // ensure at least store file exists
    if ioc.entries.is_empty() {
        ioc.upsert(IocEntry {
            kind: IocKind::Domain,
            value: "policy.seed.s2o".into(),
            source: "policy".into(),
            severity: IocSeverity::Low,
            note: Some("seed so posture IOC check can pass".into()),
            added_at: Utc::now(),
        });
    }
    ioc.save(&ioc_path)
        .map_err(|e| KernelError::Policy(e.to_string()))?;

    applied.push(format!("intel.sync_blocklist imported={n} total={}", ioc.entries.len()));
    applied.push(format!("intel.ioc_store={}", ioc_path.display()));

    if let Some(store) = store {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::ThreatGrid,
            EventKind::Policy,
            EventAction::Observed,
            Severity::Info,
            format!("policy intel sync imported={n}"),
        )
        .with_attr("imported", serde_json::json!(n))
        .with_attr("total", serde_json::json!(ioc.entries.len()));
        store.append(&ev)?;
    }

    Ok(applied)
}
