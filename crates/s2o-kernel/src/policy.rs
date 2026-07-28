//! Policy document load + route (v0: multi-fragment).

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

/// Rebase lab pack paths that start with `.aegis/` (or `.aegis\`) onto `data_dir`.
///
/// Absolute paths and other relative paths are left unchanged. Returns count of paths rewritten.
pub fn rebase_policy_paths(doc: &mut PolicyDocument, data_dir: &Path) -> u32 {
    rebase_policy_paths_report(doc, data_dir).len() as u32
}

/// Like [`rebase_policy_paths`] but returns rewritten path pairs `(before, after)` for diagnostics.
pub fn rebase_policy_paths_report(
    doc: &mut PolicyDocument,
    data_dir: &Path,
) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut one = |opt: &mut Option<String>| {
        if let Some(p) = opt.as_mut() {
            if let Some(rest) = strip_aegis_prefix(p) {
                let before = p.clone();
                let after = if rest.is_empty() {
                    data_dir.display().to_string()
                } else {
                    data_dir.join(rest).display().to_string()
                };
                *p = after.clone();
                pairs.push((before, after));
            }
        }
    };
    if let Some(dns) = doc.dns.as_mut() {
        one(&mut dns.blocklist_path);
        one(&mut dns.allowlist_path);
    }
    if let Some(intel) = doc.intel.as_mut() {
        one(&mut intel.blocklist_path);
        one(&mut intel.ioc_store_path);
    }
    if let Some(gate) = doc.gate.as_mut() {
        one(&mut gate.config_path);
    }
    if let Some(mesh) = doc.mesh.as_mut() {
        one(&mut mesh.peers_file);
    }
    pairs
}

fn strip_aegis_prefix(path: &str) -> Option<String> {
    let p = path.trim().replace('\\', "/");
    for pref in [".aegis/", "./.aegis/"] {
        if let Some(rest) = p.strip_prefix(pref) {
            return Some(rest.to_string());
        }
    }
    if p == ".aegis" || p == "./.aegis" {
        return Some(String::new());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use s2o_schema::{
        DnsPolicyIntent, GatePolicyIntent, MeshPeerIntent, MeshPolicyIntent, POLICY_SCHEMA_VERSION,
    };

    #[test]
    fn rebase_suite_style_paths() {
        let mut doc = PolicyDocument {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            name: "t".into(),
            description: None,
            firewall: None,
            dns: Some(DnsPolicyIntent {
                blocklist_path: Some(".aegis/dns-blocklist.txt".into()),
                allowlist_path: Some(r".aegis\dns-allowlist.txt".into()),
                block_domains: vec![],
                unblock_domains: vec![],
                allow_domains: vec![],
                unallow_domains: vec![],
            }),
            intel: None,
            posture: None,
            gate: Some(GatePolicyIntent {
                min_score: Some(50),
                require_session: None,
                rate_limit_per_minute: None,
                allow_ips: vec![],
                config_path: Some(".aegis/gate-routes.json".into()),
            }),
            mesh: Some(MeshPolicyIntent {
                peers_file: Some(".aegis/mesh-peers.json".into()),
                replace: false,
                peers: vec![MeshPeerIntent {
                    name: "h".into(),
                    public_key: "k".into(),
                    endpoint: None,
                    allowed_ips: "10.0.0.0/8".into(),
                    keepalive: 25,
                    notes: None,
                }],
            }),
        };
        let base = PathBuf::from("custom-data");
        let n = rebase_policy_paths(&mut doc, &base);
        assert_eq!(n, 4);
        let bl = doc.dns.as_ref().unwrap().blocklist_path.as_ref().unwrap();
        assert_eq!(bl, &base.join("dns-blocklist.txt").display().to_string());
        let al = doc.dns.as_ref().unwrap().allowlist_path.as_ref().unwrap();
        assert_eq!(al, &base.join("dns-allowlist.txt").display().to_string());
        let gate = doc.gate.as_ref().unwrap().config_path.as_ref().unwrap();
        assert_eq!(gate, &base.join("gate-routes.json").display().to_string());
        let mesh = doc.mesh.as_ref().unwrap().peers_file.as_ref().unwrap();
        assert_eq!(mesh, &base.join("mesh-peers.json").display().to_string());
        // absolute / non-.aegis paths unchanged
        if let Some(dns) = doc.dns.as_mut() {
            dns.blocklist_path = Some("/abs/block.txt".into());
        }
        let n2 = rebase_policy_paths(&mut doc, Path::new("other"));
        assert_eq!(n2, 0);
        assert_eq!(
            doc.dns.as_ref().unwrap().blocklist_path.as_deref(),
            Some("/abs/block.txt")
        );
    }
}

/// Apply policy through the kernel (uses [`crate::default_data_dir`] for posture signals).
pub async fn apply_policy(
    doc: &PolicyDocument,
    fw: &FirewallEngineHandle,
    store: Option<Arc<EventStore>>,
) -> KernelResult<PolicyApplyResult> {
    apply_policy_at(doc, fw, store, None).await
}

/// Apply policy; when `data_dir` is set, posture suite signals resolve under that root.
pub async fn apply_policy_at(
    doc: &PolicyDocument,
    fw: &FirewallEngineHandle,
    store: Option<Arc<EventStore>>,
    data_dir: Option<&Path>,
) -> KernelResult<PolicyApplyResult> {
    use crate::wall::{wall_set_enabled, wall_set_outbound_block};

    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();
    let store_ref = store.as_ref().map(|s| s.as_ref());
    let default_dd = crate::default_data_dir();
    let posture_dd = data_dir.unwrap_or(default_dd.as_path());

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
        if !fw_intent.rules.is_empty() {
            match crate::wall::wall_apply_rules(fw, &fw_intent.rules, store_ref).await {
                Ok(n) => applied.push(format!("firewall.rules={n}")),
                Err(e) => errors.push(format!("firewall.rules: {e}")),
            }
        }
        if fw_intent.enabled.is_none()
            && fw_intent.outbound_block.is_none()
            && fw_intent.rules.is_empty()
        {
            skipped.push("firewall: empty intent".into());
        }
    } else {
        skipped.push("firewall: no fragment".into());
    }

    if let Some(dns_intent) = &doc.dns {
        match crate::dns_policy::apply_dns_intent(dns_intent, store_ref) {
            Ok(lines) if !lines.is_empty() => applied.extend(lines),
            Ok(_) => skipped.push("dns: empty fragment".into()),
            Err(e) => errors.push(format!("dns: {e}")),
        }
    } else {
        skipped.push("dns: no fragment".into());
    }

    if let Some(intel_intent) = &doc.intel {
        match crate::intel_policy::apply_intel_intent(intel_intent, store_ref) {
            Ok(lines) if !lines.is_empty() => applied.extend(lines),
            Ok(_) => skipped.push("intel: empty fragment".into()),
            Err(e) => errors.push(format!("intel: {e}")),
        }
    } else {
        skipped.push("intel: no fragment".into());
    }

    if let Some(posture_intent) = &doc.posture {
        match crate::posture_policy::apply_posture_intent_at(
            posture_intent,
            fw,
            store_ref,
            posture_dd,
        )
        .await
        {
            Ok(lines) => applied.extend(lines),
            Err(e) => errors.push(format!("posture: {e}")),
        }
    } else {
        skipped.push("posture: no fragment".into());
    }

    if let Some(gate_intent) = &doc.gate {
        match crate::gate_policy::apply_gate_intent(gate_intent, store_ref) {
            Ok(lines) if !lines.is_empty() => applied.extend(lines),
            Ok(_) => skipped.push("gate: empty fragment".into()),
            Err(e) => errors.push(format!("gate: {e}")),
        }
    } else {
        skipped.push("gate: no fragment".into());
    }

    if let Some(mesh_intent) = &doc.mesh {
        match crate::mesh_policy::apply_mesh_intent(mesh_intent, store_ref) {
            Ok(lines) if !lines.is_empty() => applied.extend(lines),
            Ok(_) => skipped.push("mesh: empty fragment".into()),
            Err(e) => errors.push(format!("mesh: {e}")),
        }
    } else {
        skipped.push("mesh: no fragment".into());
    }

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
