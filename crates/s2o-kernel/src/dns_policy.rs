//! DNS policy fragment — file blocklist shared with cyberdns CLI.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use s2o_schema::{
    AegisEvent, DnsPolicyIntent, EventAction, EventKind, Ioc, ProductId, Severity,
};
use s2o_store::EventStore;

use crate::host::host_id;
use crate::policy::{KernelError, KernelResult};

fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn load_blocklist(path: &Path) -> std::io::Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    if !path.exists() {
        return Ok(set);
    }
    let file = fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        set.insert(normalize_domain(line));
    }
    Ok(set)
}

fn save_blocklist(path: &Path, set: &BTreeSet<String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "# S2O CyberDNS local blocklist (kernel policy)")?;
    for d in set {
        writeln!(file, "{d}")?;
    }
    Ok(())
}

/// Apply DNS policy fragment; returns human-readable applied lines.
pub fn apply_dns_intent(
    intent: &DnsPolicyIntent,
    store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    let path = PathBuf::from(
        intent
            .blocklist_path
            .as_deref()
            .unwrap_or(".aegis/dns-blocklist.txt"),
    );
    let mut set = load_blocklist(&path).map_err(KernelError::Io)?;
    let mut applied = Vec::new();

    for d in &intent.block_domains {
        let d = normalize_domain(d);
        if d.is_empty() {
            continue;
        }
        if set.insert(d.clone()) {
            applied.push(format!("dns.block={d}"));
            if let Some(store) = store {
                let ev = AegisEvent::new(
                    host_id(),
                    ProductId::CyberDns,
                    EventKind::Dns,
                    EventAction::Blocked,
                    Severity::Medium,
                    format!("policy block domain: {d}"),
                )
                .with_attr("domain", serde_json::json!(d))
                .with_attr("source", serde_json::json!("policy"))
                .with_ioc(Ioc::Domain(d));
                store.append(&ev)?;
            }
        }
    }

    for d in &intent.unblock_domains {
        let d = normalize_domain(d);
        if set.remove(&d) {
            applied.push(format!("dns.unblock={d}"));
            if let Some(store) = store {
                let ev = AegisEvent::new(
                    host_id(),
                    ProductId::CyberDns,
                    EventKind::Dns,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("policy unblock domain: {d}"),
                )
                .with_attr("domain", serde_json::json!(d))
                .with_attr("source", serde_json::json!("policy"));
                store.append(&ev)?;
            }
        }
    }

    if !applied.is_empty() || !intent.block_domains.is_empty() || !intent.unblock_domains.is_empty()
    {
        save_blocklist(&path, &set).map_err(KernelError::Io)?;
        applied.push(format!("dns.blocklist_path={}", path.display()));
        applied.push(format!("dns.blocklist_count={}", set.len()));
    }

    Ok(applied)
}
