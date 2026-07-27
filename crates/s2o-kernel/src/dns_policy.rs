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

fn save_domain_list(path: &Path, set: &BTreeSet<String>, header: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "{header}")?;
    for d in set {
        writeln!(file, "{d}")?;
    }
    Ok(())
}

fn save_blocklist(path: &Path, set: &BTreeSet<String>) -> std::io::Result<()> {
    save_domain_list(path, set, "# S2O CyberDNS local blocklist (kernel policy)")
}

fn save_allowlist(path: &Path, set: &BTreeSet<String>) -> std::io::Result<()> {
    save_domain_list(path, set, "# S2O CyberDNS local allowlist (kernel policy)")
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

    // Allowlist (overrides block + IOC in cyberdns resolve/serve)
    let allow_path = PathBuf::from(
        intent
            .allowlist_path
            .as_deref()
            .unwrap_or(".aegis/dns-allowlist.txt"),
    );
    let mut allow = load_blocklist(&allow_path).map_err(KernelError::Io)?;
    let mut allow_changed = false;
    for d in &intent.allow_domains {
        let d = normalize_domain(d);
        if d.is_empty() {
            continue;
        }
        if allow.insert(d.clone()) {
            allow_changed = true;
            applied.push(format!("dns.allow={d}"));
            if let Some(store) = store {
                let ev = AegisEvent::new(
                    host_id(),
                    ProductId::CyberDns,
                    EventKind::Dns,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("policy allow domain: {d}"),
                )
                .with_attr("domain", serde_json::json!(d))
                .with_attr("source", serde_json::json!("policy"));
                store.append(&ev)?;
            }
        }
    }
    for d in &intent.unallow_domains {
        let d = normalize_domain(d);
        if allow.remove(&d) {
            allow_changed = true;
            applied.push(format!("dns.unallow={d}"));
        }
    }
    if allow_changed
        || !intent.allow_domains.is_empty()
        || !intent.unallow_domains.is_empty()
        || intent.allowlist_path.is_some()
    {
        save_allowlist(&allow_path, &allow).map_err(KernelError::Io)?;
        applied.push(format!("dns.allowlist_path={}", allow_path.display()));
        applied.push(format!("dns.allowlist_count={}", allow.len()));
    }

    Ok(applied)
}
