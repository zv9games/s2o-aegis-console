//! S2O ThreatGrid — local IOC store (Phase 2 shell).

use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::*;
use s2o_ioc::{
    default_store_path, IocEntry, IocKind, IocSeverity, IocStore, STORE_VERSION,
};
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberintel")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O ThreatGrid: local IOC store & reputation lookup", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/ioc-store.json")]
    store: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Lookup domain / IP / hash in local store
    Lookup {
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Add an IOC: kind = domain|ip|hash|url
    Add {
        kind: String,
        value: String,
        #[arg(long, default_value = "manual")]
        source: String,
        #[arg(long)]
        json: bool,
    },
    /// Import IOCs from a local file (domains one-per-line, or json array/export)
    ImportFile {
        path: PathBuf,
        /// domain|ip|hash|url (used for plain text lines; json uses entry kinds)
        #[arg(long, default_value = "domain")]
        kind: String,
        #[arg(long, default_value = "file-import")]
        source: String,
        /// Max entries to import
        #[arg(long, default_value_t = 10_000)]
        max: usize,
        /// Dry-run: report only
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Import domains from DNS blocklist + optional URL feed(s)
    Sync {
        #[arg(long, default_value = ".aegis/dns-blocklist.txt")]
        blocklist: PathBuf,
        /// Optional URL of domain list (one per line / hosts-style / URL feed)
        #[arg(long)]
        feed_url: Option<String>,
        /// Fetch default public multi-feed set (URLHaus + OpenPhish, capped each)
        #[arg(long)]
        online: bool,
        /// Max domains imported **per** online/feed URL (safety cap)
        #[arg(long, default_value_t = 2000)]
        max_import: usize,
        /// Extra feed URLs (repeatable); combined with --online / --feed-url
        #[arg(long = "feed")]
        feeds: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List IOCs (optional kind filter)
    List {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Drop IOCs older than N days and/or by source
    Prune {
        /// Remove entries older than this many days (0 = skip age prune)
        #[arg(long, default_value_t = 90)]
        older_days: i64,
        /// Also remove all entries with this source (e.g. openphish)
        #[arg(long)]
        source: Option<String>,
        /// Actually delete (default dry-run)
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Export IOC store to JSON or CSV
    Export {
        /// json | csv
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50_000)]
        limit: usize,
    },
    /// Counts by kind / source / severity
    Stats {
        /// Max source rows to print
        #[arg(long, default_value_t = 15)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Validate local IOC store health
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Remove IOC(s) by value (optional kind filter)
    Remove {
        value: String,
        /// domain|ip|hash|url — omit to match any kind
        #[arg(long)]
        kind: Option<String>,
        /// Actually delete (default dry-run)
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit(event_log: &Path, action: EventAction, severity: Severity, message: impl Into<String>, attrs: &[(&str, serde_json::Value)], ioc: Option<Ioc>) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::ThreatGrid,
            EventKind::Alert,
            action,
            severity,
            message,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, v.clone());
        }
        if let Some(i) = ioc {
            ev = ev.with_ioc(i);
        }
        let _ = store.append(&ev);
    }
}

fn parse_kind(s: &str) -> Option<IocKind> {
    match s.to_ascii_lowercase().as_str() {
        "domain" | "dns" | "host" => Some(IocKind::Domain),
        "ip" | "ipv4" | "ipv6" => Some(IocKind::Ip),
        "hash" | "sha256" | "md5" => Some(IocKind::Hash),
        "url" | "uri" => Some(IocKind::Url),
        _ => None,
    }
}

/// Convert hosts-style / URL lines into domain-per-line, capped.
fn cap_domain_feed(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut n = 0usize;
    for line in text.lines() {
        if n >= max {
            break;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // hosts: "0.0.0.0 evil.com" or plain domain or full URL
        let mut token = line
            .split_whitespace()
            .last()
            .unwrap_or(line)
            .trim()
            .to_string();
        if let Some(rest) = token.strip_prefix("http://").or_else(|| token.strip_prefix("https://"))
        {
            token = rest.split('/').next().unwrap_or(rest).to_string();
        }
        token = token.trim_end_matches('.').to_ascii_lowercase();
        if token.is_empty() || token.contains(' ') || !token.contains('.') {
            continue;
        }
        // skip pure IPs in domain import
        if token.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        out.push_str(&token);
        out.push('\n');
        n += 1;
    }
    out
}

fn guess_kind(target: &str) -> IocKind {
    let t = target.trim();
    if t.contains("://") {
        return IocKind::Url;
    }
    if t.chars().all(|c| c.is_ascii_hexdigit()) && (t.len() == 32 || t.len() == 40 || t.len() == 64)
    {
        return IocKind::Hash;
    }
    if t.parse::<std::net::IpAddr>().is_ok() {
        return IocKind::Ip;
    }
    IocKind::Domain
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { json } => {
            let store = IocStore::load(&cli.store)?;
            let domains = store.count_by_kind(IocKind::Domain);
            let ips = store.count_by_kind(IocKind::Ip);
            let hashes = store.count_by_kind(IocKind::Hash);
            let urls = store.count_by_kind(IocKind::Url);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "product": "cyberintel",
                        "store": cli.store.display().to_string(),
                        "schema_version": STORE_VERSION,
                        "total": store.entries.len(),
                        "domains": domains,
                        "ips": ips,
                        "hashes": hashes,
                        "urls": urls,
                        "updated_at": store.updated_at.to_rfc3339(),
                        "implemented": "local IOC store, lookup/add/remove/import-file/sync, prune, export, stats, doctor",
                        "not_implemented": "cloud ML scoring, commercial mega-feed, real-time TIP",
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      S2O ThreatGrid (Phase 2 shell)                     "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Store path        : {}", cli.store.display());
                println!(" Schema version    : {}", STORE_VERSION);
                println!(" Total IOCs        : {}", store.entries.len().to_string().bold());
                println!(" Domains           : {domains}");
                println!(" IPs               : {ips}");
                println!(" Hashes            : {hashes}");
                println!(" URLs              : {urls}");
                println!(
                    " Updated           : {}",
                    store.updated_at.to_rfc3339()
                );
                println!(
                    " Implemented       : {}",
                    "local IOC store, lookup/add/remove/import-file/sync, prune, export, stats, doctor"
                        .green()
                );
                println!(
                    " Not implemented   : {}",
                    "cloud ML scoring, commercial mega-feed, real-time TIP".red()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
        }
        Commands::Lookup { target, json } => {
            let store = IocStore::load(&cli.store)?;
            let hits = store.lookup(&target);
            if hits.is_empty() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "target": target,
                            "hit": false,
                            "hit_count": 0,
                            "entries": [],
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!("[threatgrid] no hit for '{target}'").green()
                    );
                }
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("ioc lookup miss: {target}"),
                    &[("target", serde_json::json!(target))],
                    None,
                );
                std::process::exit(0);
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "target": target,
                        "hit": true,
                        "hit_count": hits.len(),
                        "entries": hits,
                    }))?
                );
            } else {
                println!(
                    "{}",
                    format!("[threatgrid] {} hit(s) for '{target}'", hits.len())
                        .red()
                        .bold()
                );
                for h in &hits {
                    println!(
                        "  {:?} {} source={} severity={:?}",
                        h.kind, h.value, h.source, h.severity
                    );
                }
            }
            let ioc = match guess_kind(&target) {
                IocKind::Domain => Some(Ioc::Domain(target.clone())),
                IocKind::Ip => Some(Ioc::Ip(target.clone())),
                IocKind::Hash => Some(Ioc::Hash(target.clone())),
                IocKind::Url => Some(Ioc::Url(target.clone())),
            };
            emit(
                &cli.event_log,
                EventAction::Blocked,
                Severity::High,
                format!("ioc lookup hit: {target}"),
                &[
                    ("target", serde_json::json!(target)),
                    ("hits", serde_json::json!(hits.len())),
                ],
                ioc,
            );
            std::process::exit(3);
        }
        Commands::Add {
            kind,
            value,
            source,
            json,
        } => {
            let k = parse_kind(&kind).ok_or_else(|| format!("unknown kind '{kind}'"))?;
            let mut store = IocStore::load(&cli.store)?;
            let added = store.upsert(IocEntry {
                kind: k,
                value: value.clone(),
                source: source.clone(),
                severity: IocSeverity::High,
                note: None,
                added_at: Utc::now(),
            });
            store.save(&cli.store)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "added": added,
                        "updated": !added,
                        "kind": format!("{:?}", k).to_ascii_lowercase(),
                        "value": value,
                        "source": source,
                        "store": cli.store.display().to_string(),
                        "total": store.entries.len(),
                    }))?
                );
            } else if added {
                println!(
                    "{}",
                    format!("[threatgrid] added {:?} {value}", k).red().bold()
                );
            } else {
                println!("[threatgrid] updated existing {:?} {value}", k);
            }
            emit(
                &cli.event_log,
                EventAction::Blocked,
                Severity::Medium,
                format!("ioc added: {value}"),
                &[
                    ("kind", serde_json::json!(format!("{:?}", k))),
                    ("value", serde_json::json!(value)),
                ],
                None,
            );
        }
        Commands::ImportFile {
            path,
            kind,
            source,
            max,
            dry_run,
            json,
        } => {
            if !path.exists() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": format!("missing {}", path.display()),
                        }))?
                    );
                } else {
                    eprintln!("[threatgrid] missing {}", path.display());
                }
                std::process::exit(2);
            }
            let text = std::fs::read_to_string(&path)?;
            let default_kind =
                parse_kind(&kind).ok_or_else(|| format!("unknown kind '{kind}'"))?;
            let mut store = IocStore::load(&cli.store)?;
            let before = store.entries.len();
            let mut added = 0usize;
            let mut scanned = 0usize;

            let trimmed = text.trim_start();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                // JSON: array of IocEntry-like objects, or {entries:[...]}, or string array
                let v: serde_json::Value = serde_json::from_str(&text)?;
                let arr = if let Some(a) = v.as_array() {
                    a.clone()
                } else if let Some(a) = v.get("entries").and_then(|e| e.as_array()) {
                    a.clone()
                } else {
                    vec![v]
                };
                for item in arr {
                    if scanned >= max {
                        break;
                    }
                    scanned += 1;
                    if let Some(s) = item.as_str() {
                        if store.upsert(IocEntry {
                            kind: default_kind,
                            value: s.to_string(),
                            source: source.clone(),
                            severity: IocSeverity::High,
                            note: Some(format!("import {}", path.display())),
                            added_at: Utc::now(),
                        }) {
                            added += 1;
                        }
                        continue;
                    }
                    let k = item
                        .get("kind")
                        .and_then(|x| x.as_str())
                        .and_then(parse_kind)
                        .unwrap_or(default_kind);
                    let val = item
                        .get("value")
                        .and_then(|x| x.as_str())
                        .or_else(|| item.get("domain").and_then(|x| x.as_str()))
                        .unwrap_or("")
                        .to_string();
                    if val.trim().is_empty() {
                        continue;
                    }
                    let src = item
                        .get("source")
                        .and_then(|x| x.as_str())
                        .unwrap_or(&source)
                        .to_string();
                    if store.upsert(IocEntry {
                        kind: k,
                        value: val,
                        source: src,
                        severity: IocSeverity::High,
                        note: Some(format!("import {}", path.display())),
                        added_at: Utc::now(),
                    }) {
                        added += 1;
                    }
                }
            } else {
                for line in text.lines() {
                    if scanned >= max {
                        break;
                    }
                    let line = line.split('#').next().unwrap_or("").trim();
                    if line.is_empty() {
                        continue;
                    }
                    let domain = if line.contains(char::is_whitespace) {
                        line.split_whitespace().last().unwrap_or("").trim()
                    } else {
                        line
                    };
                    if domain.is_empty() || domain.parse::<std::net::IpAddr>().is_ok() {
                        // skip bare IPs in domain mode unless kind=ip
                        if !matches!(default_kind, IocKind::Ip) {
                            continue;
                        }
                    }
                    scanned += 1;
                    if store.upsert(IocEntry {
                        kind: default_kind,
                        value: domain.to_string(),
                        source: source.clone(),
                        severity: IocSeverity::High,
                        note: Some(format!("import {}", path.display())),
                        added_at: Utc::now(),
                    }) {
                        added += 1;
                    }
                }
            }

            if !dry_run {
                store.save(&cli.store)?;
                emit(
                    &cli.event_log,
                    EventAction::Observed,
                    Severity::Info,
                    format!("ioc import-file added={added}"),
                    &[
                        ("path", serde_json::json!(path.display().to_string())),
                        ("added", serde_json::json!(added)),
                        ("scanned", serde_json::json!(scanned)),
                    ],
                    None,
                );
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "dry_run": dry_run,
                        "path": path.display().to_string(),
                        "scanned": scanned,
                        "added": added,
                        "before": before,
                        "total_after": if dry_run { before + added } else { store.entries.len() },
                        "store": cli.store.display().to_string(),
                    }))?
                );
            } else if dry_run {
                println!(
                    "[threatgrid] import-file dry-run: scanned={scanned} new={added} store_was={before} total_after={}",
                    before + added
                );
            } else {
                println!(
                    "{}",
                    format!(
                        "[threatgrid] import-file added={added} scanned={scanned} total={} from {}",
                        store.entries.len(),
                        path.display()
                    )
                    .green()
                    .bold()
                );
            }
        }
        Commands::Sync {
            blocklist,
            feed_url,
            online,
            max_import,
            feeds,
            json,
        } => {
            let mut store = IocStore::load(&cli.store)?;
            let mut imported = store.import_domain_list(&blocklist, "dns-blocklist")?;
            let mut feed_results: Vec<serde_json::Value> = Vec::new();

            // Build feed URL list: --feed-url, --feed*, and --online defaults.
            let mut urls: Vec<(String, String)> = Vec::new();
            if let Some(u) = feed_url {
                urls.push((u, "feed_url".into()));
            }
            for (i, u) in feeds.into_iter().enumerate() {
                urls.push((u, format!("feed_{i}")));
            }
            if online {
                // Public lab feeds (capped). Not a commercial TIP.
                urls.push((
                    "https://urlhaus.abuse.ch/downloads/text_online/".into(),
                    "urlhaus".into(),
                ));
                urls.push((
                    "https://openphish.com/feed.txt".into(),
                    "openphish".into(),
                ));
            }

            if !urls.is_empty() {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(60))
                    .user_agent("S2O-ThreatGrid/0.3 (+local IOC multi-feed sync)")
                    .build()?;
                for (url, source) in urls {
                if !json {
                    println!(
                        "[threatgrid] fetching feed {url} source={source} (max_import={max_import})..."
                    );
                }
                match client.get(&url).send().await {
                    Ok(res) if res.status().is_success() => {
                        let text = res.text().await?;
                        let capped = cap_domain_feed(&text, max_import);
                        let tmp = default_store_path().with_extension(format!("{source}.tmp"));
                        std::fs::write(&tmp, &capped)?;
                        let n = store.import_domain_list(&tmp, &source)?;
                        imported += n;
                        let _ = std::fs::remove_file(&tmp);
                        feed_results.push(serde_json::json!({
                            "source": source,
                            "url": url,
                            "ok": true,
                            "imported": n,
                        }));
                        if !json {
                            println!("[threatgrid] feed {source} imported +{n}");
                        }
                    }
                    Ok(res) => {
                        feed_results.push(serde_json::json!({
                            "source": source,
                            "url": url,
                            "ok": false,
                            "status": res.status().as_u16(),
                        }));
                        if !json {
                            eprintln!(
                                "[threatgrid] feed {source} HTTP {} — continuing",
                                res.status()
                            );
                        }
                    }
                    Err(e) => {
                        feed_results.push(serde_json::json!({
                            "source": source,
                            "url": url,
                            "ok": false,
                            "error": e.to_string(),
                        }));
                        if !json {
                            eprintln!("[threatgrid] feed {source} fetch failed ({e}) — continuing");
                        }
                    }
                }
                } // for each feed url
            }

            // Seed a couple of lab domains if empty
            if store.entries.is_empty() {
                store.upsert(IocEntry {
                    kind: IocKind::Domain,
                    value: "malware.test.s2o".into(),
                    source: "seed".into(),
                    severity: IocSeverity::High,
                    note: Some("lab seed".into()),
                    added_at: Utc::now(),
                });
                imported += 1;
            }
            store.save(&cli.store)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "imported": imported,
                        "total": store.entries.len(),
                        "blocklist": blocklist.display().to_string(),
                        "online": online,
                        "feeds": feed_results,
                        "store": cli.store.display().to_string(),
                    }))?
                );
            } else {
                println!(
                    "{}",
                    format!(
                        "[threatgrid] sync ok: +{imported} new, total {}",
                        store.entries.len()
                    )
                    .green()
                    .bold()
                );
            }
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("ioc sync imported={imported} total={}", store.entries.len()),
                &[
                    ("imported", serde_json::json!(imported)),
                    ("total", serde_json::json!(store.entries.len())),
                    ("online", serde_json::json!(online)),
                ],
                None,
            );
        }
        Commands::List { kind, limit, json } => {
            let store = IocStore::load(&cli.store)?;
            let filter = kind.as_ref().and_then(|k| parse_kind(k));
            let mut rows: Vec<&IocEntry> = Vec::new();
            for e in &store.entries {
                if let Some(k) = filter {
                    if e.kind != k {
                        continue;
                    }
                }
                rows.push(e);
                if rows.len() >= limit {
                    break;
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "store": cli.store.display().to_string(),
                        "kind": kind,
                        "limit": limit,
                        "shown": rows.len(),
                        "store_total": store.entries.len(),
                        "entries": rows,
                    }))?
                );
            } else if rows.is_empty() {
                println!("[threatgrid] no entries (run: cyberintel sync)");
            } else {
                for e in &rows {
                    println!(
                        "{:?}\t{}\t{}\t{:?}",
                        e.kind, e.value, e.source, e.severity
                    );
                }
            }
        }
        Commands::Prune {
            older_days,
            source,
            apply,
            json,
        } => {
            let mut store = IocStore::load(&cli.store)?;
            let before = store.entries.len();
            let age_n = if older_days > 0 {
                store.prune_older_than(older_days)
            } else {
                0
            };
            let src_n = if let Some(ref src) = source {
                store.prune_by_source(src)
            } else {
                0
            };
            if apply {
                store.save(&cli.store)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "apply": true,
                            "before": before,
                            "age_removed": age_n,
                            "source_removed": src_n,
                            "remaining": store.entries.len(),
                            "source": source,
                            "older_days": older_days,
                            "store": cli.store.display().to_string(),
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!(
                            "[threatgrid] prune APPLIED age={age_n} source={src_n} remaining={} (was {before})",
                            store.entries.len()
                        )
                        .green()
                        .bold()
                    );
                }
                emit(
                    &cli.event_log,
                    EventAction::Observed,
                    Severity::Info,
                    format!("ioc prune age={age_n} source={src_n}"),
                    &[
                        ("age_removed", serde_json::json!(age_n)),
                        ("source_removed", serde_json::json!(src_n)),
                        ("remaining", serde_json::json!(store.entries.len())),
                    ],
                    None,
                );
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "apply": false,
                        "before": before,
                        "age_removed": age_n,
                        "source_removed": src_n,
                        "would_remove": age_n + src_n,
                        "source": source,
                        "older_days": older_days,
                        "store": cli.store.display().to_string(),
                    }))?
                );
            } else {
                println!(
                    "[threatgrid] prune dry-run: would remove age={age_n} source={src_n} of {before} (use --apply)"
                );
            }
        }
        Commands::Export {
            format,
            out,
            kind,
            limit,
        } => {
            let store = IocStore::load(&cli.store)?;
            let filter = kind.as_ref().and_then(|k| parse_kind(k));
            let entries: Vec<_> = store
                .entries
                .iter()
                .filter(|e| filter.map(|k| e.kind == k).unwrap_or(true))
                .take(limit)
                .collect();
            let text = if format.eq_ignore_ascii_case("csv") {
                let mut s = String::from("kind,value,source,severity,added_at\n");
                for e in &entries {
                    s.push_str(&format!(
                        "{:?},{},{},{:?},{}\n",
                        e.kind,
                        e.value.replace(',', " "),
                        e.source.replace(',', " "),
                        e.severity,
                        e.added_at.to_rfc3339()
                    ));
                }
                s
            } else {
                serde_json::to_string_pretty(&entries)?
            };
            if let Some(path) = out {
                if let Some(p) = path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::write(&path, &text)?;
                println!(
                    "{}",
                    format!(
                        "[threatgrid] exported {} entries → {}",
                        entries.len(),
                        path.display()
                    )
                    .green()
                    .bold()
                );
            } else {
                print!("{text}");
            }
        }
        Commands::Stats { top, json } => {
            use std::collections::BTreeMap;
            let store = IocStore::load(&cli.store)?;
            let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
            for e in &store.entries {
                *by_kind
                    .entry(format!("{:?}", e.kind).to_ascii_lowercase())
                    .or_default() += 1;
                let src = if e.source.is_empty() {
                    "(empty)".into()
                } else {
                    e.source.clone()
                };
                *by_source.entry(src).or_default() += 1;
                *by_sev
                    .entry(format!("{:?}", e.severity).to_ascii_lowercase())
                    .or_default() += 1;
            }
            if json {
                let out = serde_json::json!({
                    "store": cli.store.display().to_string(),
                    "total": store.entries.len(),
                    "by_kind": by_kind,
                    "by_source": by_source,
                    "by_severity": by_sev,
                    "updated_at": store.updated_at.to_rfc3339(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      ThreatGrid IOC stats                               "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Store : {}", cli.store.display());
                println!(" Total : {}", store.entries.len());
                println!("-- by kind --");
                for (k, v) in &by_kind {
                    println!("  {k:<12} {v}");
                }
                println!("-- by severity --");
                for (k, v) in &by_sev {
                    println!("  {k:<12} {v}");
                }
                let mut sources: Vec<_> = by_source.into_iter().collect();
                sources.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                println!("-- by source (top {top}) --");
                for (k, v) in sources.into_iter().take(top) {
                    println!("  {v:<6} {k}");
                }
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
        }
        Commands::Doctor { json } => {
            use std::collections::BTreeMap;
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut notes: Vec<serde_json::Value> = Vec::new();
            let mut check = |label: &str, good: bool, soft: bool, detail: &str| {
                notes.push(serde_json::json!({
                    "label": label,
                    "ok": good,
                    "warn": soft && !good,
                    "detail": detail,
                }));
                if good {
                    ok += 1;
                    if !json {
                        println!("  {} {} — {}", "OK".green().bold(), label, detail);
                    }
                } else if soft {
                    warn += 1;
                    if !json {
                        println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                    }
                } else {
                    fail += 1;
                    if !json {
                        println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                    }
                }
            };

            if !json {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      ThreatGrid doctor                                  "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            let store = match IocStore::load(&cli.store) {
                Ok(s) => {
                    check(
                        "store file",
                        cli.store.exists(),
                        true,
                        &format!("{} (schema {})", cli.store.display(), s.version),
                    );
                    s
                }
                Err(e) => {
                    check("store file", false, false, &format!("load error: {e}"));
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "fail_count": 1,
                                "checks": notes,
                            }))?
                        );
                    }
                    std::process::exit(1);
                }
            };

            check(
                "entries",
                !store.entries.is_empty(),
                true,
                &if store.entries.is_empty() {
                    "empty (run: cyberintel sync --online)".into()
                } else {
                    format!("{} total", store.entries.len())
                },
            );
            check(
                "domains",
                true,
                false,
                &format!("{}", store.count_by_kind(IocKind::Domain)),
            );
            check(
                "ips",
                true,
                false,
                &format!("{}", store.count_by_kind(IocKind::Ip)),
            );
            check(
                "hashes",
                true,
                false,
                &format!("{}", store.count_by_kind(IocKind::Hash)),
            );
            check(
                "urls",
                true,
                false,
                &format!("{}", store.count_by_kind(IocKind::Url)),
            );

            // Empty values / dups
            let mut empty = 0u32;
            let mut seen = std::collections::BTreeSet::new();
            let mut dups = 0u32;
            for e in &store.entries {
                if e.value.trim().is_empty() {
                    empty += 1;
                }
                let key = format!("{:?}:{}", e.kind, e.value);
                if !seen.insert(key) {
                    dups += 1;
                }
            }
            check(
                "data quality",
                empty == 0 && dups == 0,
                true,
                &format!("empty_values={empty} duplicate_keys={dups}"),
            );

            let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
            for e in &store.entries {
                let src = if e.source.is_empty() {
                    "(empty)".into()
                } else {
                    e.source.clone()
                };
                *by_source.entry(src).or_default() += 1;
            }
            let top_src: Vec<_> = {
                let mut v: Vec<_> = by_source.into_iter().collect();
                v.sort_by(|a, b| b.1.cmp(&a.1));
                v.into_iter().take(5).collect::<Vec<_>>()
            };
            check(
                "sources",
                true,
                false,
                &top_src
                    .iter()
                    .map(|(k, n)| format!("{k}={n}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );

            // Age: oldest / newest
            if let (Some(oldest), Some(newest)) = (
                store.entries.iter().map(|e| e.added_at).min(),
                store.entries.iter().map(|e| e.added_at).max(),
            ) {
                let age_days = (chrono::Utc::now() - oldest).num_days();
                check(
                    "age span",
                    true,
                    false,
                    &format!(
                        "oldest={}d ago newest={}",
                        age_days,
                        newest.to_rfc3339()
                    ),
                );
                if age_days > 90 {
                    check(
                        "stale IOCs",
                        false,
                        true,
                        "entries older than 90d present (cyberintel prune --older-days 90)",
                    );
                }
            }

            check(
                "event log",
                cli.event_log.exists(),
                true,
                &format!("{}", cli.event_log.display()),
            );
            check(
                "updated_at",
                true,
                false,
                &store.updated_at.to_rfc3339(),
            );

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "total": store.entries.len(),
                        "by_kind": {
                            "domain": store.count_by_kind(IocKind::Domain),
                            "ip": store.count_by_kind(IocKind::Ip),
                            "hash": store.count_by_kind(IocKind::Hash),
                            "url": store.count_by_kind(IocKind::Url),
                        },
                        "checks": notes,
                    }))?
                );
            } else {
                println!(
                    " Summary: {} ok, {} warn, {} fail",
                    ok.to_string().green(),
                    warn.to_string().yellow(),
                    fail.to_string().red()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
            if fail > 0 {
                std::process::exit(1);
            }
        }
        Commands::Remove {
            value,
            kind,
            apply,
            json,
        } => {
            let filter = kind.as_ref().and_then(|k| parse_kind(k));
            if kind.is_some() && filter.is_none() {
                eprintln!("[threatgrid] bad --kind (use domain|ip|hash|url)");
                std::process::exit(2);
            }
            let mut store = IocStore::load(&cli.store)?;
            let hits = store.lookup(&value);
            let matched: Vec<_> = hits
                .iter()
                .filter(|e| filter.map(|k| e.kind == k).unwrap_or(true))
                .cloned()
                .collect();
            let preview: Vec<_> = matched
                .iter()
                .map(|e| format!("{:?} {} src={}", e.kind, e.value, e.source))
                .collect();
            if preview.is_empty() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": "no match",
                            "value": value,
                            "kind": kind,
                            "matches": 0,
                        }))?
                    );
                } else {
                    println!("[threatgrid] no match for '{value}'");
                }
                std::process::exit(1);
            }
            if !apply {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "apply": false,
                            "value": value,
                            "kind": kind,
                            "would_remove": matched.len(),
                            "entries": matched,
                        }))?
                    );
                } else {
                    println!(
                        "[threatgrid] remove dry-run: would drop {} entr(y/ies) (use --apply)",
                        preview.len()
                    );
                    for p in &preview {
                        println!("  - {p}");
                    }
                }
            } else {
                let n = store.remove(&value, filter);
                store.save(&cli.store)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "apply": true,
                            "value": value,
                            "kind": kind,
                            "removed": n,
                            "remaining": store.entries.len(),
                            "store": cli.store.display().to_string(),
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!("[threatgrid] removed {n} entr(y/ies) for '{value}'")
                            .green()
                            .bold()
                    );
                }
                emit(
                    &cli.event_log,
                    EventAction::Observed,
                    Severity::Info,
                    format!("ioc remove value={value} n={n}"),
                    &[
                        ("value", serde_json::json!(value)),
                        ("removed", serde_json::json!(n)),
                    ],
                    None,
                );
            }
        }
    }

    Ok(())
}
