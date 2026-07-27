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
    Status,
    /// Lookup domain / IP / hash in local store
    Lookup { target: String },
    /// Add an IOC: kind = domain|ip|hash|url
    Add {
        kind: String,
        value: String,
        #[arg(long, default_value = "manual")]
        source: String,
    },
    /// Import domains from DNS blocklist + optional URL feed
    Sync {
        #[arg(long, default_value = ".aegis/dns-blocklist.txt")]
        blocklist: PathBuf,
        /// Optional URL of domain list (one per line)
        #[arg(long)]
        feed_url: Option<String>,
    },
    /// List IOCs (optional kind filter)
    List {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
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
        Commands::Status => {
            let store = IocStore::load(&cli.store)?;
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
            println!(" Domains           : {}", store.count_by_kind(IocKind::Domain));
            println!(" IPs               : {}", store.count_by_kind(IocKind::Ip));
            println!(" Hashes            : {}", store.count_by_kind(IocKind::Hash));
            println!(" URLs              : {}", store.count_by_kind(IocKind::Url));
            println!(
                " Updated           : {}",
                store.updated_at.to_rfc3339()
            );
            println!(
                " Implemented       : {}",
                "local JSON IOC store, lookup, add, sync from blocklist/feed".green()
            );
            println!(
                " Not implemented   : {}",
                "cloud ML scoring, 2.4M commercial feed".red()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Lookup { target } => {
            let store = IocStore::load(&cli.store)?;
            let hits = store.lookup(&target);
            if hits.is_empty() {
                println!(
                    "{}",
                    format!("[threatgrid] no hit for '{target}'").green()
                );
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
        Commands::Add { kind, value, source } => {
            let k = parse_kind(&kind).ok_or_else(|| format!("unknown kind '{kind}'"))?;
            let mut store = IocStore::load(&cli.store)?;
            let added = store.upsert(IocEntry {
                kind: k,
                value: value.clone(),
                source,
                severity: IocSeverity::High,
                note: None,
                added_at: Utc::now(),
            });
            store.save(&cli.store)?;
            if added {
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
        Commands::Sync { blocklist, feed_url } => {
            let mut store = IocStore::load(&cli.store)?;
            let mut imported = store.import_domain_list(&blocklist, "dns-blocklist")?;
            if let Some(url) = feed_url {
                println!("[threatgrid] fetching feed {url}...");
                let client = reqwest::Client::new();
                let text = client.get(&url).send().await?.text().await?;
                let tmp = default_store_path().with_extension("feed.tmp");
                std::fs::write(&tmp, &text)?;
                imported += store.import_domain_list(&tmp, "feed_url")?;
                let _ = std::fs::remove_file(&tmp);
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
            println!(
                "{}",
                format!(
                    "[threatgrid] sync ok: +{imported} new, total {}",
                    store.entries.len()
                )
                .green()
                .bold()
            );
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("ioc sync imported={imported} total={}", store.entries.len()),
                &[
                    ("imported", serde_json::json!(imported)),
                    ("total", serde_json::json!(store.entries.len())),
                ],
                None,
            );
        }
        Commands::List { kind, limit } => {
            let store = IocStore::load(&cli.store)?;
            let filter = kind.as_ref().and_then(|k| parse_kind(k));
            let mut n = 0;
            for e in &store.entries {
                if let Some(k) = filter {
                    if e.kind != k {
                        continue;
                    }
                }
                println!(
                    "{:?}\t{}\t{}\t{:?}",
                    e.kind, e.value, e.source, e.severity
                );
                n += 1;
                if n >= limit {
                    break;
                }
            }
            if n == 0 {
                println!("[threatgrid] no entries (run: cyberintel sync)");
            }
        }
    }

    Ok(())
}
