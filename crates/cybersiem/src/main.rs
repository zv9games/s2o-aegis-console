//! S2O CyberLog — local event store reader + stats + light correlation.

use clap::{Parser, Subcommand};
use colored::*;
use s2o_schema::{EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cybersiem")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O CyberLog: local JSONL SIEM reader (Phase 2 shell)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    Collect,
    Export {
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        product: Option<String>,
    },
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        kind: Option<String>,
    },
    /// Counts by product / severity / kind
    Stats {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
    },
    /// Simple multi-product trail for a domain/hash/string
    Correlate {
        query: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        limit: usize,
    },
    /// Follow the event log (poll for new JSONL lines)
    Follow {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Poll interval milliseconds
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        /// Print existing tail first
        #[arg(long, default_value_t = 5)]
        from_recent: usize,
    },
}

fn product_matches(p: ProductId, filter: &str) -> bool {
    let f = filter.to_ascii_lowercase();
    p.as_str() == f
        || format!("{:?}", p).to_ascii_lowercase().contains(&f)
        || p.display_name().to_ascii_lowercase().contains(&f)
}

fn severity_matches(s: Severity, filter: &str) -> bool {
    format!("{:?}", s).eq_ignore_ascii_case(filter)
}

fn kind_matches(k: EventKind, filter: &str) -> bool {
    format!("{:?}", k).eq_ignore_ascii_case(filter)
        || format!("{:?}", k).to_ascii_lowercase().contains(&filter.to_ascii_lowercase())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { event_log } => {
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       S2O CyberLog (Phase 2 shell)                      "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "JSONL read/export, filter, stats, correlate".green()
            );
            println!(
                " Not implemented   : {}",
                "live collectors, remote EPS, multi-tenant".red()
            );
            if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                println!(" Event log         : {}", event_log.display());
                println!(" Stored events     : {}", store.count()?);
            } else {
                println!(
                    " Event log         : {} (missing — run suite tools)",
                    event_log.display()
                );
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Collect => {
            eprintln!("[cyberlog] live collect not implemented.");
            eprintln!("Emit via aegisd / cyberwall / cyberdns / cyberintel / …");
            std::process::exit(2);
        }
        Commands::Export {
            format,
            event_log,
            limit,
            product,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Some(ref p) = product {
                events.retain(|e| product_matches(e.product, p));
            }
            if format.eq_ignore_ascii_case("json") {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for ev in events {
                    println!(
                        "<14>1 {} {} {:?} {:?} - {}",
                        ev.ts.to_rfc3339(),
                        ev.host_id,
                        ev.product,
                        ev.kind,
                        ev.message
                    );
                }
            }
        }
        Commands::Events {
            event_log,
            limit,
            product,
            severity,
            kind,
        } => {
            if !event_log.exists() {
                println!("[cyberlog] no events yet.");
                return Ok(());
            }
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit * 5)?; // over-read then filter
            if let Some(ref p) = product {
                events.retain(|e| product_matches(e.product, p));
            }
            if let Some(ref s) = severity {
                events.retain(|e| severity_matches(e.severity, s));
            }
            if let Some(ref k) = kind {
                events.retain(|e| kind_matches(e.kind, k));
            }
            events = if events.len() > limit {
                events.split_off(events.len() - limit)
            } else {
                events
            };
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "          CyberLog — filtered events                     "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            if events.is_empty() {
                println!("(no matches)");
            }
            for ev in events {
                println!(
                    "[{}] [{:?}] {:?} / {:?} -> {}",
                    ev.ts.to_rfc3339().cyan(),
                    ev.severity,
                    ev.product,
                    ev.kind,
                    ev.message
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
            }
        }
        Commands::Stats { event_log, limit } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            let mut by_product: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_action: BTreeMap<String, usize> = BTreeMap::new();
            for e in &events {
                *by_product.entry(e.product.as_str().into()).or_default() += 1;
                *by_sev
                    .entry(format!("{:?}", e.severity).to_ascii_lowercase())
                    .or_default() += 1;
                *by_kind
                    .entry(format!("{:?}", e.kind).to_ascii_lowercase())
                    .or_default() += 1;
                *by_action
                    .entry(format!("{:?}", e.action).to_ascii_lowercase())
                    .or_default() += 1;
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "          CyberLog — stats                               "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Window events : {}", events.len());
            println!("-- by product --");
            for (k, v) in &by_product {
                println!("  {k:<16} {v}");
            }
            println!("-- by severity --");
            for (k, v) in &by_sev {
                println!("  {k:<16} {v}");
            }
            println!("-- by kind --");
            for (k, v) in &by_kind {
                println!("  {k:<16} {v}");
            }
            println!("-- by action --");
            for (k, v) in &by_action {
                println!("  {k:<16} {v}");
            }
        }
        Commands::Correlate {
            query,
            event_log,
            limit,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let q = query.to_ascii_lowercase();
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            let mut hits = Vec::new();
            for e in events {
                let msg = e.message.to_ascii_lowercase();
                let attrs = serde_json::to_string(&e.attrs).unwrap_or_default().to_ascii_lowercase();
                let iocs = serde_json::to_string(&e.iocs).unwrap_or_default().to_ascii_lowercase();
                if msg.contains(&q) || attrs.contains(&q) || iocs.contains(&q) {
                    hits.push(e);
                }
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                format!("  CyberLog correlate: '{query}' ({} hits)", hits.len())
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            let mut products: BTreeMap<String, usize> = BTreeMap::new();
            for e in &hits {
                *products.entry(e.product.as_str().into()).or_default() += 1;
                println!(
                    "[{}] {:?} {:?} | {}",
                    e.ts.to_rfc3339().cyan(),
                    e.product,
                    e.action,
                    e.message
                );
            }
            if !products.is_empty() {
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(" Products in trail:");
                for (p, n) in products {
                    println!("  {p}: {n}");
                }
            }
            if hits.is_empty() {
                println!("(no correlated events)");
            }
        }
        Commands::Follow {
            event_log,
            interval_ms,
            from_recent,
        } => {
            println!(
                "[cyberlog] following {} (Ctrl+C to stop)",
                event_log.display()
            );
            let store = EventStore::open(&event_log)?;
            if from_recent > 0 {
                for ev in store.recent(from_recent)? {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
                println!("{}", "---- live ----".dimmed());
            }
            let mut offset = store.byte_len().unwrap_or(0);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                let store = EventStore::open(&event_log)?;
                let (next, events) = store.read_since(offset)?;
                offset = next;
                for ev in events {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
            }
        }
    }

    Ok(())
}
