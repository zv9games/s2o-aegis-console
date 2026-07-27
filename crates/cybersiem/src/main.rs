//! S2O CyberLog — local event store reader + stats + light correlation + UDP collect.

use clap::{Parser, Subcommand};
use colored::*;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cybersiem")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.3.0")]
#[command(about = "S2O CyberLog: JSONL SIEM + UDP syslog collect (Phase 2/3)", long_about = None)]
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
    /// Live collector: UDP syslog → Aegis JSONL event store
    Collect {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// UDP bind (default high port for lab; 514 needs elevation)
        #[arg(long, default_value = "127.0.0.1:5514")]
        listen: String,
        /// Stop after N ingested events (0 = run until Ctrl+C)
        #[arg(long, default_value_t = 0)]
        max_events: u64,
        /// Also accept one line from stdin as a test inject then exit
        #[arg(long)]
        stdin_once: bool,
    },
    Export {
        /// json | syslog
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        product: Option<String>,
        /// Send syslog lines over UDP (format=syslog). Example: 127.0.0.1:514
        #[arg(long)]
        syslog_udp: Option<String>,
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

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

/// Strip leading `<PRI>` and optional RFC5424/3164 header noise for message body.
fn strip_syslog_pri(line: &str) -> (Option<u8>, &str) {
    let b = line.as_bytes();
    if b.first() == Some(&b'<') {
        if let Some(end) = b.iter().position(|&c| c == b'>') {
            if end > 1 && end < 6 {
                if let Ok(pri) = std::str::from_utf8(&b[1..end]).unwrap_or("").parse::<u8>() {
                    return (Some(pri), line[end + 1..].trim_start());
                }
            }
        }
    }
    (None, line.trim())
}

fn severity_from_pri(pri: Option<u8>) -> Severity {
    // severity = PRI % 8 (RFC 5424)
    match pri.map(|p| p % 8) {
        Some(0..=2) => Severity::Critical,
        Some(3) => Severity::High,
        Some(4) => Severity::Medium,
        Some(5) => Severity::Medium,
        Some(6) => Severity::Info,
        Some(7) => Severity::Info,
        _ => Severity::Info,
    }
}

fn syslog_to_event(peer: Option<SocketAddr>, line: &str) -> AegisEvent {
    let (pri, body) = strip_syslog_pri(line);
    let sev = severity_from_pri(pri);
    let mut ev = AegisEvent::new(
        host_id(),
        ProductId::CyberLog,
        EventKind::NetFlow,
        EventAction::Observed,
        sev,
        body.to_string(),
    )
    .with_attr("transport", serde_json::json!("udp_syslog"))
    .with_attr("raw", serde_json::json!(line));
    if let Some(p) = pri {
        ev = ev.with_attr("pri", serde_json::json!(p));
        ev = ev.with_attr("facility", serde_json::json!(p / 8));
        ev = ev.with_attr("syslog_severity", serde_json::json!(p % 8));
    }
    if let Some(addr) = peer {
        ev = ev.with_attr("source", serde_json::json!(addr.to_string()));
    } else {
        ev = ev.with_attr("source", serde_json::json!("stdin"));
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_pri_and_severity() {
        let (pri, body) = strip_syslog_pri("<14>1 host app - hello world");
        assert_eq!(pri, Some(14));
        assert!(body.contains("hello world"));
        assert!(matches!(severity_from_pri(Some(14)), Severity::Info));
        assert!(matches!(severity_from_pri(Some(3)), Severity::High));
    }
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
                "       S2O CyberLog (Phase 2/3 shell)                    "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "JSONL read/export, filter, stats, correlate, UDP syslog collect".green()
            );
            println!(
                " Not implemented   : {}",
                "remote EPS, multi-tenant, full RFC5424 parser".red()
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
                " Collect default   : {}",
                "cybersiem collect --listen 127.0.0.1:5514".yellow()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Collect {
            event_log,
            listen,
            max_events,
            stdin_once,
        } => {
            if let Some(p) = event_log.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let store = EventStore::open(&event_log)?;

            if stdin_once {
                use std::io::{self, Read};
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                let line = buf.lines().next().unwrap_or(buf.trim());
                if line.is_empty() {
                    eprintln!("[cyberlog] empty stdin");
                    std::process::exit(2);
                }
                let ev = syslog_to_event(None, line);
                store.append(&ev)?;
                println!(
                    "{}",
                    format!("[cyberlog] ingested stdin → {}", event_log.display())
                        .green()
                        .bold()
                );
                println!("  {}", ev.message);
                return Ok(());
            }

            let sock = tokio::net::UdpSocket::bind(&listen).await?;
            println!(
                "{}",
                format!(
                    "[cyberlog] collect UDP syslog on {listen} → {} (Ctrl+C to stop)",
                    event_log.display()
                )
                .cyan()
            );
            let mut buf = vec![0u8; 65535];
            let mut n = 0u64;
            loop {
                let (len, peer) = sock.recv_from(&mut buf).await?;
                let raw = String::from_utf8_lossy(&buf[..len]);
                for line in raw.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let ev = syslog_to_event(Some(peer), line);
                    store.append(&ev)?;
                    n += 1;
                    println!(
                        "[{}] {:?} from {} | {}",
                        n.to_string().yellow(),
                        ev.severity,
                        peer,
                        ev.message
                    );
                    if max_events > 0 && n >= max_events {
                        println!(
                            "{}",
                            format!("[cyberlog] max_events={max_events} reached")
                                .green()
                                .bold()
                        );
                        return Ok(());
                    }
                }
            }
        }
        Commands::Export {
            format,
            event_log,
            limit,
            product,
            syslog_udp,
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
            if format.eq_ignore_ascii_case("json") && syslog_udp.is_none() {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                let lines: Vec<String> = events
                    .iter()
                    .map(|ev| {
                        // RFC5424-ish structured line
                        format!(
                            "<14>1 {} {} s2o-{} {:?} - {}",
                            ev.ts.to_rfc3339(),
                            ev.host_id,
                            ev.product.as_str(),
                            ev.kind,
                            ev.message.replace('\n', " ")
                        )
                    })
                    .collect();
                if let Some(addr) = syslog_udp {
                    use std::net::UdpSocket;
                    let sock = UdpSocket::bind("0.0.0.0:0")?;
                    sock.connect(&addr)?;
                    let mut sent = 0usize;
                    for line in &lines {
                        sock.send(line.as_bytes())?;
                        sent += 1;
                    }
                    println!(
                        "[cyberlog] sent {sent} syslog UDP datagrams to {addr}"
                    );
                } else {
                    for line in lines {
                        println!("{line}");
                    }
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
