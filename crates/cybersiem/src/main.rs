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
        #[arg(long)]
        json: bool,
    },
    /// Validate JSONL event store health (parse/size/window)
    Doctor {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Sample last N lines for parse health
        #[arg(long, default_value_t = 500)]
        sample: usize,
        #[arg(long)]
        json: bool,
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
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
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
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
    },
    /// Counts by product / severity / kind
    Stats {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Recent high/critical (and optional blocked) events
    Alerts {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        limit: usize,
        /// Max alerts to print
        #[arg(long, default_value_t = 30)]
        max: usize,
        /// Also include EventAction::Blocked regardless of severity
        #[arg(long, default_value_t = true)]
        include_blocked: bool,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Top products / severities / attr keys (domain, path) from recent window
    Top {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
        #[arg(long, default_value_t = 10)]
        n: usize,
        /// Attr key to rank (default: domain, else path)
        #[arg(long, default_value = "domain")]
        attr: String,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Simple multi-product trail for a domain/hash/string
    Correlate {
        query: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        limit: usize,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Free-text search across message/attrs/iocs (optional product/severity/since)
    Search {
        /// Substring match (case-insensitive) against message, attrs, iocs
        query: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
        /// Max hits to print (default 50)
        #[arg(long, default_value_t = 50)]
        max: usize,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
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

/// Parse relative duration (`15m`, `1h`, `24h`, `7d`, `2w`) or RFC3339 into a UTC lower bound.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --since value".into());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return Err(format!(
            "invalid --since '{s}' (use 15m, 1h, 24h, 7d, 2w, or RFC3339)"
        ));
    }
    let unit = *bytes.last().unwrap() as char;
    let num_str = &s[..s.len() - 1];
    let n: i64 = num_str.parse().map_err(|_| {
        format!("invalid --since '{s}' (use 15m, 1h, 24h, 7d, 2w, or RFC3339)")
    })?;
    if n <= 0 {
        return Err("--since duration must be positive".into());
    }
    let now = chrono::Utc::now();
    let bound = match unit {
        's' | 'S' => now - chrono::Duration::seconds(n),
        'm' | 'M' => now - chrono::Duration::minutes(n),
        'h' | 'H' => now - chrono::Duration::hours(n),
        'd' | 'D' => now - chrono::Duration::days(n),
        'w' | 'W' => now - chrono::Duration::weeks(n),
        _ => {
            return Err(format!(
                "invalid --since unit in '{s}' (use s/m/h/d/w or RFC3339)"
            ));
        }
    };
    Ok(bound)
}

fn apply_since_filter(
    events: &mut Vec<AegisEvent>,
    since: &Option<String>,
) -> Result<(), String> {
    if let Some(ref s) = since {
        let bound = parse_since(s)?;
        events.retain(|e| e.ts >= bound);
    }
    Ok(())
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

    #[test]
    fn parse_since_relative_and_rfc3339() {
        let h = parse_since("1h").expect("1h");
        let now = chrono::Utc::now();
        assert!(now.signed_duration_since(h).num_minutes() >= 59);
        assert!(now.signed_duration_since(h).num_minutes() <= 61);
        let d = parse_since("7d").expect("7d");
        assert!(now.signed_duration_since(d).num_days() >= 6);
        let rfc = "2020-01-01T00:00:00Z";
        let abs = parse_since(rfc).expect("rfc");
        assert_eq!(abs.to_rfc3339(), "2020-01-01T00:00:00+00:00");
        assert!(parse_since("bogus").is_err());
        assert!(parse_since("0h").is_err());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { event_log, json } => {
            let (present, count, bytes) = if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                let meta = std::fs::metadata(&event_log).ok();
                (
                    true,
                    Some(store.count()?),
                    meta.map(|m| m.len()),
                )
            } else {
                (false, None, None)
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "product": "cybersiem",
                        "event_log": event_log.display().to_string(),
                        "event_log_present": present,
                        "event_count": count,
                        "event_log_bytes": bytes,
                        "collect_default": "127.0.0.1:5514",
                        "implemented": "JSONL read/export, stats, alerts, top, search, correlate, doctor, --since, UDP collect",
                        "not_implemented": "remote EPS, multi-tenant, full RFC5424 parser",
                    }))?
                );
            } else {
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
                    "JSONL read/export, stats, alerts, top, search, correlate, doctor, --since, UDP collect"
                        .green()
                );
                println!(
                    " Not implemented   : {}",
                    "remote EPS, multi-tenant, full RFC5424 parser".red()
                );
                if present {
                    println!(" Event log         : {}", event_log.display());
                    if let Some(c) = count {
                        println!(" Stored events     : {c}");
                    }
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
        }
        Commands::Doctor {
            event_log,
            sample,
            json,
        } => {
            use std::fs;
            use std::io::{BufRead, BufReader};

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
                    "      S2O CyberLog doctor                                "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            if !event_log.exists() {
                check(
                    "event log",
                    false,
                    true,
                    &format!("{} missing", event_log.display()),
                );
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "ok_count": ok,
                            "warn_count": warn,
                            "fail_count": fail,
                            "checks": notes,
                        }))?
                    );
                } else {
                    println!(
                        " Summary: {} ok, {} warn, {} fail",
                        ok, warn, fail
                    );
                }
                return Ok(());
            }

            let meta = fs::metadata(&event_log)?;
            let bytes = meta.len();
            check(
                "event log",
                true,
                false,
                &format!("{} ({} bytes)", event_log.display(), bytes),
            );

            // Line/parse sample: scan all for totals, track bad lines
            let file = fs::File::open(&event_log)?;
            let reader = BufReader::new(file);
            let mut by_product: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
            let mut oldest: Option<chrono::DateTime<chrono::Utc>> = None;
            let mut newest: Option<chrono::DateTime<chrono::Utc>> = None;
            let mut ring: std::collections::VecDeque<String> =
                std::collections::VecDeque::with_capacity(sample.max(1));
            for line in reader.lines().flatten() {
                if line.trim().is_empty() {
                    continue;
                }
                if ring.len() == sample.max(1) {
                    ring.pop_front();
                }
                ring.push_back(line);
            }
            // full line count via store; parse health from trailing sample ring
            let store = EventStore::open(&event_log)?;
            let count = store.count().unwrap_or(0);
            let mut parsed = 0u64;
            let mut bad = 0u64;
            for line in &ring {
                match serde_json::from_str::<AegisEvent>(line) {
                    Ok(ev) => {
                        parsed += 1;
                        *by_product.entry(ev.product.as_str().into()).or_default() += 1;
                        *by_sev
                            .entry(format!("{:?}", ev.severity).to_ascii_lowercase())
                            .or_default() += 1;
                        oldest = Some(oldest.map_or(ev.ts, |o| o.min(ev.ts)));
                        newest = Some(newest.map_or(ev.ts, |n| n.max(ev.ts)));
                    }
                    Err(_) => bad += 1,
                }
            }

            check(
                "line count",
                count > 0,
                true,
                &format!("{count} non-empty lines"),
            );
            check(
                "sample parse",
                bad == 0 && parsed > 0,
                bad > 0,
                &format!(
                    "last {} lines: ok={parsed} bad={bad}",
                    ring.len()
                ),
            );
            if let (Some(o), Some(n)) = (oldest, newest) {
                check(
                    "time span (sample)",
                    true,
                    false,
                    &format!("{} → {}", o.to_rfc3339(), n.to_rfc3339()),
                );
            }

            // size guidance
            let mb = bytes as f64 / (1024.0 * 1024.0);
            check(
                "size",
                mb < 50.0,
                true,
                &if mb >= 50.0 {
                    format!("{mb:.1} MiB — consider: aegis rotate")
                } else {
                    format!("{mb:.2} MiB")
                },
            );

            let top_products: Vec<_> = {
                let mut v: Vec<_> = by_product.into_iter().collect();
                v.sort_by(|a, b| b.1.cmp(&a.1));
                v.into_iter().take(5).collect()
            };
            check(
                "top products (sample)",
                true,
                false,
                &if top_products.is_empty() {
                    "(none)".into()
                } else {
                    top_products
                        .iter()
                        .map(|(k, n)| format!("{k}={n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
            check(
                "severities (sample)",
                true,
                false,
                &by_sev
                    .iter()
                    .map(|(k, n)| format!("{k}={n}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "path": event_log.display().to_string(),
                        "bytes": bytes,
                        "lines": count,
                        "sample_ok": parsed,
                        "sample_bad": bad,
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
            since,
            syslog_udp,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let read_n = if since.is_some() {
                limit.saturating_mul(20).max(limit)
            } else {
                limit
            };
            let mut events = store.recent(read_n)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
            if let Some(ref p) = product {
                events.retain(|e| product_matches(e.product, p));
            }
            if events.len() > limit {
                events = events.split_off(events.len() - limit);
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
            since,
        } => {
            if !event_log.exists() {
                println!("[cyberlog] no events yet.");
                return Ok(());
            }
            let store = EventStore::open(&event_log)?;
            let over = if since.is_some() {
                limit.saturating_mul(50).max(limit * 5)
            } else {
                limit * 5
            };
            let mut events = store.recent(over)?; // over-read then filter
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
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
        Commands::Alerts {
            event_log,
            limit,
            max,
            include_blocked,
            since,
            json,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
            let mut hits: Vec<_> = events
                .into_iter()
                .filter(|e| {
                    matches!(e.severity, Severity::High | Severity::Critical)
                        || (include_blocked
                            && matches!(e.action, s2o_schema::EventAction::Blocked))
                })
                .collect();
            // newest last in recent() — reverse so newest first
            hits.reverse();
            if hits.len() > max {
                hits.truncate(max);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    format!("  CyberLog alerts (high/critical{})", if include_blocked { "+blocked" } else { "" })
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                if hits.is_empty() {
                    println!("{}", "No alert-level events in window.".green());
                }
                for ev in &hits {
                    let sev = format!("{:?}", ev.severity);
                    let color = match ev.severity {
                        Severity::Critical | Severity::High => sev.red().bold().to_string(),
                        Severity::Medium => sev.yellow().to_string(),
                        _ => sev,
                    };
                    println!(
                        "[{}] {} {:?} / {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        color,
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
                println!(" Alerts: {}", hits.len());
            }
            if !hits.is_empty() {
                std::process::exit(3);
            }
        }
        Commands::Top {
            event_log,
            limit,
            n,
            attr,
            since,
            json,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
            let mut by_product: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_attr: BTreeMap<String, usize> = BTreeMap::new();
            for e in &events {
                *by_product.entry(e.product.as_str().into()).or_default() += 1;
                *by_sev
                    .entry(format!("{:?}", e.severity).to_ascii_lowercase())
                    .or_default() += 1;
                if let Some(v) = e.attrs.get(&attr).and_then(|x| x.as_str()) {
                    *by_attr.entry(v.to_string()).or_default() += 1;
                } else if attr == "domain" {
                    // fallback: path attr for gate, or message tokens
                    if let Some(v) = e.attrs.get("path").and_then(|x| x.as_str()) {
                        *by_attr.entry(format!("path:{v}")).or_default() += 1;
                    }
                }
            }
            let top_vec = |map: BTreeMap<String, usize>| {
                let mut v: Vec<_> = map.into_iter().collect();
                v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                v.into_iter()
                    .take(n)
                    .map(|(k, c)| serde_json::json!({"key": k, "count": c}))
                    .collect::<Vec<_>>()
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "window": events.len(),
                        "n": n,
                        "attr": attr,
                        "since": since,
                        "products": top_vec(by_product),
                        "severities": top_vec(by_sev),
                        "attr_top": top_vec(by_attr),
                    }))?
                );
            } else {
                let print_top = |title: &str, map: BTreeMap<String, usize>| {
                    let mut v: Vec<_> = map.into_iter().collect();
                    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                    println!("-- {title} --");
                    for (k, c) in v.into_iter().take(n) {
                        println!("  {c:<6} {k}");
                    }
                };
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    format!("  CyberLog top (window={}, n={})", events.len(), n)
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                print_top("products", by_product);
                print_top("severities", by_sev);
                print_top(&format!("attr:{attr}"), by_attr);
            }
        }
        Commands::Stats {
            event_log,
            limit,
            since,
            json,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
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
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "window": events.len(),
                        "since": since,
                        "by_product": by_product,
                        "by_severity": by_sev,
                        "by_kind": by_kind,
                        "by_action": by_action,
                    }))?
                );
            } else {
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
                if let Some(ref s) = since {
                    println!(" Since         : {s}");
                }
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
        }
        Commands::Correlate {
            query,
            event_log,
            limit,
            since,
            json,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let q = query.to_ascii_lowercase();
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
            let mut hits = Vec::new();
            for e in events {
                let msg = e.message.to_ascii_lowercase();
                let attrs = serde_json::to_string(&e.attrs).unwrap_or_default().to_ascii_lowercase();
                let iocs = serde_json::to_string(&e.iocs).unwrap_or_default().to_ascii_lowercase();
                if msg.contains(&q) || attrs.contains(&q) || iocs.contains(&q) {
                    hits.push(e);
                }
            }
            let mut products: BTreeMap<String, usize> = BTreeMap::new();
            for e in &hits {
                *products.entry(e.product.as_str().into()).or_default() += 1;
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "query": query,
                        "since": since,
                        "hit_count": hits.len(),
                        "products": products,
                        "events": hits,
                    }))?
                );
            } else {
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
                for e in &hits {
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
                    for (p, n) in &products {
                        println!("  {p}: {n}");
                    }
                }
                if hits.is_empty() {
                    println!("(no correlated events)");
                }
            }
        }
        Commands::Search {
            query,
            event_log,
            limit,
            max,
            product,
            severity,
            since,
            json,
        } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log");
                std::process::exit(1);
            }
            let q = query.to_ascii_lowercase();
            let store = EventStore::open(&event_log)?;
            let mut events = store.recent(limit)?;
            if let Err(e) = apply_since_filter(&mut events, &since) {
                eprintln!("[cyberlog] {e}");
                std::process::exit(2);
            }
            if let Some(ref p) = product {
                events.retain(|e| product_matches(e.product, p));
            }
            if let Some(ref s) = severity {
                events.retain(|e| severity_matches(e.severity, s));
            }
            let mut hits = Vec::new();
            for e in events {
                let msg = e.message.to_ascii_lowercase();
                let attrs =
                    serde_json::to_string(&e.attrs).unwrap_or_default().to_ascii_lowercase();
                let iocs =
                    serde_json::to_string(&e.iocs).unwrap_or_default().to_ascii_lowercase();
                let product_s = e.product.as_str().to_ascii_lowercase();
                if msg.contains(&q)
                    || attrs.contains(&q)
                    || iocs.contains(&q)
                    || product_s.contains(&q)
                {
                    hits.push(e);
                }
            }
            // newest first for search UX
            hits.reverse();
            let total = hits.len();
            if hits.len() > max {
                hits.truncate(max);
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "query": query,
                        "since": since,
                        "product": product,
                        "severity": severity,
                        "total_hits": total,
                        "shown": hits.len(),
                        "events": hits,
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    format!(
                        "  CyberLog search: '{query}' ({total} hits, showing {})",
                        hits.len()
                    )
                    .bold()
                    .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                if hits.is_empty() {
                    println!("(no matches)");
                }
                for e in &hits {
                    println!(
                        "[{}] {:?} {:?} / {:?} | {}",
                        e.ts.to_rfc3339().cyan(),
                        e.severity,
                        e.product,
                        e.action,
                        e.message
                    );
                }
                if total > hits.len() {
                    println!(
                        " … truncated; use --max {} or raise --limit",
                        total
                    );
                }
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
