use clap::{Parser, Subcommand};
use colored::*;
use s2o_store::EventStore;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cybersiem")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.1.0")]
#[command(about = "S2O CyberLog SIEM: local event store reader (Phase 2 full SIEM)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberLog status
    Status {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Live real-time tail of the Aegis event stream
    Tail {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Filter by product (e.g. cyberwall, cyberedr, cyberdns)
        #[arg(long)]
        product: Option<String>,
        /// Filter by minimum severity (info, low, medium, high, critical)
        #[arg(long)]
        min_severity: Option<String>,
    },
    /// Display event store statistics and breakdown by severity and product
    Stats {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Query events with custom filters
    Query {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        search: Option<String>,
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Export recent events from local JSONL store
    Export {
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Display recent events from local JSONL store
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { event_log } => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "            SPLIT2OPS CYBERSIEM TELEMETRY HUB            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Event Store Path  : {}", event_log.display());
            if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                println!(" Total Ingested Events: {}", store.count()?.to_string().bold().green());
            } else {
                println!(" Total Ingested Events: {}", "0 (empty log)".yellow());
            }
            println!(" Stream Protocols  : JSONL / NDJSON / Syslog RFC 5424");
            println!("{}", "=========================================================".cyan());
        }
        Commands::Stats { event_log } => {
            if !event_log.exists() {
                println!("[cybersiem] event log is empty: {}", event_log.display());
                return Ok(());
            }

            let store = EventStore::open(&event_log)?;
            let events = store.recent(10000)?;

            let mut by_product: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            let mut by_severity: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

            for ev in &events {
                let p = format!("{:?}", ev.product);
                *by_product.entry(p).or_insert(0) += 1;
                let s = format!("{:?}", ev.severity);
                *by_severity.entry(s).or_insert(0) += 1;
            }

            println!("{}", "=========================================================".cyan());
            println!("{}", "            CyberSIEM Telemetry & Security Metrics       ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Total Analyzed Events: {}", events.len());
            println!("{}", "--- By Security Discipline ---".yellow());
            for (k, v) in by_product {
                println!("  {:<15} : {}", k, v);
            }
            println!("{}", "--- By Severity Level ---".yellow());
            for (k, v) in by_severity {
                let color_val = match k.to_lowercase().as_str() {
                    "critical" | "high" => v.to_string().red().bold(),
                    "medium" => v.to_string().yellow(),
                    _ => v.to_string().green(),
                };
                println!("  {:<15} : {}", k, color_val);
            }
            println!("{}", "=========================================================".cyan());
        }
        Commands::Tail { event_log, product, min_severity } => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "        CyberSIEM Live Telemetry Stream Follower         ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Following : {}", event_log.display());
            println!("{}", "Press Ctrl+C to stop...".yellow());
            println!("{}", "---------------------------------------------------------".cyan());

            let mut last_count = 0;
            if event_log.exists() {
                if let Ok(store) = EventStore::open(&event_log) {
                    last_count = store.count().unwrap_or(0);
                }
            }

            loop {
                if event_log.exists() {
                    if let Ok(store) = EventStore::open(&event_log) {
                        let current_count = store.count().unwrap_or(0);
                        if current_count > last_count {
                            let diff = current_count - last_count;
                            if let Ok(recent) = store.recent(diff) {
                                for ev in recent {
                                    if let Some(ref p) = product {
                                        if !format!("{:?}", ev.product).eq_ignore_ascii_case(p) {
                                            continue;
                                        }
                                    }
                                    if let Some(ref s) = min_severity {
                                        if s.eq_ignore_ascii_case("high") && ev.severity != s2o_schema::Severity::High && ev.severity != s2o_schema::Severity::Critical {
                                            continue;
                                        }
                                    }

                                    let sev_colored = match ev.severity {
                                        s2o_schema::Severity::Critical => "[CRITICAL]".red().bold(),
                                        s2o_schema::Severity::High => "[HIGH]".red(),
                                        s2o_schema::Severity::Medium => "[MEDIUM]".yellow(),
                                        s2o_schema::Severity::Low => "[LOW]".blue(),
                                        s2o_schema::Severity::Info => "[INFO]".green(),
                                    };

                                    println!(
                                        "{} [{}] {:?} -> {}",
                                        sev_colored,
                                        ev.ts.format("%H:%M:%S").to_string().cyan(),
                                        ev.product,
                                        ev.message
                                    );
                                }
                            }
                            last_count = current_count;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            }
        }
        Commands::Query { event_log, product, severity, search, limit } => {
            if !event_log.exists() {
                println!("[cybersiem] event store does not exist at {}", event_log.display());
                return Ok(());
            }

            let store = EventStore::open(&event_log)?;
            let events = store.recent(500)?;

            let filtered: Vec<&s2o_schema::AegisEvent> = events
                .iter()
                .filter(|ev| {
                    if let Some(ref p) = product {
                        if !format!("{:?}", ev.product).to_lowercase().contains(&p.to_lowercase()) {
                            return false;
                        }
                    }
                    if let Some(ref s) = severity {
                        if !format!("{:?}", ev.severity).to_lowercase().contains(&s.to_lowercase()) {
                            return false;
                        }
                    }
                    if let Some(ref q) = search {
                        if !ev.message.to_lowercase().contains(&q.to_lowercase()) {
                            return false;
                        }
                    }
                    true
                })
                .take(limit)
                .collect();

            println!("{}", "=========================================================".cyan());
            println!("{}", "           CyberSIEM Filtered Security Query             ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Matching Events: {}", filtered.len());
            for ev in filtered {
                let sev_colored = match ev.severity {
                    s2o_schema::Severity::Critical => "CRIT".red().bold(),
                    s2o_schema::Severity::High => "HIGH".red(),
                    s2o_schema::Severity::Medium => "MED ".yellow(),
                    s2o_schema::Severity::Low => "LOW ".blue(),
                    s2o_schema::Severity::Info => "INFO".green(),
                };
                println!(
                    "[{}] [{}] {:<12} | {}",
                    ev.ts.to_rfc3339().cyan(),
                    sev_colored,
                    format!("{:?}", ev.product),
                    ev.message
                );
            }
            println!("{}", "=========================================================".cyan());
        }
        Commands::Export { format, event_log, limit } => {
            if !event_log.exists() {
                eprintln!("[cybersiem] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
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
        Commands::Events { event_log, limit } => {
            if !event_log.exists() {
                println!("[cybersiem] no events yet — run `aegisd start` or `cyberedr watch` to seed the store.");
                return Ok(());
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "          CyberSIEM — recent Aegis events                ".bold().green());
            println!("{}", "=========================================================".cyan());
            if events.is_empty() {
                println!("(empty store)");
            }
            for ev in events {
                println!(
                    "[{}] [{:?}] {:?} -> {}",
                    ev.ts.to_rfc3339().cyan(),
                    ev.severity,
                    ev.product,
                    ev.message
                );
                println!("{}", "---------------------------------------------------------".cyan());
            }
        }
    }

    Ok(())
}
