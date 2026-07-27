//! S2O CyberDNS — DoH resolve, blocklist, local UDP proxy (Phase 2 shell).

mod blocklist;
mod serve;

use blocklist::{is_blocked, load_blocklist, normalize_domain, save_blocklist};
use clap::{Parser, Subcommand};
use colored::*;
use serde::Deserialize;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.3.0")]
#[command(about = "S2O CyberDNS Guard: DoH + blocklist + local UDP proxy", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/dns-blocklist.txt")]
    blocklist: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Resolve { domain: String },
    Block { domain: String },
    Unblock { domain: String },
    List,
    /// Local UDP DNS proxy (blocklist + DoH A answers)
    Serve {
        /// Prefer high ports (5353 is often blocked on Windows / Hyper-V)
        #[arg(short, long, default_value = "127.0.0.1:53553")]
        listen: String,
    },
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(default)]
    data: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DohResponse {
    #[allow(dead_code)]
    Status: u32,
    Answer: Option<Vec<DohAnswer>>,
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit(
    event_log: &Path,
    action: EventAction,
    severity: Severity,
    message: impl Into<String>,
    domain: &str,
) {
    if let Ok(store) = EventStore::open(event_log) {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::CyberDns,
            EventKind::Dns,
            action,
            severity,
            message,
        )
        .with_attr("domain", serde_json::json!(domain))
        .with_ioc(Ioc::Domain(normalize_domain(domain)));
        let _ = store.append(&ev);
    }
}

async fn doh_a_records(domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type=A");
    let client = reqwest::Client::new();
    let res = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(format!("DoH HTTP {}", res.status()).into());
    }
    let doh: DohResponse = res.json().await?;
    let mut ips = Vec::new();
    if let Some(answers) = doh.Answer {
        for ans in answers {
            if ans.record_type == 1 && !ans.data.is_empty() {
                ips.push(ans.data);
            }
        }
    }
    Ok(ips)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let set = load_blocklist(&cli.blocklist)?;
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "        S2O CyberDNS Guard (Phase 2 shell)               "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "DoH resolve + blocklist + local UDP proxy (serve)".green()
            );
            println!(
                " Not implemented   : {}",
                "DoT, system resolver takeover, full recursive".red()
            );
            println!(
                " Primary Resolver  : {}",
                "https://cloudflare-dns.com/dns-query".yellow()
            );
            println!(" Blocklist path    : {}", cli.blocklist.display());
            println!(" Blocked domains   : {}", set.len());
            println!(" Event log         : {}", cli.event_log.display());
            println!(
                " Proxy             : {}",
                "cyberdns serve --listen 127.0.0.1:53553".yellow()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::List => {
            let set = load_blocklist(&cli.blocklist)?;
            if set.is_empty() {
                println!("[cyberdns] blocklist empty ({})", cli.blocklist.display());
            } else {
                for d in &set {
                    println!("{d}");
                }
            }
        }
        Commands::Block { domain } => {
            let d = normalize_domain(&domain);
            if d.is_empty() {
                eprintln!("[cyberdns] empty domain");
                std::process::exit(2);
            }
            let mut set = load_blocklist(&cli.blocklist)?;
            if set.insert(d.clone()) {
                save_blocklist(&cli.blocklist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] blocked {d} ({} total)", set.len())
                        .red()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::Medium,
                    format!("domain added to blocklist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] already blocked: {d}");
            }
        }
        Commands::Unblock { domain } => {
            let d = normalize_domain(&domain);
            let mut set = load_blocklist(&cli.blocklist)?;
            if set.remove(&d) {
                save_blocklist(&cli.blocklist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] unblocked {d}").green().bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("domain removed from blocklist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] not in blocklist: {d}");
            }
        }
        Commands::Resolve { domain } => {
            let d = normalize_domain(&domain);
            let set = load_blocklist(&cli.blocklist)?;
            if is_blocked(&set, &d) {
                println!(
                    "{}",
                    format!("[CYBERDNS] BLOCKED by local blocklist: {d}")
                        .red()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::High,
                    format!("resolve denied (blocklist): {d}"),
                    &d,
                );
                std::process::exit(3);
            }

            println!(
                "{}",
                format!("[CYBERDNS] Resolving '{d}' via Encrypted DoH...").cyan()
            );
            match doh_a_records(&d).await {
                Ok(ips) if !ips.is_empty() => {
                    for ip in &ips {
                        println!(" Resolved IP   : {}", ip.green().bold());
                    }
                    emit(
                        &cli.event_log,
                        EventAction::Allowed,
                        Severity::Info,
                        format!("resolve ok: {d}"),
                        &d,
                    );
                }
                Ok(_) => {
                    println!("{}", "NXDOMAIN / no A records.".yellow());
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Low,
                        format!("resolve nxdomain: {d}"),
                        &d,
                    );
                }
                Err(e) => {
                    eprintln!("{}", format!("DoH error: {e}").red());
                    std::process::exit(1);
                }
            }
        }
        Commands::Serve { listen } => {
            serve::run_proxy(&listen, &cli.blocklist, &cli.event_log).await?;
        }
    }

    Ok(())
}
