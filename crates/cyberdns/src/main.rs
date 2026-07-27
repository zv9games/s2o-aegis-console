//! S2O CyberDNS — DoH resolve + persistent local blocklist (Phase 2 shell).

use clap::{Parser, Subcommand};
use colored::*;
use serde::Deserialize;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O CyberDNS Guard: DoH resolver + local blocklist (Phase 2 shell)", long_about = None)]
struct Cli {
    /// Blocklist file (one domain per line)
    #[arg(long, global = true, default_value = ".aegis/dns-blocklist.txt")]
    blocklist: PathBuf,

    /// Event log for Aegis events
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberDNS status and blocklist metrics
    Status,
    /// Resolve a domain over DoH (blocked domains are denied)
    Resolve {
        domain: String,
    },
    /// Add a domain to the local blocklist
    Block {
        domain: String,
    },
    /// Remove a domain from the local blocklist
    Unblock {
        domain: String,
    },
    /// List blocked domains
    List,
    /// Local proxy serve (not production yet)
    Serve {
        #[arg(short, long, default_value = "127.0.0.1:5353")]
        listen: String,
    },
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    name: String,
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
    writeln!(file, "# S2O CyberDNS local blocklist")?;
    for d in set {
        writeln!(file, "{d}")?;
    }
    Ok(())
}

fn is_blocked(set: &BTreeSet<String>, domain: &str) -> bool {
    let d = normalize_domain(domain);
    if set.contains(&d) {
        return true;
    }
    // suffix match: block evil.com also blocks a.evil.com
    for b in set {
        if d == *b || d.ends_with(&format!(".{b}")) {
            return true;
        }
    }
    false
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
                "DoH resolve + persistent file blocklist".green()
            );
            println!(
                " Not implemented   : {}",
                "local recursive proxy serve, DoT".red()
            );
            println!(
                " Primary Resolver  : {}",
                "https://cloudflare-dns.com/dns-query".yellow()
            );
            println!(" Blocklist path    : {}", cli.blocklist.display());
            println!(" Blocked domains   : {}", set.len());
            println!(
                " Event log         : {}",
                cli.event_log.display()
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

            let url = format!("https://cloudflare-dns.com/dns-query?name={d}&type=A");
            let client = reqwest::Client::new();
            let res = client
                .get(&url)
                .header("accept", "application/dns-json")
                .send()
                .await?;

            if res.status().is_success() {
                let doh: DohResponse = res.json().await?;
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                if let Some(answers) = doh.Answer {
                    for ans in answers {
                        println!(" Domain Record : {}", ans.name.bold());
                        println!(" Type Code     : {}", ans.record_type);
                        println!(" Resolved IP   : {}", ans.data.green().bold());
                        println!(
                            "{}",
                            "---------------------------------------------------------".cyan()
                        );
                    }
                    emit(
                        &cli.event_log,
                        EventAction::Allowed,
                        Severity::Info,
                        format!("resolve ok: {d}"),
                        &d,
                    );
                } else {
                    println!(
                        "{}",
                        "NXDOMAIN: No DNS records found for this target.".yellow()
                    );
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Low,
                        format!("resolve nxdomain: {d}"),
                        &d,
                    );
                }
            } else {
                println!("{}", format!("DoH HTTP Error: {}", res.status()).red());
                std::process::exit(1);
            }
        }
        Commands::Serve { listen } => {
            eprintln!(
                "[cyberdns] local proxy serve not implemented (requested listen={listen})."
            );
            eprintln!("Blocklist + DoH resolve are live; proxy ships later in Phase 2.");
            std::process::exit(2);
        }
    }

    Ok(())
}
