//! S2O CyberDNS — DoH resolve, blocklist, local UDP proxy, system DNS bind.

mod blocklist;
mod serve;
mod system_dns;

use blocklist::{is_blocked, load_blocklist, normalize_domain, save_blocklist};
use clap::{Parser, Subcommand};
use colored::*;
use serde::Deserialize;
use s2o_ioc::IocStore;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::path::{Path, PathBuf};

fn domain_denied(blocklist: &Path, ioc_path: &Path, domain: &str) -> Option<&'static str> {
    if let Ok(set) = load_blocklist(blocklist) {
        if is_blocked(&set, domain) {
            return Some("blocklist");
        }
    }
    if let Ok(store) = IocStore::load(ioc_path) {
        if store.is_domain_blocked(domain).is_some() {
            return Some("threatgrid_ioc");
        }
    }
    None
}

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.4.0")]
#[command(about = "S2O CyberDNS Guard: DoH + blocklist + local UDP proxy + system DNS", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/dns-blocklist.txt")]
    blocklist: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    /// ThreatGrid local IOC store (optional)
    #[arg(long, global = true, default_value = ".aegis/ioc-store.json")]
    ioc_store: PathBuf,

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
    /// Point OS resolver at local proxy / restore (hijack-lite T0)
    SystemDns {
        #[command(subcommand)]
        command: SystemDnsCmd,
    },
}

#[derive(Subcommand)]
enum SystemDnsCmd {
    /// Show current system DNS configuration
    Show,
    /// Backup current DNS then set primary to SERVER (default 127.0.0.1)
    Set {
        #[arg(long, default_value = "127.0.0.1")]
        server: String,
        /// Windows interface name (default: all interfaces)
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
    },
    /// Restore DNS from backup file
    Restore {
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
    },
    /// Only write backup without changing DNS
    Backup {
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
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
            let ioc_n = IocStore::load(&cli.ioc_store)
                .map(|s| s.entries.len())
                .unwrap_or(0);
            println!(
                " Implemented       : {}",
                "DoH + blocklist + IOC + UDP proxy + system-dns bind".green()
            );
            println!(" IOC store         : {} ({} entries)", cli.ioc_store.display(), ioc_n);
            println!(
                " Not implemented   : {}",
                "DoT, full recursive, transparent redirector".red()
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
            if let Some(reason) = domain_denied(&cli.blocklist, &cli.ioc_store, &d) {
                println!(
                    "{}",
                    format!("[CYBERDNS] BLOCKED by {reason}: {d}")
                        .red()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::High,
                    format!("resolve denied ({reason}): {d}"),
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
            serve::run_proxy(&listen, &cli.blocklist, &cli.ioc_store, &cli.event_log).await?;
        }
        Commands::SystemDns { command } => match command {
            SystemDnsCmd::Show => match system_dns::show_current() {
                Ok(s) => print!("{s}"),
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
            SystemDnsCmd::Backup { backup } => match system_dns::backup_current(&backup) {
                Ok(b) => {
                    println!(
                        "[cyberdns] backup wrote {} ({} server(s), {} iface(s))",
                        backup.display(),
                        b.servers.len(),
                        b.interfaces.len()
                    );
                }
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
            SystemDnsCmd::Set {
                server,
                interface,
                backup,
            } => {
                println!(
                    "{}",
                    "[cyberdns] system-dns set requires elevation on Windows (Admin) / root on Linux"
                        .yellow()
                );
                match system_dns::set_system_dns(&server, interface.as_deref(), &backup) {
                    Ok(msg) => {
                        println!("{}", format!("[cyberdns] {msg}").green().bold());
                        println!("Start proxy: cyberdns serve --listen 127.0.0.1:53  (or map 53→53553)");
                        println!("Note: many OS stacks need port 53; serve on 53553 + portproxy if needed.");
                        emit(
                            &cli.event_log,
                            EventAction::Observed,
                            Severity::High,
                            format!("system dns set server={server}"),
                            &server,
                        );
                    }
                    Err(e) => {
                        eprintln!("[cyberdns] {e}");
                        std::process::exit(1);
                    }
                }
            }
            SystemDnsCmd::Restore { backup } => match system_dns::restore_system_dns(&backup) {
                Ok(msg) => {
                    println!("{}", format!("[cyberdns] {msg}").green().bold());
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Medium,
                        "system dns restored from backup",
                        "restore",
                    );
                }
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
        },
    }

    Ok(())
}
