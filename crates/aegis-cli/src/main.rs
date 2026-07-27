//! `aegis` — single operator front door for the suite kernel.

use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::{
    apply_policy, collect_platform_status, create_firewall_engine, demo_mode, host_id,
    load_policy_file, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{HealthState, PolicyDocument, SCHEMA_VERSION};
use s2o_store::EventStore;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aegis")]
#[command(author = "Split2ops Software")]
#[command(version = "0.1.0")]
#[command(about = "S2O Aegis operator CLI — one front door to the suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print suite / kernel versions
    Version,
    /// Honest platform matrix (same as aegisd status)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Kernel / host doctor
    Doctor,
    /// Policy operations
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Recent events from the local store
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Rotate the local event log now (archives to events.jsonl.1 …)
    Rotate {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5)]
        keep: usize,
    },
    /// Run a product CLI if on PATH / target/debug (best-effort shim)
    Run {
        /// Product binary: cyberwall, cyberdns, cyberdefender, cyberedr, ...
        product: String,
        /// Args forwarded to the product
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Apply {
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    Example {
        /// wall | edge
        #[arg(long, default_value = "edge")]
        kind: String,
    },
}

fn find_product_bin(name: &str) -> Option<PathBuf> {
    let suffixes = ["", ".exe"];
    let candidates = [
        format!("target/debug/{name}"),
        format!("target/release/{name}"),
        name.to_string(),
    ];
    for c in &candidates {
        for suf in &suffixes {
            let p = PathBuf::from(format!("{c}{suf}"));
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Version => {
            println!("aegis-cli          0.1.0");
            println!("s2o-kernel         {KERNEL_VERSION}");
            println!("s2o-schema         {SCHEMA_VERSION}");
            println!("phase              {PHASE_LABEL}");
            println!("tier_ceiling       {}", TIER_CEILING.as_str());
        }
        Commands::Status { json } => {
            let status = collect_platform_status(&fw).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "    S2O AEGIS  (operator front door)                      "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Phase        : {}", status.phase);
                println!(" OS           : {}", status.os.as_str());
                println!(" Tier ceiling : {}", status.tier_ceiling.as_str());
                println!(" Host         : {}", status.host_id);
                println!(
                    " Demo mode    : {}",
                    if status.demo_mode { "ON" } else { "OFF" }
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                for m in &status.modules {
                    let state_col = match m.state {
                        HealthState::Implemented => m.state.as_str().green().bold(),
                        HealthState::Partial => m.state.as_str().yellow().bold(),
                        HealthState::Demo => m.state.as_str().yellow().bold(),
                        HealthState::Degraded => m.state.as_str().red().bold(),
                        _ => m.state.as_str().red(),
                    };
                    println!(" {:<16} {}", m.id.bold(), state_col);
                    println!("                  {}", m.detail);
                }
            }
        }
        Commands::Doctor => {
            println!("{}", "Aegis doctor".bold().green());
            println!(" kernel       : {KERNEL_VERSION}");
            println!(" schema       : {SCHEMA_VERSION}");
            println!(" phase        : {PHASE_LABEL}");
            println!(" tier ceiling : {}", TIER_CEILING.as_str());
            println!(" host_id      : {}", host_id());
            println!(
                " demo_mode    : {}",
                if demo_mode() { "ON" } else { "OFF" }
            );
            match collect_platform_status(&fw).await.modules.iter().find(|m| m.id == "cyberwall") {
                Some(m) => println!(" cyberwall    : {} — {}", m.state.as_str(), m.detail),
                None => println!(" cyberwall    : missing from matrix"),
            }
            let event_log = PathBuf::from(".aegis/events.jsonl");
            if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                println!(
                    " event_log    : {} ({} events)",
                    event_log.display(),
                    store.count()?
                );
            } else {
                println!(
                    " event_log    : {} (missing)",
                    event_log.display()
                );
            }
            let bl = PathBuf::from(".aegis/dns-blocklist.txt");
            println!(
                " dns_blocklist: {} ({})",
                bl.display(),
                if bl.exists() { "present" } else { "missing" }
            );
        }
        Commands::Policy { command } => match command {
            PolicyCmd::Example { kind } => {
                let doc = if kind.eq_ignore_ascii_case("wall") {
                    PolicyDocument::example_wall_enable()
                } else {
                    PolicyDocument::example_edge_pack()
                };
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            PolicyCmd::Apply { path, event_log } => {
                let doc = load_policy_file(&path)?;
                let store = Arc::new(EventStore::open(&event_log)?);
                let result = apply_policy(&doc, &fw, Some(store)).await?;
                if result.ok {
                    println!(
                        "{}",
                        format!("[aegis] policy OK: {}", result.policy_name)
                            .green()
                            .bold()
                    );
                } else {
                    println!(
                        "{}",
                        format!("[aegis] policy incomplete: {}", result.policy_name)
                            .yellow()
                            .bold()
                    );
                }
                for a in &result.applied {
                    println!("  applied : {}", a.green());
                }
                for s in &result.skipped {
                    println!("  skipped : {}", s.dimmed());
                }
                for e in &result.errors {
                    println!("  error   : {}", e.red());
                }
                if !result.ok {
                    std::process::exit(1);
                }
            }
        },
        Commands::Events { event_log, limit } => {
            if !event_log.exists() {
                eprintln!("[aegis] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        Commands::Rotate { event_log, keep } => {
            let store = EventStore::open_with_rotation(&event_log, 0, keep)?;
            let before = store.len_bytes().unwrap_or(0);
            store.rotate()?;
            println!(
                "[aegis] rotated {} (was {} bytes) → {}.1",
                event_log.display(),
                before,
                event_log.display()
            );
        }
        Commands::Run { product, args } => {
            let bin = find_product_bin(&product).ok_or_else(|| {
                format!(
                    "product binary '{product}' not found (build with cargo build -p {product} or similar)"
                )
            })?;
            let status = Command::new(&bin).args(&args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}
