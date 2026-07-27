//! S2O Aegis master daemon — Phase 1 foundation front door.
//!
//! Honesty: only engines that actually work report live data.
//! Demo labels require AEGIS_DEMO=1.

use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::{
    apply_policy, collect_platform_status, create_firewall_engine, demo_mode, host_id,
    load_policy_file, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{
    AegisEvent, EventAction, EventKind, HealthState, ProductId, Severity, SCHEMA_VERSION,
};
use s2o_store::EventStore;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aegisd")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.1.0")]
#[command(about = "S2O Aegis Platform: suite kernel / cyber-ops orchestrator (Phase 1 foundation)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Aegis daemon (Cyberwall probe + event store)
    Start {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Display platform status (honest matrix for all 9 worlds)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Apply a policy document (v0: firewall intents)
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Reload policy (placeholder — use `policy apply`)
    Reload,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Apply a JSON policy file through the kernel
    Apply {
        /// Path to policy JSON
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Print an example policy document
    Example {
        /// wall | edge
        #[arg(long, default_value = "edge")]
        kind: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Start { event_log } => {
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "     S2O AEGIS MASTER DAEMON  (Phase 1 foundation)       "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Kernel version    : {}", KERNEL_VERSION);
            println!(" Schema version    : {}", SCHEMA_VERSION);
            println!(" Phase             : {}", PHASE_LABEL);
            println!(" Tier ceiling      : {}", TIER_CEILING.as_str());
            println!(
                " Demo mode         : {}",
                if demo_mode() {
                    "ON (AEGIS_DEMO)".yellow().to_string()
                } else {
                    "OFF".green().to_string()
                }
            );

            let store = EventStore::open(&event_log)?;
            println!(" Event store       : {}", store.path().display());
            println!(" Host id           : {}", host_id());

            let status = collect_platform_status(&fw).await;
            for (i, m) in status.modules.iter().enumerate() {
                let label = match m.state {
                    HealthState::Implemented => m.state.as_str().green().bold().to_string(),
                    HealthState::Partial => m.state.as_str().yellow().to_string(),
                    HealthState::Demo => m.state.as_str().yellow().bold().to_string(),
                    HealthState::Degraded => m.state.as_str().red().bold().to_string(),
                    _ => m.state.as_str().red().to_string(),
                };
                println!(
                    "[AEGISD] [{}/9] {} ... {}",
                    i + 1,
                    m.name,
                    label
                );
                println!("         {}", m.detail);
            }

            let wall = status
                .modules
                .iter()
                .find(|m| m.product == ProductId::Cyberwall);
            let ev = AegisEvent::new(
                host_id(),
                ProductId::Aegis,
                EventKind::Health,
                EventAction::Observed,
                Severity::Info,
                format!(
                    "aegisd start; phase={PHASE_LABEL}; wall={}",
                    wall.map(|w| w.state.as_str()).unwrap_or("unknown")
                ),
            )
            .with_attr("phase", serde_json::json!(PHASE_LABEL))
            .with_attr("tier_ceiling", serde_json::json!(TIER_CEILING.as_str()))
            .with_attr(
                "wall_detail",
                serde_json::json!(wall.map(|w| w.detail.as_str()).unwrap_or("")),
            );
            store.append(&ev)?;
            println!("[AEGISD] health event written to store");

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "  Phase 1: kernel + 9-world matrix + Cyberwall T0. Ctrl+C to stop."
                    .bold()
                    .yellow()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            tokio::signal::ctrl_c().await?;
            println!("\n[AEGISD] shutdown complete.");
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
                    "    S2O AEGIS PLATFORM STATUS (honest)                   "
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
                    println!(" Module  : {}", m.name.bold());
                    println!(" State   : {}", state_col);
                    println!(" Detail  : {}", m.detail);
                    if let Some(b) = &m.backend {
                        println!(" Backend : {}", b);
                    }
                    println!(
                        "{}",
                        "---------------------------------------------------------".cyan()
                    );
                }
            }
        }
        Commands::Policy { command } => match command {
            PolicyCmd::Example { kind } => {
                let doc = if kind.eq_ignore_ascii_case("wall") {
                    s2o_schema::PolicyDocument::example_wall_enable()
                } else {
                    s2o_schema::PolicyDocument::example_edge_pack()
                };
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            PolicyCmd::Apply { path, event_log } => {
                println!("[aegisd] loading policy {}", path.display());
                let doc = load_policy_file(&path)?;
                let store = Arc::new(EventStore::open(&event_log)?);
                let result = apply_policy(&doc, &fw, Some(store)).await?;
                if result.ok {
                    println!(
                        "{}",
                        format!("[aegisd] policy OK: {}", result.policy_name)
                            .green()
                            .bold()
                    );
                } else {
                    println!(
                        "{}",
                        format!("[aegisd] policy incomplete/failed: {}", result.policy_name)
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
        Commands::Reload => {
            eprintln!(
                "{}",
                "[AEGISD] Reload: use `aegisd policy apply <file>` (no daemon-held policy file yet)."
                    .yellow()
                    .bold()
            );
            std::process::exit(2);
        }
    }

    Ok(())
}
