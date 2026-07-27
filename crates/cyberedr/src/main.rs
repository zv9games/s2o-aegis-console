//! S2O CyberEDR — IP Helper TCP telemetry + events (Phase 2 shell).

use clap::{Parser, Subcommand};
use colored::*;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberedr")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O CyberEDR: userspace TCP telemetry (Phase 2 shell)", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// Active TCP connections (IP Helper)
    Processes {
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// Also write a summary event
        #[arg(long, default_value_t = true)]
        emit_event: bool,
    },
    Alerts,
    Trace,
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit(
    event_log: &Path,
    kind: EventKind,
    action: EventAction,
    severity: Severity,
    message: impl Into<String>,
    attrs: &[(&str, serde_json::Value)],
) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::CyberEdr,
            kind,
            action,
            severity,
            message,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, v.clone());
        }
        let _ = store.append(&ev);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "        S2O CyberEDR (Phase 2 shell)                     "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "TCP table via IP Helper; summary events".green()
            );
            println!(
                " Not implemented   : {}",
                "ETW hooks, behavioral ML, alert engine".red()
            );
            println!(
                " Kernel hooks      : {}",
                "NONE ATTACHED".red().bold()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            emit(
                &cli.event_log,
                EventKind::Health,
                EventAction::Observed,
                Severity::Info,
                "cyberedr status (userspace only)",
                &[("hooks", serde_json::json!("none"))],
            );
        }
        Commands::Processes { limit, emit_event } => {
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;

            let established = conns
                .iter()
                .filter(|c| c.state.eq_ignore_ascii_case("ESTABLISHED"))
                .count();
            let listen = conns
                .iter()
                .filter(|c| c.state.eq_ignore_ascii_case("LISTEN"))
                .count();

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       Active TCP connections (IP Helper telemetry)      "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            for c in conns.iter().take(limit) {
                println!(
                    " PID {:<6} | {:<15}:{} -> {:<15}:{} [{}]",
                    c.pid,
                    c.local_addr,
                    c.local_port,
                    c.remote_addr,
                    c.remote_port,
                    c.state.bold()
                );
            }
            println!(
                "{}",
                "---------------------------------------------------------".cyan()
            );
            println!(
                " Total: {}  ESTABLISHED: {}  LISTEN: {}  (showing up to {})",
                conns.len(),
                established,
                listen,
                limit
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );

            if emit_event {
                emit(
                    &cli.event_log,
                    EventKind::NetFlow,
                    EventAction::Observed,
                    Severity::Info,
                    format!(
                        "tcp snapshot total={} established={} listen={}",
                        conns.len(),
                        established,
                        listen
                    ),
                    &[
                        ("total", serde_json::json!(conns.len())),
                        ("established", serde_json::json!(established)),
                        ("listen", serde_json::json!(listen)),
                    ],
                );
            }
        }
        Commands::Alerts => {
            println!(
                "{}",
                "[cyberedr] alert engine not implemented (Phase 2).".yellow()
            );
            println!("No behavioral alerts stored.");
        }
        Commands::Trace => {
            eprintln!("[cyberedr] ETW/eBPF live trace not implemented (Phase 2).");
            std::process::exit(2);
        }
    }

    Ok(())
}
