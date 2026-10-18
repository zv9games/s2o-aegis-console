//! S2O Aegis master daemon.
//!
//! The daemon itself probes the OS firewall/Defender state and live TCP
//! sockets, writes a health event, and serves `ping`/`status` over local IPC.
//! The other pillars are separate CLIs that the daemon does not run or
//! supervise; `status` says so instead of reporting them as ONLINE.

use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::FirewallEngine;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity, SCHEMA_VERSION};
use s2o_store::EventStore;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aegisd")]
#[command(author = "Split2ops Software <support@zv9games.org>")]
#[command(version = "0.1.0")]
#[command(about = "S2O Aegis Platform: unified cyber-ops orchestrator (Phase 0: Cyberwall real)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Aegis daemon (real Cyberwall probe + event store)
    Start {
        /// Directory for local event store (JSONL)
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Display platform status (honest: only implemented engines report live data)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Reload policy (NOT IMPLEMENTED: there is no policy engine yet)
    Reload,
}

#[derive(serde::Serialize)]
struct ModuleStatus {
    id: &'static str,
    name: &'static str,
    /// LIVE (probed by aegisd) | CLI (works via its own CLI, not supervised)
    /// | PARTIAL | NOT_IMPLEMENTED | OFFLINE | WARNING
    state: &'static str,
    detail: String,
}

fn module_table(st: &cyberwall_core::FirewallStatus, conns: usize) -> Vec<ModuleStatus> {
    vec![
        ModuleStatus {
            id: "cyberwall",
            name: "S2O Cyberwall",
            state: if st.enabled { "LIVE" } else { "OFFLINE" },
            detail: format!(
                "OS firewall enabled={} private={} public={} domain={} via {}; declarative apply_policy not implemented",
                st.enabled, st.profile_private, st.profile_public, st.profile_domain, st.backend_driver
            ),
        },
        ModuleStatus {
            id: "cybermesh",
            name: "S2O CyberMesh",
            state: "PARTIAL",
            detail: "Generates X25519 keys and WireGuard config files; does not bring up tunnels or exchange peers".into(),
        },
        ModuleStatus {
            id: "cyberdefender",
            name: "S2O CyberDefender",
            state: if st.defender_active { "LIVE" } else { "WARNING" },
            detail: format!(
                "Microsoft Defender AntivirusEnabled={}; SHA-256 hash scan is on demand (cyberdefender scan)",
                st.defender_active
            ),
        },
        ModuleStatus {
            id: "cyberedr",
            name: "S2O CyberEDR",
            state: "LIVE",
            detail: format!("{conns} TCP sockets via {}", s2o_platform::telemetry::telemetry_source()),
        },
        ModuleStatus {
            id: "cybersiem",
            name: "S2O CyberSIEM",
            state: "CLI",
            detail: "Local JSONL event store (.aegis/events.jsonl); query/follow via cybersiem".into(),
        },
        ModuleStatus {
            id: "cyberintel",
            name: "S2O CyberIntel",
            state: "CLI",
            detail: "URLhaus feed pulled on demand into a local JSON DB (cyberintel)".into(),
        },
        ModuleStatus {
            id: "cyberdns",
            name: "S2O CyberDNS",
            state: "CLI",
            detail: "DoH lookups + local blocklist; UDP forwarder only while `cyberdns serve` runs".into(),
        },
        ModuleStatus {
            id: "cyberid",
            name: "S2O CyberID",
            state: "CLI",
            detail: "4-check posture score + Ed25519-signed token on demand (cyberid posture / attest)".into(),
        },
        ModuleStatus {
            id: "cyberztna",
            name: "S2O CyberZTNA",
            state: "NOT_IMPLEMENTED",
            detail: "Stores route definitions only; no proxy or enforcement exists yet".into(),
        },
    ]
}

fn state_colored(state: &str) -> ColoredString {
    match state {
        "LIVE" => state.green().bold(),
        "CLI" => state.cyan(),
        "PARTIAL" | "WARNING" => state.yellow().bold(),
        _ => state.red(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { event_log } => {
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "     S2O AEGIS MASTER DAEMON  (Phase 0 spine)            "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Schema version    : {}", SCHEMA_VERSION);
            let store = EventStore::open(&event_log)?;
            println!(" Event store       : {}", store.path().display());

            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;

            let conns =
                tokio::task::spawn_blocking(s2o_platform::telemetry::get_active_tcp_connections)
                    .await
                    .unwrap_or_default();
            for (idx, m) in module_table(&st, conns.len()).iter().enumerate() {
                println!(
                    "[AEGISD] [{}/9] {:<18} {}  {}",
                    idx + 1,
                    m.name,
                    state_colored(m.state),
                    m.detail
                );
            }

            let host_id = hostname();
            let ev = AegisEvent::new(
                host_id,
                ProductId::Aegis,
                EventKind::Health,
                EventAction::Observed,
                Severity::Info,
                format!(
                    "aegisd started. Cyberwall enabled={}, Defender={}",
                    st.enabled, st.defender_active
                ),
            )
            .with_attr("cyberwall_enabled", serde_json::json!(st.enabled))
            .with_attr("backend", serde_json::json!(st.backend_driver));
            store.append(&ev)?;
            println!("[AEGISD]       -> Master health event committed to store");

            // Spawn the Universal IPC Server (Named Pipe on Windows / Unix Domain Socket on Unix)
            let ipc_server = std::sync::Arc::new(s2o_bus::AegisIpcServer::new(
                |req: s2o_bus::IpcRequest| async move {
                    match req.method.as_str() {
                        "status" => {
                            let fw = WindowsFirewallEngine::new();
                            let st =
                                fw.get_status()
                                    .await
                                    .unwrap_or(cyberwall_core::FirewallStatus {
                                        enabled: false,
                                        outbound_blocked: false,
                                        defender_active: false,
                                        profile_private: false,
                                        profile_public: false,
                                        profile_domain: false,
                                        platform: "Windows".into(),
                                        backend_driver: "".into(),
                                        substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
                                    });
                            s2o_bus::IpcResponse::ok(
                                req.id,
                                serde_json::to_value(&st).unwrap_or_default(),
                            )
                        }
                        "ping" => {
                            s2o_bus::IpcResponse::ok(req.id, serde_json::json!({ "pong": true }))
                        }
                        "reload" => s2o_bus::IpcResponse::err(
                            req.id,
                            "reload not implemented: no policy engine yet".to_string(),
                        ),
                        unknown => s2o_bus::IpcResponse::err(
                            req.id,
                            format!("Unknown RPC method: {unknown}"),
                        ),
                    }
                },
            ));

            #[cfg(windows)]
            {
                let srv = ipc_server.clone();
                tokio::spawn(async move {
                    if let Err(e) = srv.run_named_pipe().await {
                        eprintln!("[AEGISD] IPC named pipe server error: {e}");
                    }
                });
                println!(
                    "[AEGISD]       -> IPC Named Pipe active at {}",
                    s2o_bus::AEGIS_PIPE_NAME.cyan()
                );
            }

            #[cfg(unix)]
            {
                let srv = ipc_server.clone();
                tokio::spawn(async move {
                    if let Err(e) = srv.run_unix_socket().await {
                        eprintln!("[AEGISD] IPC Unix socket server error: {e}");
                    }
                });
                println!(
                    "[AEGISD]       -> IPC Unix Socket active at {}",
                    s2o_bus::AEGIS_UNIX_SOCKET.cyan()
                );
            }

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "  aegisd running (IPC: ping, status). Other pillars run via their own CLIs."
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!("\nPress Ctrl+C to stop...");
            tokio::signal::ctrl_c().await?;
            println!("\n[AEGISD] shutdown complete.");
        }
        Commands::Status { json } => {
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;

            let conns = tokio::task::spawn_blocking(|| {
                s2o_platform::telemetry::get_active_tcp_connections()
            })
            .await
            .unwrap_or_default();

            let modules = module_table(&st, conns.len());

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "platform": "S2O Aegis",
                        "schema_version": SCHEMA_VERSION,
                        "modules": modules,
                        "cyberwall": st,
                        "active_sockets": conns.len(),
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "       S2O AEGIS ENTERPRISE MATRIX STATUS          "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                for (idx, m) in modules.iter().enumerate() {
                    let state_col = state_colored(m.state);
                    println!(" [{}/9] {:<24} : {}", idx + 1, m.name.bold(), state_col);
                    println!("       Detail : {}", m.detail);
                    println!(
                        "{}",
                        "---------------------------------------------------------".cyan()
                    );
                }
            }
        }
        Commands::Reload => {
            eprintln!(
                "{}",
                "[AEGISD] reload: NOT IMPLEMENTED (there is no policy engine to reload yet)".red()
            );
            std::process::exit(2);
        }
    }

    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}
