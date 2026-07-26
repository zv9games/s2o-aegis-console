//! S2O Aegis master daemon — Phase 0 honesty:
//! only Cyberwall is a real engine. Other products report NOT_IMPLEMENTED
//! unless AEGIS_DEMO=1 is set (explicit demo mode).

use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::FirewallEngine;
use s2o_schema::{
    AegisEvent, EventAction, EventKind, ProductId, Severity, SCHEMA_VERSION,
};
use s2o_store::EventStore;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aegisd")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
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
    /// Reload policy (not yet implemented)
    Reload,
}

fn demo_mode() -> bool {
    std::env::var("AEGIS_DEMO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { event_log } => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "     S2O AEGIS MASTER DAEMON  (Phase 0 spine)            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Schema version    : {}", SCHEMA_VERSION);
            println!(" Demo mode         : {}", if demo_mode() { "ON (AEGIS_DEMO)".yellow() } else { "OFF".green() });

            let store = EventStore::open(&event_log)?;
            println!(" Event store       : {}", store.path().display());

            println!("[AEGISD] [1/9] Cyberwall Engine (COM policy)...");
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;
            let line = if st.enabled {
                format!(
                    "ONLINE private={} public={} domain={}",
                    st.profile_private, st.profile_public, st.profile_domain
                )
            } else {
                "OFFLINE / disabled on interactive profiles".to_string()
            };
            println!(
                "[AEGISD]       -> {}",
                if st.enabled {
                    line.green().bold().to_string()
                } else {
                    line.red().to_string()
                }
            );

            let host_id = hostname();
            let ev = AegisEvent::new(
                host_id,
                ProductId::Aegis,
                EventKind::Health,
                EventAction::Observed,
                Severity::Info,
                format!(
                    "aegisd start; cyberwall enabled={} defender={}",
                    st.enabled, st.defender_active
                ),
            )
            .with_attr("cyberwall_enabled", serde_json::json!(st.enabled))
            .with_attr("backend", serde_json::json!(st.backend_driver));
            store.append(&ev)?;
            println!("[AEGISD]       -> health event written to store");

            println!("[AEGISD] [2/9] CyberMesh ............ {}", stub_label("Phase 3"));
            println!("[AEGISD] [3/9] CyberDefender ........ {}", stub_label("Phase 1"));
            println!("[AEGISD] [4/9] CyberEDR ............. {}", stub_label("Phase 2"));
            println!("[AEGISD] [5/9] CyberLog ............. {}", stub_label("Phase 2"));
            println!("[AEGISD] [6/9] ThreatGrid ........... {}", stub_label("Phase 2"));
            println!("[AEGISD] [7/9] CyberDNS ............. {}", stub_label("Phase 1"));
            println!("[AEGISD] [8/9] CyberID .............. {}", stub_label("Phase 2/3"));
            println!("[AEGISD] [9/9] Gate (ZTNA) .......... {}", stub_label("Phase 3"));

            println!("{}", "=========================================================".cyan());
            println!(
                "{}",
                "  Phase 0: spine live (Cyberwall + event store). Other engines pending."
                    .bold()
                    .yellow()
            );
            println!("{}", "=========================================================".cyan());
            println!("\nPress Ctrl+C to stop...");
            tokio::signal::ctrl_c().await?;
            println!("\n[AEGISD] shutdown complete.");
        }
        Commands::Status { json } => {
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;

            #[derive(serde::Serialize)]
            struct ModuleStatus {
                id: &'static str,
                name: &'static str,
                state: &'static str,
                detail: String,
            }

            let modules = vec![
                ModuleStatus {
                    id: "cyberwall",
                    name: "S2O Cyberwall",
                    state: "implemented",
                    detail: format!(
                        "enabled={} private={} public={} domain={} defender={}",
                        st.enabled,
                        st.profile_private,
                        st.profile_public,
                        st.profile_domain,
                        st.defender_active
                    ),
                },
                ModuleStatus {
                    id: "cybermesh",
                    name: "S2O CyberMesh",
                    state: stub_state(),
                    detail: "not implemented (Phase 3)".into(),
                },
                ModuleStatus {
                    id: "cyberdefender",
                    name: "S2O CyberDefender",
                    state: stub_state(),
                    detail: "not implemented (Phase 1); net_lib Defender hooks exist".into(),
                },
                ModuleStatus {
                    id: "cyberedr",
                    name: "S2O CyberEDR",
                    state: stub_state(),
                    detail: "not implemented (Phase 2)".into(),
                },
                ModuleStatus {
                    id: "cybersiem",
                    name: "S2O CyberLog",
                    state: stub_state(),
                    detail: "not implemented (Phase 2); s2o-store/schema ready".into(),
                },
                ModuleStatus {
                    id: "cyberintel",
                    name: "S2O ThreatGrid",
                    state: stub_state(),
                    detail: "not implemented (Phase 2)".into(),
                },
                ModuleStatus {
                    id: "cyberdns",
                    name: "S2O CyberDNS",
                    state: stub_state(),
                    detail: "partial CLI DoH resolve may work; proxy not production".into(),
                },
                ModuleStatus {
                    id: "cyberid",
                    name: "S2O CyberID",
                    state: stub_state(),
                    detail: "not implemented (Phase 2/3)".into(),
                },
                ModuleStatus {
                    id: "cyberztna",
                    name: "S2O Gate",
                    state: stub_state(),
                    detail: "not implemented (Phase 3)".into(),
                },
            ];

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "platform": "S2O Aegis",
                        "schema_version": SCHEMA_VERSION,
                        "demo_mode": demo_mode(),
                        "modules": modules,
                        "cyberwall": st,
                    }))?
                );
            } else {
                println!("{}", "=========================================================".cyan());
                println!("{}", "    S2O AEGIS PLATFORM STATUS (honest)                   ".bold().green());
                println!("{}", "=========================================================".cyan());
                for m in &modules {
                    let state_col = match m.state {
                        "implemented" => m.state.green().bold(),
                        "demo" => m.state.yellow().bold(),
                        _ => m.state.red(),
                    };
                    println!(" Module  : {}", m.name.bold());
                    println!(" State   : {}", state_col);
                    println!(" Detail  : {}", m.detail);
                    println!("{}", "---------------------------------------------------------".cyan());
                }
            }
        }
        Commands::Reload => {
            eprintln!(
                "{}",
                "[AEGISD] Reload not implemented yet (no policy.json loader)."
                    .yellow()
                    .bold()
            );
            std::process::exit(2);
        }
    }

    Ok(())
}

fn stub_state() -> &'static str {
    if demo_mode() {
        "demo"
    } else {
        "not_implemented"
    }
}

fn stub_label(phase: &str) -> ColoredString {
    if demo_mode() {
        format!("DEMO ONLINE ({phase})").yellow().bold()
    } else {
        format!("NOT IMPLEMENTED ({phase})").red()
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}
