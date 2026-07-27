//! S2O Aegis master daemon — suite kernel front door.
//!
//! Honesty: only engines that actually work report live data.
//! Demo labels require AEGIS_DEMO=1.
//!
//! Windows Service: `aegisd --run-as-service` (SCM entry). Interactive: `aegisd start`.

#[cfg(windows)]
mod service;

use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::{
    apply_policy, collect_platform_status, create_firewall_engine, demo_mode, host_id,
    load_policy_file, FirewallEngineHandle, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{
    AegisEvent, EventAction, EventKind, HealthState, ProductId, Severity, SCHEMA_VERSION,
};
use s2o_store::EventStore;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "aegisd")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O Aegis Platform: suite kernel / cyber-ops orchestrator", long_about = None)]
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
        /// Local health HTTP bind (empty to disable). Example: 127.0.0.1:9090
        #[arg(long, default_value = "127.0.0.1:9090")]
        health_bind: String,
        /// Disable the health HTTP endpoint
        #[arg(long)]
        no_health: bool,
        /// Fleet inventory store path (for /fleet HTTP)
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
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

/// Minimal HTTP/1.0 health server: GET /health, /status, /metrics, /fleet
/// POST /fleet/heartbeat
async fn health_server(
    bind: String,
    fw: FirewallEngineHandle,
    event_log: PathBuf,
    fleet_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&bind).await?;
    loop {
        let (mut sock, peer) = listener.accept().await?;
        let fw = fw.clone();
        let event_log = event_log.clone();
        let fleet_path = fleet_path.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            let n = match sock.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let path = parts
                .next()
                .unwrap_or("/")
                .split('?')
                .next()
                .unwrap_or("/");

            // body after headers
            let body_bytes = req
                .split("\r\n\r\n")
                .nth(1)
                .or_else(|| req.split("\n\n").nth(1))
                .unwrap_or("");

            let (code, body, ctype) = if path == "/health" || path.starts_with("/health/") {
                (
                    "200 OK",
                    format!(
                        "{{\"ok\":true,\"platform\":\"S2O Aegis\",\"phase\":\"{PHASE_LABEL}\",\"kernel\":\"{KERNEL_VERSION}\"}}\n"
                    ),
                    "application/json",
                )
            } else if path == "/status" || path.starts_with("/status/") {
                match serde_json::to_string(&collect_platform_status(&fw).await) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/fleet" || path == "/fleet/" {
                let store = s2o_fleet::FleetStore::load(&fleet_path);
                match serde_json::to_string(&store) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/fleet/summary" || path.starts_with("/fleet/summary") {
                let store = s2o_fleet::FleetStore::load(&fleet_path);
                let sum = store.summary(60);
                match serde_json::to_string(&sum) {
                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                    Err(e) => (
                        "500 Internal Server Error",
                        format!("{{\"error\":\"{e}\"}}\n"),
                        "application/json",
                    ),
                }
            } else if path == "/fleet/heartbeat" || path.starts_with("/fleet/heartbeat") {
                if method != "POST" && method != "PUT" {
                    (
                        "405 Method Not Allowed",
                        "{\"error\":\"POST JSON HeartbeatPayload\"}\n".into(),
                        "application/json",
                    )
                } else {
                    match serde_json::from_str::<s2o_fleet::HeartbeatPayload>(body_bytes) {
                        Ok(mut hb) => {
                            if hb.last_ip.is_none() {
                                hb.last_ip = Some(peer.ip().to_string());
                            }
                            let mut store = s2o_fleet::FleetStore::load(&fleet_path);
                            let host = store.upsert_heartbeat(hb);
                            if let Err(e) = store.save(&fleet_path) {
                                (
                                    "500 Internal Server Error",
                                    format!("{{\"error\":\"save: {e}\"}}\n"),
                                    "application/json",
                                )
                            } else {
                                match serde_json::to_string(&host) {
                                    Ok(s) => ("200 OK", format!("{s}\n"), "application/json"),
                                    Err(e) => (
                                        "500 Internal Server Error",
                                        format!("{{\"error\":\"{e}\"}}\n"),
                                        "application/json",
                                    ),
                                }
                            }
                        }
                        Err(e) => (
                            "400 Bad Request",
                            format!("{{\"error\":\"json: {e}\"}}\n"),
                            "application/json",
                        ),
                    }
                }
            } else if path == "/metrics" || path.starts_with("/metrics/") {
                let st = collect_platform_status(&fw).await;
                let mut implemented = 0u32;
                let mut partial = 0u32;
                let mut other = 0u32;
                for m in &st.modules {
                    match m.state.as_str() {
                        "implemented" => implemented += 1,
                        "partial" => partial += 1,
                        _ => other += 1,
                    }
                }
                let (events, bytes) = if event_log.exists() {
                    match EventStore::open(&event_log) {
                        Ok(s) => (
                            s.count().unwrap_or(0) as u64,
                            s.len_bytes().unwrap_or(0),
                        ),
                        Err(_) => (0, 0),
                    }
                } else {
                    (0, 0)
                };
                let fleet = s2o_fleet::FleetStore::load(&fleet_path);
                let fsum = fleet.summary(60);
                let body = format!(
                    "# HELP aegis_up 1 if daemon health endpoint is serving\n\
                     # TYPE aegis_up gauge\n\
                     aegis_up 1\n\
                     # HELP aegis_modules Modules by honesty state\n\
                     # TYPE aegis_modules gauge\n\
                     aegis_modules{{state=\"implemented\"}} {implemented}\n\
                     aegis_modules{{state=\"partial\"}} {partial}\n\
                     aegis_modules{{state=\"other\"}} {other}\n\
                     # HELP aegis_events_total Events in local JSONL store\n\
                     # TYPE aegis_events_total gauge\n\
                     aegis_events_total {events}\n\
                     # HELP aegis_event_log_bytes Size of event log file\n\
                     # TYPE aegis_event_log_bytes gauge\n\
                     aegis_event_log_bytes {bytes}\n\
                     # HELP aegis_fleet_hosts Fleet roster size\n\
                     # TYPE aegis_fleet_hosts gauge\n\
                     aegis_fleet_hosts {fleet_total}\n\
                     # HELP aegis_fleet_online Hosts seen within stale window\n\
                     # TYPE aegis_fleet_online gauge\n\
                     aegis_fleet_online {fleet_online}\n\
                     # HELP aegis_demo_mode 1 if AEGIS_DEMO is enabled\n\
                     # TYPE aegis_demo_mode gauge\n\
                     aegis_demo_mode {}\n",
                    if st.demo_mode { 1 } else { 0 },
                    fleet_total = fsum.total,
                    fleet_online = fsum.online,
                );
                ("200 OK", body, "text/plain; version=0.0.4")
            } else {
                (
                    "404 Not Found",
                    "try GET /health /status /metrics /fleet /fleet/summary ; POST /fleet/heartbeat\n".into(),
                    "text/plain",
                )
            };

            let resp = format!(
                "HTTP/1.0 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

/// Shared start path for interactive console and Windows Service.
pub async fn run_daemon(
    event_log: PathBuf,
    health_bind: String,
    no_health: bool,
    as_service: bool,
    fleet_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fw = create_firewall_engine();

    if !as_service {
        println!(
            "{}",
            "=========================================================".cyan()
        );
        println!(
            "{}",
            "     S2O AEGIS MASTER DAEMON  (Phase 2/3 shell)          "
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
    }

    if let Some(parent) = event_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let store = EventStore::open(&event_log)?;
    if !as_service {
        println!(" Event store       : {}", store.path().display());
        println!(" Host id           : {}", host_id());
    }

    let status = collect_platform_status(&fw).await;
    if !as_service {
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
    }

    let wall = status
        .modules
        .iter()
        .find(|m| m.product == ProductId::Cyberwall);
    let mode = if as_service { "service" } else { "console" };
    let ev = AegisEvent::new(
        host_id(),
        ProductId::Aegis,
        EventKind::Health,
        EventAction::Observed,
        Severity::Info,
        format!(
            "aegisd start mode={mode}; phase={PHASE_LABEL}; wall={}",
            wall.map(|w| w.state.as_str()).unwrap_or("unknown")
        ),
    )
    .with_attr("phase", serde_json::json!(PHASE_LABEL))
    .with_attr("tier_ceiling", serde_json::json!(TIER_CEILING.as_str()))
    .with_attr("mode", serde_json::json!(mode))
    .with_attr(
        "wall_detail",
        serde_json::json!(wall.map(|w| w.detail.as_str()).unwrap_or("")),
    );
    store.append(&ev)?;
    if !as_service {
        println!("[AEGISD] health event written to store");
    }

    if !no_health && !health_bind.is_empty() {
        let bind = health_bind.clone();
        let fw_h = create_firewall_engine();
        let el = event_log.clone();
        let fl = fleet_path.clone();
        tokio::spawn(async move {
            if let Err(e) = health_server(bind, fw_h, el, fl).await {
                eprintln!("[AEGISD] health server error: {e}");
            }
        });
        if !as_service {
            println!("[AEGISD] health HTTP     : http://{health_bind}/health");
            println!("[AEGISD] status JSON     : http://{health_bind}/status");
            println!("[AEGISD] metrics         : http://{health_bind}/metrics");
            println!("[AEGISD] fleet           : http://{health_bind}/fleet");
            println!("[AEGISD] fleet heartbeat : POST http://{health_bind}/fleet/heartbeat");
        }
    }

    if !as_service {
        println!(
            "{}",
            "=========================================================".cyan()
        );
        println!(
            "{}",
            "  Suite kernel live. Ctrl+C to stop."
                .bold()
                .yellow()
        );
        println!(
            "{}",
            "=========================================================".cyan()
        );
        tokio::signal::ctrl_c().await?;
        println!("\n[AEGISD] shutdown complete.");
    } else {
        // Service mode: run until cancelled by caller (select in service.rs)
        std::future::pending::<()>().await;
    }
    Ok(())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Start {
            event_log,
            health_bind,
            no_health,
            fleet,
        } => {
            run_daemon(event_log, health_bind, no_health, false, fleet).await?;
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

fn main() {
    // SCM entry: must run before clap (service dispatcher protocol).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--run-as-service") {
        #[cfg(windows)]
        {
            if let Err(e) = service::dispatch() {
                eprintln!("[aegisd] service dispatcher error: {e}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("[aegisd] --run-as-service is only supported on Windows");
            std::process::exit(2);
        }
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[aegisd] runtime error: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(async_main()) {
        eprintln!("[aegisd] error: {e}");
        std::process::exit(1);
    }
}
