//! S2O CyberEDR — TCP + process inventory + simple heuristics (Phase 2 shell).

use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "cyberedr")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.4.0")]
#[command(about = "S2O CyberEDR: userspace telemetry + heuristics + baseline", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/edr-baseline.json")]
    baseline: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// Active TCP connections (IP Helper on Windows)
    Processes {
        #[arg(long, default_value_t = 64)]
        limit: usize,
        #[arg(long, default_value_t = true)]
        emit_event: bool,
    },
    /// OS process inventory (tasklist / ps)
    Ps {
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Snapshot process image names into baseline file
    Baseline {
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Compare live process names to baseline (exit 3 if new images found)
    Drift {
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Heuristic alerts from TCP snapshot (no ETW yet)
    Alerts,
    /// Poll process table for new PIDs (ETW-lite T0; not kernel ETW)
    Watch {
        #[arg(long, default_value_t = 2000)]
        interval_ms: u64,
        #[arg(long, default_value_t = 800)]
        limit: usize,
        /// Also emit when a process image name disappears
        #[arg(long)]
        exits: bool,
        /// Exit after this many new-process events (0 = run forever)
        #[arg(long, default_value_t = 0)]
        max_events: u32,
    },
    /// Placeholder for true ETW/eBPF (use `watch` for userspace poll)
    Trace,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessBaseline {
    version: String,
    captured_at: String,
    host_id: String,
    /// Sorted unique process image names (lowercase)
    images: Vec<String>,
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

fn process_images(limit: usize) -> BTreeSet<String> {
    list_processes(limit)
        .into_iter()
        .map(|(_, name)| {
            // strip path if present; keep basename
            let base = Path::new(&name)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&name);
            base.to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn list_processes(limit: usize) -> Vec<(u32, String)> {
    // Windows: tasklist /FO CSV /NH
    if cfg!(windows) {
        if let Ok(out) = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut rows = Vec::new();
                for line in text.lines() {
                    // "name","pid","session","session#","mem"
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    let name = parts[0].trim().trim_matches('"').to_string();
                    let pid = parts[1]
                        .trim()
                        .trim_matches('"')
                        .parse::<u32>()
                        .unwrap_or(0);
                    if pid > 0 {
                        rows.push((pid, name));
                    }
                    if rows.len() >= limit {
                        break;
                    }
                }
                return rows;
            }
        }
    }
    // Unix fallback
    if let Ok(out) = Command::new("ps").args(["-eo", "pid,comm", "--no-headers"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut rows = Vec::new();
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let pid = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let name = it.collect::<Vec<_>>().join(" ");
                if pid > 0 {
                    rows.push((pid, name));
                }
                if rows.len() >= limit {
                    break;
                }
            }
            return rows;
        }
    }
    Vec::new()
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
                "TCP table, process inventory, baseline/drift, alerts, watch (poll)".green()
            );
            println!(
                " Not implemented   : {}",
                "kernel ETW/eBPF hooks, behavioral ML".red()
            );
            println!(
                " Baseline file     : {} ({})",
                cli.baseline.display(),
                if cli.baseline.exists() {
                    "present".green().to_string()
                } else {
                    "missing".yellow().to_string()
                }
            );
            println!(
                " Kernel hooks      : {}",
                "NONE ATTACHED (userspace only)".yellow().bold()
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
        Commands::Ps { limit } => {
            let rows = list_processes(limit);
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       Process inventory (userspace)                     "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            for (pid, name) in &rows {
                println!(" PID {pid:<6} | {name}");
            }
            println!(" Count: {}", rows.len());
            emit(
                &cli.event_log,
                EventKind::Process,
                EventAction::Observed,
                Severity::Info,
                format!("process inventory count={}", rows.len()),
                &[("count", serde_json::json!(rows.len()))],
            );
        }
        Commands::Baseline { limit } => {
            let images: Vec<String> = process_images(limit).into_iter().collect();
            let bl = ProcessBaseline {
                version: "0.1.0".into(),
                captured_at: chrono::Utc::now().to_rfc3339(),
                host_id: host_id(),
                images: images.clone(),
            };
            if let Some(p) = cli.baseline.parent() {
                fs::create_dir_all(p)?;
            }
            fs::write(&cli.baseline, serde_json::to_string_pretty(&bl)?)?;
            println!(
                "{}",
                format!(
                    "[cyberedr] baseline wrote {} ({} images)",
                    cli.baseline.display(),
                    images.len()
                )
                .green()
                .bold()
            );
            emit(
                &cli.event_log,
                EventKind::Process,
                EventAction::Observed,
                Severity::Info,
                format!("process baseline captured n={}", images.len()),
                &[
                    ("path", serde_json::json!(cli.baseline.display().to_string())),
                    ("images", serde_json::json!(images.len())),
                ],
            );
        }
        Commands::Drift { limit } => {
            if !cli.baseline.exists() {
                eprintln!(
                    "[cyberedr] no baseline at {} — run: cyberedr baseline",
                    cli.baseline.display()
                );
                std::process::exit(2);
            }
            let bl: ProcessBaseline =
                serde_json::from_str(&fs::read_to_string(&cli.baseline)?)?;
            let base: BTreeSet<String> = bl.images.into_iter().collect();
            let live = process_images(limit);
            let new: Vec<_> = live.difference(&base).cloned().collect();
            let gone: Vec<_> = base.difference(&live).cloned().collect();
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       Process baseline drift                            "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Baseline images : {}", base.len());
            println!(" Live images     : {}", live.len());
            println!(" New             : {}", new.len());
            println!(" Missing         : {}", gone.len());
            for n in new.iter().take(32) {
                println!("  + {}", n.yellow());
            }
            for g in gone.iter().take(16) {
                println!("  - {}", g.dimmed());
            }
            emit(
                &cli.event_log,
                EventKind::Alert,
                if new.is_empty() {
                    EventAction::Observed
                } else {
                    EventAction::Blocked
                },
                if new.is_empty() {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                format!(
                    "process drift new={} missing={}",
                    new.len(),
                    gone.len()
                ),
                &[
                    ("new_count", serde_json::json!(new.len())),
                    ("missing_count", serde_json::json!(gone.len())),
                    ("new_sample", serde_json::json!(new.iter().take(10).cloned().collect::<Vec<_>>())),
                ],
            );
            if !new.is_empty() {
                std::process::exit(3);
            }
        }
        Commands::Alerts => {
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;

            // Heuristic 1: many ESTABLISHED to same remote IP
            let mut by_remote: BTreeMap<String, u32> = BTreeMap::new();
            // Heuristic 2: listening on high risk ports (set)
            let risk_listen: BTreeSet<u16> = [23, 445, 3389, 5900, 4444, 5555].into_iter().collect();
            let mut alerts: Vec<(Severity, String)> = Vec::new();

            for c in &conns {
                if c.state.eq_ignore_ascii_case("ESTABLISHED")
                    && c.remote_addr != "0.0.0.0"
                    && c.remote_addr != "127.0.0.1"
                {
                    *by_remote.entry(c.remote_addr.clone()).or_default() += 1;
                }
                if c.state.eq_ignore_ascii_case("LISTEN") && risk_listen.contains(&c.local_port) {
                    alerts.push((
                        Severity::Medium,
                        format!(
                            "listen on sensitive port {} pid={} ({})",
                            c.local_port, c.pid, c.local_addr
                        ),
                    ));
                }
            }
            for (ip, n) in by_remote {
                if n >= 8 {
                    alerts.push((
                        Severity::Medium,
                        format!("high connection fan-out to {ip}: {n} established"),
                    ));
                }
            }

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       CyberEDR heuristic alerts (userspace)             "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            if alerts.is_empty() {
                println!("{}", "No heuristic alerts.".green());
            } else {
                for (sev, msg) in &alerts {
                    println!(" [{:?}] {}", sev, msg.yellow());
                    emit(
                        &cli.event_log,
                        EventKind::Alert,
                        EventAction::Observed,
                        *sev,
                        msg.clone(),
                        &[("engine", serde_json::json!("heuristic_v0"))],
                    );
                }
            }
            println!(" Alerts: {}", alerts.len());
        }
        Commands::Watch {
            interval_ms,
            limit,
            exits,
            max_events,
        } => {
            println!(
                "[cyberedr] watch interval={}ms limit={} (Ctrl+C to stop; userspace poll, not ETW)",
                interval_ms, limit
            );
            let mut known: BTreeMap<u32, String> = list_processes(limit).into_iter().collect();
            println!("[cyberedr] seed {} processes", known.len());
            emit(
                &cli.event_log,
                EventKind::Process,
                EventAction::Observed,
                Severity::Info,
                format!("edr watch start seed={}", known.len()),
                &[
                    ("interval_ms", serde_json::json!(interval_ms)),
                    ("seed", serde_json::json!(known.len())),
                    ("engine", serde_json::json!("poll_v0")),
                ],
            );
            let mut new_events = 0u32;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms.max(200))).await;
                let live: BTreeMap<u32, String> = list_processes(limit).into_iter().collect();
                for (pid, name) in &live {
                    if !known.contains_key(pid) {
                        println!(
                            "{} PID {pid:<6} | {name}",
                            " START".green().bold()
                        );
                        emit(
                            &cli.event_log,
                            EventKind::Process,
                            EventAction::Observed,
                            Severity::Info,
                            format!("process start pid={pid} name={name}"),
                            &[
                                ("pid", serde_json::json!(pid)),
                                ("name", serde_json::json!(name)),
                                ("engine", serde_json::json!("poll_v0")),
                            ],
                        );
                        new_events += 1;
                        if max_events > 0 && new_events >= max_events {
                            println!("[cyberedr] watch max_events={max_events} reached");
                            return Ok(());
                        }
                    }
                }
                if exits {
                    for (pid, name) in &known {
                        if !live.contains_key(pid) {
                            println!(
                                "{} PID {pid:<6} | {name}",
                                " EXIT ".yellow().bold()
                            );
                            emit(
                                &cli.event_log,
                                EventKind::Process,
                                EventAction::Observed,
                                Severity::Low,
                                format!("process exit pid={pid} name={name}"),
                                &[
                                    ("pid", serde_json::json!(pid)),
                                    ("name", serde_json::json!(name)),
                                    ("engine", serde_json::json!("poll_v0")),
                                ],
                            );
                        }
                    }
                }
                known = live;
            }
        }
        Commands::Trace => {
            eprintln!("[cyberedr] kernel ETW/eBPF live trace not implemented.");
            eprintln!("Use: cyberedr watch  (userspace process poll / ETW-lite)");
            eprintln!("     cyberedr processes | ps | alerts | drift");
            std::process::exit(2);
        }
    }

    Ok(())
}
