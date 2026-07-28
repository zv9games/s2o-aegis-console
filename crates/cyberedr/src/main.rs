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
    /// OS process inventory (tasklist / WMI / ps)
    Ps {
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Include command line + parent PID (WMI/ps - richer, slower)
        #[arg(long)]
        rich: bool,
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
    /// TCP LISTEN sockets (userspace table)
    Listen {
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// Only show ports commonly associated with risk (23,445,3389,…)
        #[arg(long)]
        risk_only: bool,
        #[arg(long)]
        emit_event: bool,
    },
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
        /// Capture command line + parent PID on start (WMI/ps)
        #[arg(long)]
        rich: bool,
    },
    /// Poll TCP table for new ESTABLISHED connections (userspace; not ETW)
    NetWatch {
        #[arg(long, default_value_t = 2000)]
        interval_ms: u64,
        /// Only remote IPs not in this list (comma-separated; default includes loopback)
        #[arg(long, default_value = "127.0.0.1,0.0.0.0,::1")]
        ignore_remote: String,
        /// Exit after this many new-connection events (0 = forever)
        #[arg(long, default_value_t = 0)]
        max_events: u32,
        /// Also report connections that disappear
        #[arg(long)]
        closes: bool,
        /// Emit events to JSONL
        #[arg(long, default_value_t = true)]
        emit_event: bool,
    },
    /// Validate userspace telemetry + baseline health (no ETW claim)
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Placeholder for true ETW/eBPF (use `watch --rich` / `net-watch` for userspace poll)
    Trace,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    ppid: Option<u32>,
    cmdline: Option<String>,
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
    list_processes(limit, false)
        .into_iter()
        .map(|p| {
            let base = Path::new(&p.name)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&p.name);
            base.to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn list_processes(limit: usize, rich: bool) -> Vec<ProcessInfo> {
    if rich {
        if let Some(rows) = list_processes_rich(limit) {
            return rows;
        }
    }
    list_processes_fast(limit)
}

fn list_processes_fast(limit: usize) -> Vec<ProcessInfo> {
    // Windows: tasklist /FO CSV /NH
    if cfg!(windows) {
        if let Ok(out) = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut rows = Vec::new();
                for line in text.lines() {
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
                        rows.push(ProcessInfo {
                            pid,
                            name,
                            ppid: None,
                            cmdline: None,
                        });
                    }
                    if rows.len() >= limit {
                        break;
                    }
                }
                return rows;
            }
        }
    }
    if let Ok(out) = Command::new("ps")
        .args(["-eo", "pid,ppid,comm", "--no-headers"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut rows = Vec::new();
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let pid = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let ppid = it.next().and_then(|p| p.parse().ok());
                let name = it.collect::<Vec<_>>().join(" ");
                if pid > 0 {
                    rows.push(ProcessInfo {
                        pid,
                        name,
                        ppid,
                        cmdline: None,
                    });
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

/// Windows WMI / Unix ps -eo with args for cmdline + parent.
fn list_processes_rich(limit: usize) -> Option<Vec<ProcessInfo>> {
    if cfg!(windows) {
        // wmic is deprecated but still common; PowerShell as fallback
        if let Ok(out) = Command::new("wmic")
            .args([
                "process",
                "get",
                "ProcessId,ParentProcessId,Name,CommandLine",
                "/FORMAT:CSV",
            ])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut rows = Vec::new();
                for line in text.lines().skip(1) {
                    // Node,CommandLine,Name,ParentProcessId,ProcessId
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts = parse_csv_line(line);
                    if parts.len() < 5 {
                        continue;
                    }
                    let cmdline = parts[1].trim().to_string();
                    let name = parts[2].trim().to_string();
                    let ppid = parts[3].trim().parse::<u32>().ok();
                    let pid = parts[4].trim().parse::<u32>().unwrap_or(0);
                    if pid == 0 {
                        continue;
                    }
                    rows.push(ProcessInfo {
                        pid,
                        name,
                        ppid,
                        cmdline: if cmdline.is_empty() {
                            None
                        } else {
                            Some(cmdline)
                        },
                    });
                    if rows.len() >= limit {
                        break;
                    }
                }
                if !rows.is_empty() {
                    return Some(rows);
                }
            }
        }
        // PowerShell fallback
        if let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Csv -NoTypeInformation",
            ])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut rows = Vec::new();
                for line in text.lines().skip(1) {
                    let parts = parse_csv_line(line);
                    // "ProcessId","ParentProcessId","Name","CommandLine"
                    if parts.len() < 3 {
                        continue;
                    }
                    let pid = parts[0].trim().parse::<u32>().unwrap_or(0);
                    let ppid = parts.get(1).and_then(|s| s.trim().parse().ok());
                    let name = parts.get(2).map(|s| s.trim().to_string()).unwrap_or_default();
                    let cmdline = parts.get(3).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                    if pid == 0 {
                        continue;
                    }
                    rows.push(ProcessInfo {
                        pid,
                        name,
                        ppid,
                        cmdline,
                    });
                    if rows.len() >= limit {
                        break;
                    }
                }
                if !rows.is_empty() {
                    return Some(rows);
                }
            }
        }
        return None;
    }
    // Unix: pid,ppid,comm,args
    if let Ok(out) = Command::new("ps")
        .args(["-eo", "pid,ppid,comm,args", "--no-headers"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut rows = Vec::new();
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let pid = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let ppid = it.next().and_then(|p| p.parse().ok());
                let name = it.next().unwrap_or("").to_string();
                let cmdline = {
                    let rest = it.collect::<Vec<_>>().join(" ");
                    if rest.is_empty() {
                        None
                    } else {
                        Some(rest)
                    }
                };
                if pid > 0 {
                    rows.push(ProcessInfo {
                        pid,
                        name,
                        ppid,
                        cmdline,
                    });
                }
                if rows.len() >= limit {
                    break;
                }
            }
            return Some(rows);
        }
    }
    None
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in line.chars() {
        match c {
            '"' => in_q = !in_q,
            ',' if !in_q => {
                fields.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
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
                "TCP table, listen, net-watch, process inventory (+rich), baseline/drift, alerts, watch, doctor"
                    .green()
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
        Commands::Doctor { json } => {
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut notes: Vec<serde_json::Value> = Vec::new();
            let mut check = |label: &str, good: bool, soft: bool, detail: &str| {
                notes.push(serde_json::json!({
                    "label": label,
                    "ok": good,
                    "warn": soft && !good,
                    "detail": detail,
                }));
                if good {
                    ok += 1;
                    if !json {
                        println!("  {} {} — {}", "OK".green().bold(), label, detail);
                    }
                } else if soft {
                    warn += 1;
                    if !json {
                        println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                    }
                } else {
                    fail += 1;
                    if !json {
                        println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                    }
                }
            };

            if !json {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      S2O CyberEDR doctor                                "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    " {}",
                    "Userspace only — no kernel ETW/eBPF claim.".yellow()
                );
            }

            check(
                "event log",
                cli.event_log.exists(),
                true,
                &format!("{}", cli.event_log.display()),
            );

            let baseline_n = if cli.baseline.exists() {
                fs::read_to_string(&cli.baseline)
                    .ok()
                    .and_then(|t| serde_json::from_str::<ProcessBaseline>(&t).ok())
                    .map(|b| b.images.len())
            } else {
                None
            };
            check(
                "baseline",
                baseline_n.is_some(),
                true,
                &match baseline_n {
                    Some(n) => format!("{} ({n} images)", cli.baseline.display()),
                    None => format!("{} missing (run: cyberedr baseline)", cli.baseline.display()),
                },
            );

            let procs = list_processes(200, false);
            check(
                "process inventory",
                !procs.is_empty(),
                false,
                &if procs.is_empty() {
                    "empty (tasklist/ps failed?)".into()
                } else {
                    format!("{} processes sampled", procs.len())
                },
            );

            let (tcp_ok, established, listen, tcp_detail) =
                match tokio::task::spawn_blocking(|| {
                    s2o_net_lib::telemetry::get_active_tcp_connections()
                })
                .await
                {
                    Ok(conns) => {
                        let est = conns
                            .iter()
                            .filter(|c| c.state.eq_ignore_ascii_case("ESTABLISHED"))
                            .count();
                        let lis = conns
                            .iter()
                            .filter(|c| c.state.eq_ignore_ascii_case("LISTEN"))
                            .count();
                        (
                            true,
                            est,
                            lis,
                            format!("{} rows (est={est} listen={lis})", conns.len()),
                        )
                    }
                    Err(e) => (false, 0, 0, format!("join error: {e}")),
                };
            // get_active may return empty vec on non-windows without error
            let tcp_soft = cfg!(not(windows));
            check(
                "tcp table",
                tcp_ok && (established + listen > 0 || tcp_soft),
                tcp_soft,
                &tcp_detail,
            );

            check(
                "kernel hooks",
                false,
                true,
                "none attached (use watch / net-watch for poll)",
            );

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "processes_sampled": procs.len(),
                        "tcp_established": established,
                        "tcp_listen": listen,
                        "baseline_images": baseline_n,
                        "checks": notes,
                    }))?
                );
            } else {
                println!(
                    " Summary: {} ok, {} warn, {} fail",
                    ok.to_string().green(),
                    warn.to_string().yellow(),
                    fail.to_string().red()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
            if fail > 0 {
                std::process::exit(1);
            }
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
        Commands::Ps { limit, rich } => {
            let rows = list_processes(limit, rich);
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                format!(
                    "       Process inventory ({})                     ",
                    if rich { "rich/WMI" } else { "userspace" }
                )
                .bold()
                .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            for p in &rows {
                if rich {
                    println!(
                        " PID {:<6} PPID {:<6} | {}{}",
                        p.pid,
                        p.ppid.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                        p.name,
                        p.cmdline
                            .as_ref()
                            .map(|c| format!("\n    cmd: {c}"))
                            .unwrap_or_default()
                    );
                } else {
                    println!(" PID {:<6} | {}", p.pid, p.name);
                }
            }
            println!(" Count: {}", rows.len());
            emit(
                &cli.event_log,
                EventKind::Process,
                EventAction::Observed,
                Severity::Info,
                format!("process inventory count={} rich={rich}", rows.len()),
                &[
                    ("count", serde_json::json!(rows.len())),
                    ("rich", serde_json::json!(rich)),
                ],
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
        Commands::Listen {
            limit,
            risk_only,
            emit_event,
        } => {
            let risk: BTreeSet<u16> = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 4444, 5555]
                .into_iter()
                .collect();
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;
            let mut listening: Vec<_> = conns
                .into_iter()
                .filter(|c| c.state.eq_ignore_ascii_case("LISTEN"))
                .collect();
            listening.sort_by(|a, b| a.local_port.cmp(&b.local_port).then(a.pid.cmp(&b.pid)));
            if risk_only {
                listening.retain(|c| risk.contains(&c.local_port));
            }
            let total = listening.len();
            let show = listening.into_iter().take(limit).collect::<Vec<_>>();
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "       CyberEDR listening TCP sockets                    "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Count: {} (showing {}){}",
                total,
                show.len(),
                if risk_only { " risk_only" } else { "" }
            );
            for c in &show {
                let mark = if risk.contains(&c.local_port) {
                    " !".red().bold().to_string()
                } else {
                    String::new()
                };
                println!(
                    "  :{:<5}  pid={:<7}  {}{}",
                    c.local_port, c.pid, c.local_addr, mark
                );
            }
            if emit_event {
                emit(
                    &cli.event_log,
                    EventKind::NetFlow,
                    EventAction::Observed,
                    Severity::Info,
                    format!("listen inventory count={total} risk_only={risk_only}"),
                    &[
                        ("count", serde_json::json!(total)),
                        ("risk_only", serde_json::json!(risk_only)),
                        (
                            "ports",
                            serde_json::json!(
                                show.iter().map(|c| c.local_port).collect::<Vec<_>>()
                            ),
                        ),
                    ],
                );
            }
        }
        Commands::NetWatch {
            interval_ms,
            ignore_remote,
            max_events,
            closes,
            emit_event,
        } => {
            let ignore: BTreeSet<String> = ignore_remote
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            println!(
                "[cyberedr] net-watch interval={}ms closes={} (poll TCP table, not ETW)",
                interval_ms, closes
            );
            let seed = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;
            let conn_key = |c: &s2o_net_lib::telemetry::ActiveConnection| {
                format!(
                    "{}:{}-{}:{}-{}-{}",
                    c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.state, c.pid
                )
            };
            let mut known: BTreeSet<String> = seed
                .iter()
                .filter(|c| c.state.eq_ignore_ascii_case("ESTABLISHED"))
                .filter(|c| !ignore.contains(&c.remote_addr))
                .map(conn_key)
                .collect();
            println!(
                "[cyberedr] seed {} established (ignoring remotes: {})",
                known.len(),
                ignore_remote
            );
            if emit_event {
                emit(
                    &cli.event_log,
                    EventKind::NetFlow,
                    EventAction::Observed,
                    Severity::Info,
                    format!("edr net-watch start seed={}", known.len()),
                    &[
                        ("interval_ms", serde_json::json!(interval_ms)),
                        ("seed", serde_json::json!(known.len())),
                        ("engine", serde_json::json!("tcp_poll_v0")),
                    ],
                );
            }
            let mut new_events = 0u32;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms.max(500))).await;
                let live = tokio::task::spawn_blocking(|| {
                    s2o_net_lib::telemetry::get_active_tcp_connections()
                })
                .await?;
                let mut live_keys: BTreeSet<String> = BTreeSet::new();
                for c in &live {
                    if !c.state.eq_ignore_ascii_case("ESTABLISHED") {
                        continue;
                    }
                    if ignore.contains(&c.remote_addr) {
                        continue;
                    }
                    let k = conn_key(c);
                    live_keys.insert(k.clone());
                    if !known.contains(&k) {
                        println!(
                            "{} pid={} {}:{} → {}:{}",
                            " NEW ".cyan().bold(),
                            c.pid,
                            c.local_addr,
                            c.local_port,
                            c.remote_addr,
                            c.remote_port
                        );
                        if emit_event {
                            emit(
                                &cli.event_log,
                                EventKind::NetFlow,
                                EventAction::Observed,
                                Severity::Medium,
                                format!(
                                    "new established {}:{} -> {}:{} pid={}",
                                    c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.pid
                                ),
                                &[
                                    ("local", serde_json::json!(format!("{}:{}", c.local_addr, c.local_port))),
                                    ("remote", serde_json::json!(format!("{}:{}", c.remote_addr, c.remote_port))),
                                    ("pid", serde_json::json!(c.pid)),
                                    ("engine", serde_json::json!("tcp_poll_v0")),
                                ],
                            );
                        }
                        new_events += 1;
                        if max_events > 0 && new_events >= max_events {
                            println!("[cyberedr] net-watch max_events={max_events} reached");
                            return Ok(());
                        }
                    }
                }
                if closes {
                    for k in known.difference(&live_keys) {
                        println!("{} {}", " CLOSE ".yellow().bold(), k);
                        if emit_event {
                            emit(
                                &cli.event_log,
                                EventKind::NetFlow,
                                EventAction::Observed,
                                Severity::Low,
                                format!("connection closed {k}"),
                                &[("key", serde_json::json!(k)), ("engine", serde_json::json!("tcp_poll_v0"))],
                            );
                        }
                    }
                }
                known = live_keys;
            }
        }
        Commands::Watch {
            interval_ms,
            limit,
            exits,
            max_events,
            rich,
        } => {
            println!(
                "[cyberedr] watch interval={}ms limit={} rich={} (poll, not kernel ETW)",
                interval_ms, limit, rich
            );
            let seed = list_processes(limit, rich);
            let mut known: BTreeMap<u32, ProcessInfo> =
                seed.into_iter().map(|p| (p.pid, p)).collect();
            println!("[cyberedr] seed {} processes", known.len());
            emit(
                &cli.event_log,
                EventKind::Process,
                EventAction::Observed,
                Severity::Info,
                format!("edr watch start seed={} rich={rich}", known.len()),
                &[
                    ("interval_ms", serde_json::json!(interval_ms)),
                    ("seed", serde_json::json!(known.len())),
                    ("engine", serde_json::json!(if rich { "poll_rich_v0" } else { "poll_v0" })),
                ],
            );
            let mut new_events = 0u32;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms.max(200))).await;
                let live_list = list_processes(limit, rich);
                let live: BTreeMap<u32, ProcessInfo> =
                    live_list.into_iter().map(|p| (p.pid, p)).collect();
                for (pid, info) in &live {
                    if !known.contains_key(pid) {
                        println!(
                            "{} PID {pid:<6} PPID {} | {}{}",
                            " START".green().bold(),
                            info.ppid
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "-".into()),
                            info.name,
                            info.cmdline
                                .as_ref()
                                .map(|c| format!(" | {c}"))
                                .unwrap_or_default()
                        );
                        emit(
                            &cli.event_log,
                            EventKind::Process,
                            EventAction::Observed,
                            Severity::Info,
                            format!("process start pid={pid} name={}", info.name),
                            &[
                                ("pid", serde_json::json!(pid)),
                                ("name", serde_json::json!(info.name)),
                                ("ppid", serde_json::json!(info.ppid)),
                                ("cmdline", serde_json::json!(info.cmdline)),
                                (
                                    "engine",
                                    serde_json::json!(if rich {
                                        "poll_rich_v0"
                                    } else {
                                        "poll_v0"
                                    }),
                                ),
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
                    for (pid, info) in &known {
                        if !live.contains_key(pid) {
                            println!(
                                "{} PID {pid:<6} | {}",
                                " EXIT ".yellow().bold(),
                                info.name
                            );
                            emit(
                                &cli.event_log,
                                EventKind::Process,
                                EventAction::Observed,
                                Severity::Low,
                                format!("process exit pid={pid} name={}", info.name),
                                &[
                                    ("pid", serde_json::json!(pid)),
                                    ("name", serde_json::json!(info.name)),
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
            eprintln!("Use: cyberedr watch --rich | net-watch | listen | alerts");
            std::process::exit(2);
        }
    }

    Ok(())
}
