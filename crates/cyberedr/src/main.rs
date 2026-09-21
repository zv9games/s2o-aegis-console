use clap::{Parser, Subcommand};
use colored::*;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

const SUSPICIOUS_PORTS: &[u16] = &[
    1337, 31337, 4444, 5555, 6667, 8888, 9999, 4445, 12345, 54321
];

#[derive(Parser)]
#[command(name = "cyberedr")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.1.0")]
#[command(about = "S2O CyberEDR Agent: Kernel IP Telemetry & Behavioral Threat Detection CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberEDR agent status and telemetry statistics
    Status,
    /// Display active network socket connections correlated with PID & process name
    Processes {
        /// Filter by specific process name or remote IP/port
        #[arg(long)]
        filter: Option<String>,
        /// Limit number of displayed connections
        #[arg(short, long, default_value_t = 30)]
        limit: usize,
    },
    /// Live monitor loop logging new outbound connections and flagging suspicious activity
    Watch {
        /// Polling interval in seconds (default: 2)
        #[arg(short, long, default_value_t = 2)]
        interval: u64,
        /// Path to Aegis event store
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Display behavioral threat alerts detected by network telemetry
    Alerts {
        /// Path to Aegis event store
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
}

#[derive(Debug, serde::Deserialize)]
struct ProcessEntry {
    #[serde(rename = "Id")]
    id: u32,
    #[serde(rename = "ProcessName")]
    name: String,
}

fn get_process_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process | Select-Object Id, ProcessName | ConvertTo-Json",
        ])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Ok(entries) = serde_json::from_str::<Vec<ProcessEntry>>(&text) {
                for e in entries {
                    map.insert(e.id, e.name);
                }
            } else if let Ok(single) = serde_json::from_str::<ProcessEntry>(&text) {
                map.insert(single.id, single.name);
            }
        }
    }
    map
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;

            println!("{}", "=========================================================".cyan());
            println!("{}", "          SPLIT2OPS CYBEREDR TELEMETRY ENGINE            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Driver Provider   : {}", "Windows IP Helper (GetExtendedTcpTable)".green());
            println!(" Active Sockets    : {}", conns.len().to_string().bold());
            println!(" Monitored Protocols: {}", "IPv4 TCP / Owner PID Correlation".yellow());
            println!(" Threat Signatures : {}", format!("{} suspicious C2/backdoor ports monitored", SUSPICIOUS_PORTS.len()).bold());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Processes { filter, limit } => {
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;

            let proc_map = tokio::task::spawn_blocking(get_process_map).await?;

            println!("{}", "=========================================================".cyan());
            println!("{}", "   Active TCP Sockets & Correlated Process Telemetry     ".bold().green());
            println!("{}", "=========================================================".cyan());

            let mut count = 0;
            for c in &conns {
                let proc_name = proc_map.get(&c.pid).cloned().unwrap_or_else(|| "Unknown".to_string());
                let is_suspicious = SUSPICIOUS_PORTS.contains(&c.remote_port) || SUSPICIOUS_PORTS.contains(&c.local_port);

                if let Some(ref q) = filter {
                    let q_lower = q.to_lowercase();
                    let matches = proc_name.to_lowercase().contains(&q_lower)
                        || c.pid.to_string().contains(&q_lower)
                        || c.remote_addr.contains(&q_lower)
                        || c.local_addr.contains(&q_lower);
                    if !matches {
                        continue;
                    }
                }

                let proc_display = if is_suspicious {
                    format!("{:<15}", proc_name).red().bold()
                } else {
                    format!("{:<15}", proc_name).green()
                };

                let state_display = match c.state.as_str() {
                    "ESTABLISHED" => c.state.green().bold(),
                    "LISTEN" => c.state.yellow(),
                    _ => c.state.normal(),
                };

                println!(
                    " {:<6} | {} | {:<15}:{} -> {:<15}:{} [{}]",
                    c.pid,
                    proc_display,
                    c.local_addr,
                    c.local_port,
                    c.remote_addr,
                    c.remote_port,
                    state_display
                );

                count += 1;
                if count >= limit {
                    break;
                }
            }

            println!("{}", "---------------------------------------------------------".cyan());
            println!(" Displayed: {} / Total Active Sockets: {}", count, conns.len());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Watch { interval, event_log } => {
            let store = EventStore::open(&event_log)?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "     CYBEREDR REAL-TIME SOCKET WATCHER ACTIVE            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Polling Interval : {}s", interval);
            println!(" Event Logging    : {}", event_log.display());
            println!("{}", "Press Ctrl+C to stop monitoring...".yellow());
            println!("{}", "---------------------------------------------------------".cyan());

            let mut known_connections: HashSet<String> = HashSet::new();

            loop {
                let conns = tokio::task::spawn_blocking(|| {
                    s2o_net_lib::telemetry::get_active_tcp_connections()
                })
                .await?;

                let proc_map = tokio::task::spawn_blocking(get_process_map).await?;

                for c in &conns {
                    let key = format!("{}:{}-{}:{}-{}", c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.pid);

                    if !known_connections.contains(&key) {
                        known_connections.insert(key);

                        let proc_name = proc_map.get(&c.pid).cloned().unwrap_or_else(|| "Unknown".to_string());
                        let is_suspicious = SUSPICIOUS_PORTS.contains(&c.remote_port) || SUSPICIOUS_PORTS.contains(&c.local_port);

                        let severity = if is_suspicious {
                            Severity::High
                        } else {
                            Severity::Info
                        };

                        let msg = format!(
                            "TCP {} connection: PID {} ({}) {} -> {}",
                            c.state, c.pid, proc_name, c.local_addr, c.remote_addr
                        );

                        if is_suspicious {
                            println!(
                                "{} [ALERT] PID {} ({}) -> {}:{} (SUSPICIOUS PORT)",
                                "[CYBEREDR-THREAT]".red().bold(),
                                c.pid,
                                proc_name.red().bold(),
                                c.remote_addr,
                                c.remote_port
                            );
                        } else if c.state == "ESTABLISHED" {
                            println!(
                                "{} PID {} ({}) -> {}:{}",
                                "[NET-FLOW]".cyan(),
                                c.pid,
                                proc_name,
                                c.remote_addr,
                                c.remote_port
                            );
                        }

                        let ev = AegisEvent::new(
                            "local-endpoint",
                            ProductId::CyberEdr,
                            EventKind::NetFlow,
                            EventAction::Observed,
                            severity,
                            msg,
                        )
                        .with_attr("pid", serde_json::json!(c.pid))
                        .with_attr("process_name", serde_json::json!(proc_name))
                        .with_attr("remote_ip", serde_json::json!(c.remote_addr))
                        .with_attr("remote_port", serde_json::json!(c.remote_port))
                        .with_attr("suspicious", serde_json::json!(is_suspicious));

                        let _ = store.append(&ev);
                    }
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        }
        Commands::Alerts { event_log } => {
            if !event_log.exists() {
                println!("[cyberedr] no events stored yet (run `cyberedr watch` to stream events).");
                return Ok(());
            }

            let store = EventStore::open(&event_log)?;
            let events = store.recent(100)?;
            let alerts: Vec<&AegisEvent> = events
                .iter()
                .filter(|e| e.product == ProductId::CyberEdr && (e.severity == Severity::High || e.severity == Severity::Critical))
                .collect();

            println!("{}", "=========================================================".cyan());
            println!("{}", "           CyberEDR Behavioral Threat Alerts             ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Total detected alerts: {}", alerts.len());
            for (idx, a) in alerts.iter().enumerate() {
                println!("{}. [{}] {}", idx + 1, a.ts.to_rfc3339().yellow(), a.message.red().bold());
            }
            println!("{}", "=========================================================".cyan());
        }
    }

    Ok(())
}
