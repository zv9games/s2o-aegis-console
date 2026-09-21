use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::{FirewallEngine, RuleAction, RuleDirection, RuleProtocol, FirewallRule, ProfileType};

#[derive(Parser)]
#[command(name = "aegis")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.0.0")]
#[command(about = "S2O Aegis Universal Master Security CLI - Unified Control Matrix", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect platform health, 9-pillar matrix, and driver substrate
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Direct control over S2O Cyberwall firewall engine
    Firewall {
        #[command(subcommand)]
        action: FirewallCommands,
    },
    /// File integrity & malware scanning (CyberDefender)
    Scan {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Query or control DNS Shield & Sinkhole (CyberDNS)
    Dns {
        #[command(subcommand)]
        action: DnsCommands,
    },
    /// Endpoint Detection & Socket Telemetry (CyberEDR)
    Edr {
        #[command(subcommand)]
        action: EdrCommands,
    },
    /// Zero-Trust Posture Assessment & Attestation (CyberID)
    Posture,
    /// Send ping or RPC query to the background daemon via IPC
    Daemon {
        #[arg(default_value = "ping")]
        rpc_cmd: String,
    },
}

#[derive(Subcommand)]
enum FirewallCommands {
    /// Enable all OS firewall profiles
    Enable,
    /// Disable all OS firewall profiles
    Disable,
    /// Block an inbound port
    BlockPort {
        port: u16,
        #[arg(long, default_value = "TCP")]
        protocol: String,
    },
    /// Allow an inbound port
    AllowPort {
        port: u16,
        #[arg(long, default_value = "TCP")]
        protocol: String,
    },
    /// Block a specific remote IP address
    BlockIp {
        ip: String,
    },
    /// List active firewall rules
    List,
}

#[derive(Subcommand)]
enum DnsCommands {
    /// Resolve domain via Encrypted DNS-over-HTTPS (DoH)
    Resolve {
        domain: String,
    },
    /// Add domain to local sinkhole blocklist
    Block {
        domain: String,
    },
}

#[derive(Subcommand)]
enum EdrCommands {
    /// List active network sockets correlated with Windows processes
    Sockets,
    /// Scan for suspicious or backdoor ports
    Audit,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let fw = WindowsFirewallEngine::new();

    match cli.command {
        Commands::Status { json } => {
            let st = fw.get_status().await?;
            let caps = fw.driver_capabilities();

            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "platform": st.platform,
                    "enabled": st.enabled,
                    "defender_active": st.defender_active,
                    "substrate": caps.substrate,
                    "driver_version": caps.driver_version,
                    "profiles": {
                        "private": st.profile_private,
                        "public": st.profile_public,
                        "domain": st.profile_domain,
                    }
                }))?);
            } else {
                println!("{}", "=========================================================".cyan());
                println!("{}", "      S2O AEGIS UNIVERSAL MASTER CONTROL CLI             ".bold().green());
                println!("{}", "=========================================================".cyan());
                println!(" Operating System : {:?}", caps.os);
                println!(" Driver Substrate : {:?} [{}]", caps.substrate, if caps.substrate == cyberwall_core::DriverSubstrate::UserspaceNative { "Tier-0 Native ($0/yr)".green().bold() } else { "Kernel Mode Attached".cyan().bold() });
                println!(" Substrate Engine : {}", caps.driver_version.unwrap_or_default());
                println!(" OS Firewall      : {}", if st.enabled { "ONLINE (WFP Policy Active)".green().bold() } else { "DISABLED".red().bold() });
                println!(" CyberDefender    : {}", if st.defender_active { "ONLINE (WinDefend Shield Active)".green().bold() } else { "INACTIVE".red().bold() });
                println!("{}", "---------------------------------------------------------".cyan());
                println!(" Ready to orchestrate all 9 pillars via 'aegis <module> <command>'");
            }
        }
        Commands::Firewall { action } => match action {
            FirewallCommands::Enable => {
                println!("[AEGIS] Enabling OS firewall across all profiles...");
                fw.set_enabled(true).await?;
                println!("{}", "[AEGIS] OK: Firewall enabled.".green().bold());
            }
            FirewallCommands::Disable => {
                println!("[AEGIS] Disabling OS firewall across all profiles...");
                fw.set_enabled(false).await?;
                println!("{}", "[AEGIS] WARNING: Firewall disabled.".yellow().bold());
            }
            FirewallCommands::BlockPort { port, protocol } => {
                println!("[AEGIS] Adding block rule for port {}/{}...", port, protocol);
                let rule = FirewallRule {
                    name: format!("S2O-Aegis-Block-Port-{}", port),
                    enabled: true,
                    action: RuleAction::Block,
                    direction: RuleDirection::Inbound,
                    profile: ProfileType::All,
                    protocol: Some(if protocol.eq_ignore_ascii_case("UDP") { RuleProtocol::Udp } else { RuleProtocol::Tcp }),
                    local_ports: Some(port.to_string()),
                    remote_ports: None,
                    remote_addresses: None,
                    application: None,
                };
                fw.add_rule(&rule).await?;
                println!("{}", format!("[AEGIS] OK: Block rule created for port {}", port).green().bold());
            }
            FirewallCommands::AllowPort { port, protocol } => {
                println!("[AEGIS] Adding allow rule for port {}/{}...", port, protocol);
                let rule = FirewallRule {
                    name: format!("S2O-Aegis-Allow-Port-{}", port),
                    enabled: true,
                    action: RuleAction::Allow,
                    direction: RuleDirection::Inbound,
                    profile: ProfileType::All,
                    protocol: Some(if protocol.eq_ignore_ascii_case("UDP") { RuleProtocol::Udp } else { RuleProtocol::Tcp }),
                    local_ports: Some(port.to_string()),
                    remote_ports: None,
                    remote_addresses: None,
                    application: None,
                };
                fw.add_rule(&rule).await?;
                println!("{}", format!("[AEGIS] OK: Allow rule created for port {}", port).green().bold());
            }
            FirewallCommands::BlockIp { ip } => {
                println!("[AEGIS] Blocking IP {}...", ip);
                let rule = FirewallRule {
                    name: format!("S2O-Aegis-Block-IP-{}", ip.replace('.', "-")),
                    enabled: true,
                    action: RuleAction::Block,
                    direction: RuleDirection::Inbound,
                    profile: ProfileType::All,
                    protocol: Some(RuleProtocol::Any),
                    local_ports: None,
                    remote_ports: None,
                    remote_addresses: Some(ip.clone()),
                    application: None,
                };
                fw.add_rule(&rule).await?;
                println!("{}", format!("[AEGIS] OK: Inbound traffic from {} blocked.", ip).green().bold());
            }
            FirewallCommands::List => {
                let rules = fw.list_rules().await?;
                println!("{}", format!("[AEGIS] Active Firewall Rules ({} total):", rules.len()).cyan());
                for r in rules.iter().take(20) {
                    println!("  - {:<40} [{:?}] [{:?}]", r.name, r.direction, r.action);
                }
                if rules.len() > 20 {
                    println!("  ... and {} more rules.", rules.len() - 20);
                }
            }
        },
        Commands::Scan { path } => {
            println!("[AEGIS] Invoking CyberDefender SHA-256 integrity scanner on: {}", path);
            let status = std::process::Command::new("cargo")
                .args(["run", "-q", "-p", "cyberdefender", "--", "scan", &path])
                .status()?;
            if !status.success() {
                eprintln!("[AEGIS] Scan exited with status: {:?}", status.code());
            }
        }
        Commands::Dns { action } => match action {
            DnsCommands::Resolve { domain } => {
                println!("[AEGIS] Resolving {} via Cloudflare Encrypted DoH...", domain);
                let _ = std::process::Command::new("cargo")
                    .args(["run", "-q", "-p", "cyberdns", "--", "lookup", &domain])
                    .status()?;
            }
            DnsCommands::Block { domain } => {
                println!("[AEGIS] Adding {} to local threat sinkhole...", domain);
                let _ = std::process::Command::new("cargo")
                    .args(["run", "-q", "-p", "cyberdns", "--", "block", &domain])
                    .status()?;
            }
        },
        Commands::Edr { action } => match action {
            EdrCommands::Sockets => {
                let _ = std::process::Command::new("cargo")
                    .args(["run", "-q", "-p", "cyberedr", "--", "sockets"])
                    .status()?;
            }
            EdrCommands::Audit => {
                let _ = std::process::Command::new("cargo")
                    .args(["run", "-q", "-p", "cyberedr", "--", "audit"])
                    .status()?;
            }
        },
        Commands::Posture => {
            println!("[AEGIS] Running 5-Pillar Zero-Trust Endpoint Posture Audit...");
            let _ = std::process::Command::new("cargo")
                .args(["run", "-q", "-p", "cyberid", "--", "posture"])
                .status()?;
        }
        Commands::Daemon { rpc_cmd } => {
            println!("[AEGIS] Connecting to aegisd via Universal IPC...");
            let req = s2o_bus::IpcRequest {
                id: 1,
                method: rpc_cmd,
                params: serde_json::Value::Null,
            };

            match s2o_bus::AegisIpcClient::call(&req).await {
                Ok(resp) => {
                    if resp.success {
                        println!("{}", format!("[AEGIS IPC] SUCCESS: {:?}", resp.data).green().bold());
                    } else {
                        println!("{}", format!("[AEGIS IPC] ERROR: {:?}", resp.error).red().bold());
                    }
                }
                Err(e) => {
                    println!("{}", format!("[AEGIS IPC] Failed to communicate with daemon: {e}").yellow());
                    println!("Make sure 'aegisd start' is running in the background.");
                }
            }
        }
    }

    Ok(())
}
