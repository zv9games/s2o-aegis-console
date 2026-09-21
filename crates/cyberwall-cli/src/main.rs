use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::FirewallEngine;

#[derive(Parser)]
#[command(name = "cyberwall")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.0.0")]
#[command(about = "Split2ops Cyberwall Enterprise Commercial Firewall CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display live OS firewall status, profile breakdown, and backend engine info
    Status {
        /// Output status as JSON
        #[arg(long)]
        json: bool,
    },
    /// Enable the OS firewall across all profiles
    Enable,
    /// Disable the OS firewall across all profiles
    Disable,
    /// Engage emergency outbound isolation shield (airplane/lockdown mode)
    Lock,
    /// Disengage outbound isolation shield
    Unlock,
    /// List active OS firewall filtering rules with optional filter
    Rules {
        /// Filter by rule direction: in or out
        #[arg(long)]
        dir: Option<String>,
        /// Filter by rule action: allow or block
        #[arg(long)]
        action: Option<String>,
        /// Search string for rule name
        #[arg(long)]
        search: Option<String>,
        /// Output rules as JSON
        #[arg(long)]
        json: bool,
    },
    /// Block an inbound or outbound port
    BlockPort {
        /// Port number (e.g. 445, 8080)
        port: u16,
        /// Protocol: tcp or udp (default: tcp)
        #[arg(long, default_value = "tcp")]
        protocol: String,
        /// Direction: in or out (default: in)
        #[arg(long, default_value = "in")]
        dir: String,
        /// Custom rule name
        #[arg(long)]
        name: Option<String>,
    },
    /// Allow an inbound or outbound port
    AllowPort {
        /// Port number (e.g. 80, 443)
        port: u16,
        /// Protocol: tcp or udp (default: tcp)
        #[arg(long, default_value = "tcp")]
        protocol: String,
        /// Direction: in or out (default: in)
        #[arg(long, default_value = "in")]
        dir: String,
        /// Custom rule name
        #[arg(long)]
        name: Option<String>,
    },
    /// Block all traffic to or from a remote IP address
    BlockIp {
        /// Remote IPv4 or IPv6 address
        ip: String,
        /// Direction: in or out (default: out)
        #[arg(long, default_value = "out")]
        dir: String,
        /// Custom rule name
        #[arg(long)]
        name: Option<String>,
    },
    /// Block network communication for an executable application
    BlockApp {
        /// Path to application executable
        path: String,
        /// Direction: in or out (default: out)
        #[arg(long, default_value = "out")]
        dir: String,
        /// Custom rule name
        #[arg(long)]
        name: Option<String>,
    },
    /// Allow network communication for an executable application
    AllowApp {
        /// Path to application executable
        path: String,
        /// Direction: in or out (default: in)
        #[arg(long, default_value = "in")]
        dir: String,
        /// Custom rule name
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete a firewall rule by exact name
    DeleteRule {
        /// Name of the rule to remove
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let engine = WindowsFirewallEngine::new();

    match cli.command {
        Commands::Status { json } => {
            let status = engine.get_status().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("{}", "=========================================================".cyan());
                println!("{}", "       SPLIT2OPS SOFTWARE CYBERWALL ENTERPRISE CLI       ".bold().green());
                println!("{}", "=========================================================".cyan());
                println!(" Platform Engine   : {}", status.platform.bold());
                println!(" Backend Driver    : {}", status.backend_driver.yellow());
                println!(" Firewall Status   : {}", if status.enabled { "ENABLED (Green)".green().bold() } else { "DISABLED (Red)".red().bold() });
                println!(" Outbound Shield   : {}", if status.outbound_blocked { "BLOCKED (Red)".red().bold() } else { "NORMAL (Allow)".green() });
                println!(" Windows Defender  : {}", if status.defender_active { "ACTIVE (Green)".green() } else { "INACTIVE (Red)".red() });
                println!("{}", "---------------------------------------------------------".cyan());
                println!(" Private Profile   : {}", if status.profile_private { "ON".green() } else { "OFF".red() });
                println!(" Public Profile    : {}", if status.profile_public { "ON".green() } else { "OFF".red() });
                println!(" Domain Profile    : {}", if status.profile_domain { "ON".green() } else { "OFF".red() });
                println!("{}", "=========================================================".cyan());
            }
        }
        Commands::Enable => {
            println!("[cyberwall] enabling Windows Firewall (COM, netsh fallback)...");
            engine.set_enabled(true).await?;
            let status = engine.get_status().await?;
            if status.enabled {
                println!("{}", "[cyberwall] OK: firewall enabled on interactive profiles.".green().bold());
            } else {
                eprintln!("{}", "[cyberwall] command returned OK but profiles still report disabled.".red().bold());
                std::process::exit(1);
            }
        }
        Commands::Disable => {
            println!("[cyberwall] disabling Windows Firewall (COM, netsh fallback)...");
            engine.set_enabled(false).await?;
            let status = engine.get_status().await?;
            if !status.enabled {
                println!("{}", "[cyberwall] OK: firewall disabled on interactive profiles.".yellow().bold());
            } else {
                eprintln!("{}", "[cyberwall] command returned OK but profiles still report enabled.".red().bold());
                std::process::exit(1);
            }
        }
        Commands::Lock => {
            println!("[cyberwall] enabling outbound block (airplane / isolation)...");
            engine.set_outbound_block(true).await?;
            let status = engine.get_status().await?;
            if status.outbound_blocked {
                println!("{}", "[cyberwall] OK: outbound default action is BLOCK.".red().bold());
            } else {
                eprintln!("{}", "[cyberwall] lock returned OK but outbound not blocked.".red().bold());
                std::process::exit(1);
            }
        }
        Commands::Unlock => {
            println!("[cyberwall] restoring outbound allow (from snapshot or default)...");
            engine.set_outbound_block(false).await?;
            let status = engine.get_status().await?;
            if !status.outbound_blocked {
                println!("{}", "[cyberwall] OK: outbound traffic allowed.".green().bold());
            } else {
                eprintln!("{}", "[cyberwall] unlock returned OK but outbound still blocked.".red().bold());
                std::process::exit(1);
            }
        }
        Commands::Rules { dir, action, search, json } => {
            let filter_dir = match dir.as_deref() {
                Some("in") => Some(cyberwall_core::RuleDirection::Inbound),
                Some("out") => Some(cyberwall_core::RuleDirection::Outbound),
                _ => None,
            };
            let filter_act = match action.as_deref() {
                Some("allow") => Some(cyberwall_core::RuleAction::Allow),
                Some("block") => Some(cyberwall_core::RuleAction::Block),
                _ => None,
            };
            let filter = cyberwall_core::RuleFilter {
                direction: filter_dir,
                action: filter_act,
                protocol: None,
                port: None,
                search,
            };

            let rules = engine.list_rules_filtered(&filter).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rules)?);
            } else {
                println!("{}", "=========================================================".cyan());
                println!("{}", "            S2O Cyberwall — OS firewall rules            ".bold().green());
                println!("{}", "=========================================================".cyan());
                println!(" Total matching rules: {}", rules.len());
                for (idx, rule) in rules.iter().take(40).enumerate() {
                    let act_colored = match rule.action {
                        cyberwall_core::RuleAction::Allow => "ALLOW".green(),
                        cyberwall_core::RuleAction::Block => "BLOCK".red(),
                    };
                    println!("{}. {} [{}]", idx + 1, rule.name.bold(), act_colored);
                    println!(
                        "   enabled={} direction={:?}",
                        rule.enabled, rule.direction
                    );
                    println!("{}", "---------------------------------------------------------".cyan());
                }
                if rules.len() > 40 {
                    println!("... and {} more rules (use --search or --json for full list)", rules.len() - 40);
                }
            }
        }
        Commands::BlockPort { port, protocol, dir, name } => {
            let is_out = dir.eq_ignore_ascii_case("out");
            let proto = if protocol.eq_ignore_ascii_case("udp") {
                cyberwall_core::RuleProtocol::Udp
            } else {
                cyberwall_core::RuleProtocol::Tcp
            };
            let rule_name = name.unwrap_or_else(|| {
                format!("S2O-Block-Port-{}-{}-{}", protocol.to_uppercase(), port, if is_out { "Out" } else { "In" })
            });

            let rule = cyberwall_core::FirewallRule {
                name: rule_name.clone(),
                enabled: true,
                action: cyberwall_core::RuleAction::Block,
                direction: if is_out { cyberwall_core::RuleDirection::Outbound } else { cyberwall_core::RuleDirection::Inbound },
                profile: cyberwall_core::ProfileType::All,
                protocol: Some(proto),
                local_ports: if !is_out { Some(port.to_string()) } else { None },
                remote_ports: if is_out { Some(port.to_string()) } else { None },
                remote_addresses: None,
                application: None,
            };

            println!("[cyberwall] applying block rule: '{}' on port {}/{}...", rule_name, port, protocol);
            engine.add_rule(&rule).await?;
            println!("{}", format!("[cyberwall] OK: port {}/{} successfully blocked.", port, protocol).green().bold());
        }
        Commands::AllowPort { port, protocol, dir, name } => {
            let is_out = dir.eq_ignore_ascii_case("out");
            let proto = if protocol.eq_ignore_ascii_case("udp") {
                cyberwall_core::RuleProtocol::Udp
            } else {
                cyberwall_core::RuleProtocol::Tcp
            };
            let rule_name = name.unwrap_or_else(|| {
                format!("S2O-Allow-Port-{}-{}-{}", protocol.to_uppercase(), port, if is_out { "Out" } else { "In" })
            });

            let rule = cyberwall_core::FirewallRule {
                name: rule_name.clone(),
                enabled: true,
                action: cyberwall_core::RuleAction::Allow,
                direction: if is_out { cyberwall_core::RuleDirection::Outbound } else { cyberwall_core::RuleDirection::Inbound },
                profile: cyberwall_core::ProfileType::All,
                protocol: Some(proto),
                local_ports: if !is_out { Some(port.to_string()) } else { None },
                remote_ports: if is_out { Some(port.to_string()) } else { None },
                remote_addresses: None,
                application: None,
            };

            println!("[cyberwall] applying allow rule: '{}' on port {}/{}...", rule_name, port, protocol);
            engine.add_rule(&rule).await?;
            println!("{}", format!("[cyberwall] OK: port {}/{} successfully allowed.", port, protocol).green().bold());
        }
        Commands::BlockIp { ip, dir, name } => {
            let is_in = dir.eq_ignore_ascii_case("in");
            let rule_name = name.unwrap_or_else(|| {
                format!("S2O-Block-IP-{}-{}", ip.replace(['.', ':'], "_"), if is_in { "In" } else { "Out" })
            });

            let rule = cyberwall_core::FirewallRule {
                name: rule_name.clone(),
                enabled: true,
                action: cyberwall_core::RuleAction::Block,
                direction: if is_in { cyberwall_core::RuleDirection::Inbound } else { cyberwall_core::RuleDirection::Outbound },
                profile: cyberwall_core::ProfileType::All,
                protocol: Some(cyberwall_core::RuleProtocol::Any),
                local_ports: None,
                remote_ports: None,
                remote_addresses: Some(ip.clone()),
                application: None,
            };

            println!("[cyberwall] blocking traffic for IP '{}'...", ip);
            engine.add_rule(&rule).await?;
            println!("{}", format!("[cyberwall] OK: rule '{}' added for IP {}.", rule_name, ip).green().bold());
        }
        Commands::BlockApp { path, dir, name } => {
            let is_in = dir.eq_ignore_ascii_case("in");
            let file_name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("App");
            let rule_name = name.unwrap_or_else(|| format!("S2O-Block-App-{}", file_name));

            let rule = cyberwall_core::FirewallRule {
                name: rule_name.clone(),
                enabled: true,
                action: cyberwall_core::RuleAction::Block,
                direction: if is_in { cyberwall_core::RuleDirection::Inbound } else { cyberwall_core::RuleDirection::Outbound },
                profile: cyberwall_core::ProfileType::All,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                remote_addresses: None,
                application: Some(path.clone()),
            };

            println!("[cyberwall] blocking traffic for application '{}'...", path);
            engine.add_rule(&rule).await?;
            println!("{}", format!("[cyberwall] OK: rule '{}' added for {}.", rule_name, path).green().bold());
        }
        Commands::AllowApp { path, dir, name } => {
            let is_out = dir.eq_ignore_ascii_case("out");
            let file_name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("App");
            let rule_name = name.unwrap_or_else(|| format!("S2O-Allow-App-{}", file_name));

            let rule = cyberwall_core::FirewallRule {
                name: rule_name.clone(),
                enabled: true,
                action: cyberwall_core::RuleAction::Allow,
                direction: if is_out { cyberwall_core::RuleDirection::Outbound } else { cyberwall_core::RuleDirection::Inbound },
                profile: cyberwall_core::ProfileType::All,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                remote_addresses: None,
                application: Some(path.clone()),
            };

            println!("[cyberwall] allowing traffic for application '{}'...", path);
            engine.add_rule(&rule).await?;
            println!("{}", format!("[cyberwall] OK: rule '{}' added for {}.", rule_name, path).green().bold());
        }
        Commands::DeleteRule { name } => {
            println!("[cyberwall] removing firewall rule '{}'...", name);
            engine.delete_rule(&name).await?;
            println!("{}", format!("[cyberwall] OK: rule '{}' deleted.", name).green().bold());
        }
    }

    Ok(())
}
