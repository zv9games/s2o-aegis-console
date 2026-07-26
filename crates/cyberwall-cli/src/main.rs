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
    /// List active OS firewall filtering rules
    Rules,
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
        Commands::Rules => {
            let rules = engine.list_rules().await?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "            S2O Cyberwall — OS firewall rules            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Count: {}", rules.len());
            for (idx, rule) in rules.iter().enumerate() {
                println!("{}. {}", idx + 1, rule.name.bold());
                println!(
                    "   enabled={} action={:?} direction={:?}",
                    rule.enabled, rule.action, rule.direction
                );
                println!("{}", "---------------------------------------------------------".cyan());
            }
        }
    }

    Ok(())
}
