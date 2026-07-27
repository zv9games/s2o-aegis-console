use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::{
    create_firewall_engine, open_default_store, wall_set_enabled, wall_set_outbound_block,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cyberwall")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.0.0")]
#[command(about = "Split2ops Cyberwall Enterprise Firewall CLI (multi-OS T0)", long_about = None)]
struct Cli {
    /// Append policy actions to Aegis event log
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    /// Skip writing events
    #[arg(long, global = true)]
    no_events: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display live OS firewall status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Enable the OS firewall across profiles (where supported)
    Enable,
    /// Disable the OS firewall (where safely supported)
    Disable,
    /// Engage emergency outbound isolation
    Lock,
    /// Disengage outbound isolation
    Unlock,
    /// List active OS firewall filtering rules
    Rules,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let engine = create_firewall_engine();
    let store = if cli.no_events {
        None
    } else {
        Some(open_default_store(&cli.event_log)?)
    };
    let store_ref = store.as_ref().map(|s| s.as_ref());

    match cli.command {
        Commands::Status { json } => {
            let status = cyberwall_core::FirewallEngine::get_status(engine.as_ref()).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "       SPLIT2OPS SOFTWARE CYBERWALL CLI                 "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Platform Engine   : {}", status.platform.bold());
                println!(" Backend Driver    : {}", status.backend_driver.yellow());
                println!(
                    " Firewall Status   : {}",
                    if status.enabled {
                        "ENABLED".green().bold()
                    } else {
                        "DISABLED".red().bold()
                    }
                );
                println!(
                    " Outbound Shield   : {}",
                    if status.outbound_blocked {
                        "BLOCKED".red().bold()
                    } else {
                        "NORMAL".green()
                    }
                );
                println!(
                    " Defender / AV     : {}",
                    if status.defender_active {
                        "ACTIVE".green()
                    } else {
                        "INACTIVE / N/A".yellow()
                    }
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(
                    " Private Profile   : {}",
                    if status.profile_private {
                        "ON".green()
                    } else {
                        "OFF".red()
                    }
                );
                println!(
                    " Public Profile    : {}",
                    if status.profile_public {
                        "ON".green()
                    } else {
                        "OFF".red()
                    }
                );
                println!(
                    " Domain Profile    : {}",
                    if status.profile_domain {
                        "ON".green()
                    } else {
                        "OFF".red()
                    }
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
        }
        Commands::Enable => {
            println!("[cyberwall] enabling firewall...");
            wall_set_enabled(&engine, true, store_ref).await?;
            let status = cyberwall_core::FirewallEngine::get_status(engine.as_ref()).await?;
            if status.enabled {
                println!(
                    "{}",
                    "[cyberwall] OK: firewall reports enabled.".green().bold()
                );
            } else {
                eprintln!(
                    "{}",
                    "[cyberwall] command returned OK but status still disabled."
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        }
        Commands::Disable => {
            println!("[cyberwall] disabling firewall...");
            wall_set_enabled(&engine, false, store_ref).await?;
            let status = cyberwall_core::FirewallEngine::get_status(engine.as_ref()).await?;
            if !status.enabled {
                println!(
                    "{}",
                    "[cyberwall] OK: firewall reports disabled.".yellow().bold()
                );
            } else {
                eprintln!(
                    "{}",
                    "[cyberwall] command returned OK but status still enabled."
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        }
        Commands::Lock => {
            println!("[cyberwall] enabling outbound block...");
            wall_set_outbound_block(&engine, true, store_ref).await?;
            let status = cyberwall_core::FirewallEngine::get_status(engine.as_ref()).await?;
            if status.outbound_blocked {
                println!(
                    "{}",
                    "[cyberwall] OK: outbound default is BLOCK.".red().bold()
                );
            } else {
                eprintln!(
                    "{}",
                    "[cyberwall] lock returned OK but outbound not blocked."
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        }
        Commands::Unlock => {
            println!("[cyberwall] restoring outbound allow...");
            wall_set_outbound_block(&engine, false, store_ref).await?;
            let status = cyberwall_core::FirewallEngine::get_status(engine.as_ref()).await?;
            if !status.outbound_blocked {
                println!(
                    "{}",
                    "[cyberwall] OK: outbound traffic allowed.".green().bold()
                );
            } else {
                eprintln!(
                    "{}",
                    "[cyberwall] unlock returned OK but outbound still blocked."
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        }
        Commands::Rules => {
            let rules = cyberwall_core::FirewallEngine::list_rules(engine.as_ref()).await?;
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "            S2O Cyberwall — OS firewall rules            "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Count: {}", rules.len());
            for (idx, rule) in rules.iter().enumerate() {
                println!("{}. {}", idx + 1, rule.name.bold());
                println!(
                    "   enabled={} action={:?} direction={:?}",
                    rule.enabled, rule.action, rule.direction
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
            }
        }
    }

    Ok(())
}
