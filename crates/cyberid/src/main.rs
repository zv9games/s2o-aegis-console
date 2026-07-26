use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::FirewallEngine;

#[derive(Parser)]
#[command(name = "cyberid")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.1.0")]
#[command(about = "S2O CyberID: posture + identity (Phase 2/3)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// Device posture from real Cyberwall / Defender signals only
    Posture,
    Authenticate { user: String },
    Sessions,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "        S2O CyberID (Phase 2/3 target)                  ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Implemented       : {}", "partial posture from Cyberwall/Defender".green());
            println!(" Not implemented   : {}", "OIDC/FIDO2 auth, session store, PAM".red());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Posture => {
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "      CyberID endpoint posture (honest signals)        ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(
                " Firewall enabled  : {}",
                if st.enabled {
                    "PASS".green().bold()
                } else {
                    "FAIL".red().bold()
                }
            );
            println!(
                " Defender service  : {}",
                if st.defender_active {
                    "PASS".green().bold()
                } else {
                    "FAIL / unknown".red().bold()
                }
            );
            println!(" EDR hooks         : {}", "NOT CHECKED (Phase 2)".yellow());
            println!(" Disk encryption   : {}", "NOT CHECKED".yellow());
            let score = (if st.enabled { 50 } else { 0 }) + (if st.defender_active { 50 } else { 0 });
            println!(" Partial score     : {} / 100 (firewall+defender only)", score);
            println!("{}", "=========================================================".cyan());
        }
        Commands::Authenticate { user } => {
            eprintln!("[cyberid] authenticate not implemented for '{user}' (Phase 3).");
            std::process::exit(2);
        }
        Commands::Sessions => {
            println!("[cyberid] no sessions — auth store not implemented.");
        }
    }

    Ok(())
}
