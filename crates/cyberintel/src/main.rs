use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(name = "cyberintel")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.1.0")]
#[command(about = "S2O ThreatGrid Intel: IOC feeds & reputation (Phase 2)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Lookup { target: String },
    Sync,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "      S2O ThreatGrid (Phase 2 target)                    ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" IOC database      : {}", "NOT BUILT".red().bold());
            println!(" Feeds             : {}", "planned: abuse.ch, OTX, MISP".yellow());
            println!(" Implemented       : {}", "CLI scaffold only".yellow());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Lookup { target } => {
            eprintln!("[threatgrid] lookup not implemented for '{target}' (Phase 2).");
            std::process::exit(2);
        }
        Commands::Sync => {
            eprintln!("[threatgrid] feed sync not implemented (Phase 2).");
            std::process::exit(2);
        }
    }

    Ok(())
}
