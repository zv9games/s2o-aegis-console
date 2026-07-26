use clap::{Parser, Subcommand};
use colored::*;
use s2o_store::EventStore;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cybersiem")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.1.0")]
#[command(about = "S2O CyberLog SIEM: local event store reader (Phase 2 full SIEM)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberLog status
    Status {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    /// Collect is not implemented (use aegisd / product engines to emit)
    Collect,
    /// Export recent events from local JSONL store
    Export {
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Display recent events from local JSONL store
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { event_log } => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "       S2O CyberLog (Phase 2 target)                     ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Implemented       : {}", "read local Aegis JSONL event store".green());
            println!(" Not implemented   : {}", "live collectors, correlation, remote EPS".red());
            if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                println!(" Event log         : {}", event_log.display());
                println!(" Stored events     : {}", store.count()?);
            } else {
                println!(
                    " Event log         : {} (missing — run `aegisd start`)",
                    event_log.display()
                );
            }
            println!("{}", "=========================================================".cyan());
        }
        Commands::Collect => {
            eprintln!("[cyberlog] live collect not implemented (Phase 2).");
            eprintln!("Emit events via aegisd / product engines into the JSONL store.");
            std::process::exit(2);
        }
        Commands::Export { format, event_log, limit } => {
            if !event_log.exists() {
                eprintln!("[cyberlog] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            if format.eq_ignore_ascii_case("json") {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for ev in events {
                    println!(
                        "<14>1 {} {} {:?} {:?} - {}",
                        ev.ts.to_rfc3339(),
                        ev.host_id,
                        ev.product,
                        ev.kind,
                        ev.message
                    );
                }
            }
        }
        Commands::Events { event_log, limit } => {
            if !event_log.exists() {
                println!("[cyberlog] no events yet — run `aegisd start` to seed the store.");
                return Ok(());
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "          CyberLog — recent Aegis events                 ".bold().green());
            println!("{}", "=========================================================".cyan());
            if events.is_empty() {
                println!("(empty store)");
            }
            for ev in events {
                println!(
                    "[{}] [{:?}] {:?} -> {}",
                    ev.ts.to_rfc3339().cyan(),
                    ev.severity,
                    ev.product,
                    ev.message
                );
                println!("{}", "---------------------------------------------------------".cyan());
            }
        }
    }

    Ok(())
}
