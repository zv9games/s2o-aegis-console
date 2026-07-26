use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(name = "cyberedr")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.0.0")]
#[command(about = "S2O CyberEDR Agent: Deep Kernel Event Telemetry & Behavioral Threat Detection CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberEDR agent status, active ETW/eBPF kernel hooks, and threat metrics
    Status,
    /// Display active network socket process connections tracked by kernel telemetry
    Processes,
    /// Display active behavioral threat alerts detected by kernel telemetry
    Alerts,
    /// Attach live event stream tracer to kernel ETW/eBPF tracepoints
    Trace,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "        S2O CyberEDR (Phase 2 target)                    ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Implemented       : {}", "TCP table via IP Helper (processes cmd)".green());
            println!(" Not implemented   : {}", "ETW hooks, behavioral ML, alert engine".red());
            println!(" Kernel hooks      : {}", "NONE ATTACHED".red().bold());
            println!(" Roadmap phase     : {}", "Aegis Endpoint Phase 2".bold());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Processes => {
            let conns = tokio::task::spawn_blocking(|| {
                s2o_net_lib::telemetry::get_active_tcp_connections()
            })
            .await?;

            println!("{}", "=========================================================".cyan());
            println!("{}", "       Active TCP connections (IP Helper telemetry)      ".bold().green());
            println!("{}", "=========================================================".cyan());
            for c in conns.iter().take(32) {
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
            println!("{}", "---------------------------------------------------------".cyan());
            println!(" Total sockets: {}", conns.len());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Alerts => {
            println!("{}", "[cyberedr] alert engine not implemented (Phase 2).".yellow());
            println!("No behavioral alerts stored.");
        }
        Commands::Trace => {
            eprintln!("[cyberedr] ETW/eBPF live trace not implemented (Phase 2).");
            std::process::exit(2);
        }
    }

    Ok(())
}
