use clap::{Parser, Subcommand};
use colored::*;
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.0.0")]
#[command(about = "S2O CyberDNS Guard: Encrypted DNS-over-HTTPS (DoH) Resolver & Category Web Filter", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberDNS engine status, active DoH resolver, and blocklist metrics
    Status,
    /// Resolve a domain name securely over encrypted DNS-over-HTTPS (DoH)
    Resolve {
        /// The target domain name to resolve
        domain: String,
    },
    /// Add a domain to the local threat blocklist
    Block {
        /// Target domain name to block
        domain: String,
    },
    /// Start the local S2O CyberDNS Guard proxy server
    Serve {
        /// Local listen address (default: 127.0.0.1:5353)
        #[arg(short, long, default_value = "127.0.0.1:5353")]
        listen: String,
    },
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(default)]
    data: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DohResponse {
    Status: u32,
    Answer: Option<Vec<DohAnswer>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "        S2O CyberDNS Guard (Phase 1 target)              ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Implemented       : {}", "DoH resolve via Cloudflare (resolve cmd)".green());
            println!(" Not implemented   : {}", "local proxy serve, persistent blocklist, DoT".red());
            println!(" Primary Resolver  : {}", "https://cloudflare-dns.com/dns-query".yellow());
            println!(" Roadmap phase     : {}", "Aegis Edge Phase 1".bold());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Resolve { domain } => {
            println!("{}", format!("[CYBERDNS] Resolving domain '{}' via Encrypted DoH...", domain).cyan());

            let url = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", domain);
            let client = reqwest::Client::new();
            let res = client
                .get(&url)
                .header("accept", "application/dns-json")
                .send()
                .await?;

            if res.status().is_success() {
                let doh: DohResponse = res.json().await?;
                println!("{}", "---------------------------------------------------------".cyan());
                if let Some(answers) = doh.Answer {
                    for ans in answers {
                        println!(" Domain Record : {}", ans.name.bold());
                        println!(" Type Code     : {}", ans.record_type);
                        println!(" Resolved IP   : {}", ans.data.green().bold());
                        println!("{}", "---------------------------------------------------------".cyan());
                    }
                } else {
                    println!("{}", "NXDOMAIN: No DNS records found for this target.".yellow());
                }
            } else {
                println!("{}", format!("DoH HTTP Error: {}", res.status()).red());
            }
        }
        Commands::Block { domain } => {
            eprintln!(
                "[cyberdns] blocklist persistence not implemented yet (wanted: {}).",
                domain
            );
            eprintln!("Use resolve for DoH lookups; block ships in Phase 1.");
            std::process::exit(2);
        }
        Commands::Serve { listen } => {
            eprintln!(
                "[cyberdns] local proxy serve not implemented (requested listen={listen})."
            );
            eprintln!("Phase 1 will bind a real DoH/forwarding proxy.");
            std::process::exit(2);
        }
    }

    Ok(())
}
