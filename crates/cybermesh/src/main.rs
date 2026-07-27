//! S2O CyberMesh — WireGuard key material + honest tunnel status (Phase 3 start).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use colored::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "cybermesh")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O CyberMesh: WireGuard keygen + tunnel orchestration (Phase 3)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Up,
    Down,
    Peers,
    /// Real X25519 WireGuard-compatible keypair (base64)
    Genkey {
        /// Also write private key to path (optional)
        #[arg(long)]
        write_private: Option<String>,
    },
    /// Derive public key from a base64 private key
    Pubkey {
        private_b64: String,
    },
}

fn wg_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    let priv_b64 = B64.encode(secret.to_bytes());
    let pub_b64 = B64.encode(public.as_bytes());
    (priv_b64, pub_b64)
}

fn wg_pubkey_from_private(private_b64: &str) -> Result<String, String> {
    let bytes = B64
        .decode(private_b64.trim())
        .map_err(|e| format!("base64 decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("private key must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(B64.encode(public.as_bytes()))
}

fn wg_tool_present() -> bool {
    std::process::Command::new("wg")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || std::process::Command::new("wg.exe")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let wg = wg_tool_present();
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "        S2O CyberMesh (Phase 3 start)                    "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Tunnel status     : {}",
                "NOT BROUGHT UP (orchestrator later)".red().bold()
            );
            println!(
                " system wg tool    : {}",
                if wg {
                    "found".green()
                } else {
                    "not found (optional)".yellow()
                }
            );
            println!(
                " Implemented       : {}",
                "real X25519 genkey/pubkey (WireGuard-compatible)".green()
            );
            println!(
                " Not implemented   : {}",
                "tunnel up/down, peer mesh, boringtun embed".red()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Up => {
            eprintln!("[cybermesh] tunnel up not implemented (Phase 3).");
            eprintln!("Keys: cybermesh genkey — then configure system WireGuard.");
            std::process::exit(2);
        }
        Commands::Down => {
            eprintln!("[cybermesh] tunnel down not implemented (Phase 3).");
            std::process::exit(2);
        }
        Commands::Peers => {
            println!("[cybermesh] no peers — mesh not running (Phase 3).");
            if wg_tool_present() {
                println!("Hint: `wg show` for system interfaces.");
            }
        }
        Commands::Genkey { write_private } => {
            let (privkey, pubkey) = wg_keypair();
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "  WireGuard X25519 keypair (real Curve25519)             "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Private : {}", privkey.yellow());
            println!(" Public  : {}", pubkey.green());
            if let Some(path) = write_private {
                std::fs::write(&path, format!("{privkey}\n"))?;
                println!(" Wrote private key to {path}");
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Pubkey { private_b64 } => match wg_pubkey_from_private(&private_b64) {
            Ok(p) => println!("{p}"),
            Err(e) => {
                eprintln!("[cybermesh] {e}");
                std::process::exit(1);
            }
        },
    }

    Ok(())
}
