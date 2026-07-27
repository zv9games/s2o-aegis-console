//! S2O CyberDefender — SHA-256 scan + Defender service probe + events (Phase 2 shell).

use clap::{Parser, Subcommand};
use colored::*;
use sha2::{Digest, Sha256};
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberdefender")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O CyberDefender: hash scan + Defender health (Phase 2 shell)", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// SHA-256 hash a file (directory: first-level files, max 32)
    Scan {
        path: String,
    },
    UpdateDefs,
    Realtime {
        action: String,
    },
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit(event_log: &Path, action: EventAction, severity: Severity, message: impl Into<String>, attrs: &[(&str, serde_json::Value)], ioc: Option<Ioc>) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::CyberDefender,
            EventKind::File,
            action,
            severity,
            message,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, v.clone());
        }
        if let Some(i) = ioc {
            ev = ev.with_ioc(i);
        }
        let _ = store.append(&ev);
    }
}

fn calculate_file_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_targets(path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if path.is_dir() {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                files.push(p);
            }
            if files.len() >= 32 {
                break;
            }
        }
        return Ok(files);
    }
    Err(format!("path not found: {}", path.display()).into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let is_active = tokio::task::spawn_blocking(|| {
                s2o_net_lib::defender::DefenderController::is_defender_active()
            })
            .await?;

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "      S2O CyberDefender (Phase 2 shell)                  "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " WinDefend service : {}",
                if is_active {
                    "Running".green().bold()
                } else {
                    "Not running / query failed".red().bold()
                }
            );
            println!(
                " Implemented       : {}",
                "SHA-256 file/dir scan; Defender service query; events".green()
            );
            println!(
                " Not implemented   : {}",
                "YARA engine, realtime FS shield, cloud defs".red()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );

            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("cyberdefender status defender_active={is_active}"),
                &[("defender_active", serde_json::json!(is_active))],
                None,
            );
        }
        Commands::Scan { path } => {
            let root = PathBuf::from(&path);
            println!(
                "{}",
                format!("[cyberdefender] hashing (no YARA yet): '{}'...", root.display()).cyan()
            );

            let targets = match collect_targets(&root) {
                Ok(t) if !t.is_empty() => t,
                Ok(_) => {
                    eprintln!("{}", "[cyberdefender] no files to scan".yellow());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("{}", format!("Scan Error: {e}").red());
                    emit(
                        &cli.event_log,
                        EventAction::Failed,
                        Severity::Medium,
                        format!("scan failed: {e}"),
                        &[("path", serde_json::json!(path))],
                        None,
                    );
                    std::process::exit(1);
                }
            };

            let mut hashed = 0u32;
            for t in &targets {
                match calculate_file_hash(t) {
                    Ok(hash) => {
                        hashed += 1;
                        println!(
                            "{}",
                            "---------------------------------------------------------".cyan()
                        );
                        println!(" Target File  : {}", t.display().to_string().bold());
                        println!(" SHA-256 Hash : {}", hash.yellow());
                        println!(
                            " Verdict      : {}",
                            "hash only — malware match engine not implemented"
                                .yellow()
                                .bold()
                        );
                        emit(
                            &cli.event_log,
                            EventAction::Observed,
                            Severity::Info,
                            format!("file hashed: {}", t.display()),
                            &[
                                ("path", serde_json::json!(t.display().to_string())),
                                ("sha256", serde_json::json!(hash)),
                                ("verdict", serde_json::json!("hash_only")),
                            ],
                            Some(Ioc::Hash(hash)),
                        );
                    }
                    Err(e) => {
                        eprintln!("{}", format!("  skip {}: {e}", t.display()).red());
                    }
                }
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" Files hashed: {hashed}/{}", targets.len());
        }
        Commands::UpdateDefs => {
            eprintln!("[cyberdefender] signature update not implemented (Phase 2).");
            std::process::exit(2);
        }
        Commands::Realtime { action } => {
            eprintln!(
                "[cyberdefender] realtime shield not implemented (requested action={action})."
            );
            std::process::exit(2);
        }
    }

    Ok(())
}
