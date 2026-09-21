use clap::{Parser, Subcommand};
use colored::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

// Known test and malicious hashes for fast signature matching
const KNOWN_THREAT_HASHES: &[(&str, &str)] = &[
    // EICAR standard antivirus test file
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-AV-Test-File"),
    ("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", "EICAR-Standard-AV-Test-File-CRLF"),
    // WannaCry sample
    ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "Ransomware.WannaCry.A"),
    // NotPetya sample
    ("027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", "Ransomware.NotPetya.A"),
    // Emotet loader
    ("41d0442334f35422911b3f70f86ab59f77222f290962b3256017e50246697b58", "Trojan.Emotet.Generic"),
];

#[derive(Parser)]
#[command(name = "cyberdefender")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.1.0")]
#[command(about = "S2O CyberDefender AV: Real-Time Anti-Malware & Signature Scanner CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberDefender status, Windows Defender engine metrics, and active signatures
    Status,
    /// Perform a high-speed SHA-256 threat scan on a file or recursively on a directory
    Scan {
        /// Absolute or relative path to target file or directory
        path: String,
        /// Recursive search in subdirectories (default: true)
        #[arg(short, long, default_value_t = true)]
        recursive: bool,
    },
    /// Trigger a native Windows Defender quick scan (MpCmdRun.exe)
    ScanNative,
    /// Trigger an automated update of Windows Defender threat definitions
    UpdateDefs,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct MpStatusOutput {
    AntivirusEnabled: Option<bool>,
    RealTimeProtectionEnabled: Option<bool>,
    AntivirusSignatureVersion: Option<String>,
}

fn query_mp_status() -> Option<MpStatusOutput> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion | ConvertTo-Json",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&text).ok()
    } else {
        None
    }
}

fn calculate_file_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_files(target: &Path, recursive: bool, list: &mut Vec<PathBuf>) {
    if target.is_file() {
        list.push(target.to_path_buf());
    } else if target.is_dir() {
        if let Ok(entries) = std::fs::read_dir(target) {
            for entry in entries.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    list.push(p);
                } else if p.is_dir() && recursive {
                    collect_files(&p, recursive, list);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let is_service_active = tokio::task::spawn_blocking(|| {
                s2o_net_lib::defender::DefenderController::is_defender_active()
            })
            .await?;

            let mp_info = tokio::task::spawn_blocking(query_mp_status).await?;

            println!("{}", "=========================================================".cyan());
            println!("{}", "            SPLIT2OPS CYBERDEFENDER AV ENGINE            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(
                " WinDefend Service : {}",
                if is_service_active {
                    "RUNNING (Active)".green().bold()
                } else {
                    "STOPPED / Inactive".red().bold()
                }
            );

            if let Some(info) = mp_info {
                println!(
                    " Real-Time Shield  : {}",
                    if info.RealTimeProtectionEnabled.unwrap_or(false) {
                        "ENABLED (Shield On)".green().bold()
                    } else {
                        "DISABLED (Shield Off)".red().bold()
                    }
                );
                println!(
                    " Signature Version : {}",
                    info.AntivirusSignatureVersion.unwrap_or_else(|| "Unknown".into()).yellow()
                );
            } else {
                println!(" Real-Time Shield  : {}", "Query unavailable".yellow());
            }

            println!(" S2O Known Signatures: {}", format!("{} indexed IOC hashes", KNOWN_THREAT_HASHES.len()).bold());
            println!(" MpCmdRun Helper   : {}", match s2o_net_lib::defender::DefenderController::find_mp_cmd_run() {
                Some(p) => p.display().to_string().green(),
                None => "Not found".yellow(),
            });
            println!("{}", "=========================================================".cyan());
        }
        Commands::Scan { path, recursive } => {
            let target_path = Path::new(&path);
            if !target_path.exists() {
                eprintln!("{}", format!("[cyberdefender] target path does not exist: '{path}'").red());
                std::process::exit(1);
            }

            println!("{}", format!("[cyberdefender] scanning target: '{}' (recursive={})...", path, recursive).cyan());

            let mut files_to_scan = Vec::new();
            collect_files(target_path, recursive, &mut files_to_scan);

            println!("{}", format!("[cyberdefender] discovered {} files to inspect.", files_to_scan.len()).bold());
            println!("{}", "---------------------------------------------------------".cyan());

            let mut threat_count = 0;
            let mut scanned_count = 0;

            for file in &files_to_scan {
                match calculate_file_hash(file) {
                    Ok(hash) => {
                        scanned_count += 1;
                        let matched_threat = KNOWN_THREAT_HASHES.iter().find(|(h, _)| *h == hash.as_str());

                        if let Some((_, threat_name)) = matched_threat {
                            threat_count += 1;
                            println!(
                                "{} File: {} | Hash: {} | Threat: {}",
                                "[THREAT DETECTED]".red().bold(),
                                file.display().to_string().bold(),
                                hash.yellow(),
                                threat_name.red().bold()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Skipping {}: {}", file.display(), e);
                    }
                }
            }

            println!("{}", "---------------------------------------------------------".cyan());
            if threat_count > 0 {
                println!(
                    "{}",
                    format!(
                        "[cyberdefender] SCAN ALERT: {} infected file(s) identified among {} scanned files!",
                        threat_count, scanned_count
                    )
                    .red()
                    .bold()
                );
                std::process::exit(1);
            } else {
                println!(
                    "{}",
                    format!(
                        "[cyberdefender] SCAN CLEAN: All {} file(s) verified against threat database. No matches found.",
                        scanned_count
                    )
                    .green()
                    .bold()
                );
            }
        }
        Commands::ScanNative => {
            println!("{}", "[cyberdefender] launching native Windows Defender scan via MpCmdRun...".cyan());
            tokio::task::spawn_blocking(|| {
                s2o_net_lib::defender::DefenderController::run_scan_native()
            })
            .await?
            .map_err(|e| format!("Native scan execution error: {e}"))?;
            println!("{}", "[cyberdefender] OK: native scan completed successfully.".green().bold());
        }
        Commands::UpdateDefs => {
            println!("{}", "[cyberdefender] triggering Defender signature update...".cyan());
            tokio::task::spawn_blocking(|| {
                s2o_net_lib::defender::DefenderController::update_defender_native()
            })
            .await?
            .map_err(|e| format!("Definition update error: {e}"))?;
            println!("{}", "[cyberdefender] OK: signatures successfully refreshed.".green().bold());
        }
    }

    Ok(())
}
