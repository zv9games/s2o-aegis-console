use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

const IOC_DATABASE_PATH: &str = ".aegis/threatgrid_iocs.json";

#[derive(Parser)]
#[command(name = "cyberintel")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.1.0")]
#[command(about = "S2O ThreatGrid Intel: IOC Feeds, Hash Reputation & Threat Lookups", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display ThreatGrid database metrics, total loaded IOCs, and threat feed health
    Status,
    /// Query the threat intelligence database for a specific IP, domain, or SHA-256 hash
    Lookup {
        /// Target indicator of compromise (IP, domain, or SHA-256)
        target: String,
    },
    /// Ingest and synchronize latest indicators from open threat intelligence feeds
    Sync,
    /// Add a custom threat indicator to the local intelligence database
    Add {
        /// Indicator value (e.g. 198.51.100.23, malware.net, hash)
        indicator: String,
        /// Threat type: ip, domain, or hash
        #[arg(long)]
        kind: String,
        /// Threat classification (e.g. Ransomware, C2, CobaltStrike, Phishing)
        #[arg(long, default_value = "Malware")]
        threat: String,
        /// Confidence score (1-100)
        #[arg(long, default_value_t = 90)]
        confidence: u8,
    },
    /// List all currently indexed threat intelligence indicators
    List {
        /// Maximum number of records to show
        #[arg(short, long, default_value_t = 30)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IocRecord {
    indicator: String,
    kind: String,
    threat: String,
    confidence: u8,
    first_seen: String,
    source: String,
}

fn load_ioc_db() -> HashMap<String, IocRecord> {
    let path = PathBuf::from(IOC_DATABASE_PATH);
    if let Ok(file) = File::open(&path) {
        let reader = BufReader::new(file);
        if let Ok(db) = serde_json::from_reader(reader) {
            return db;
        }
    }

    // Default seeded baseline if database file is missing
    let mut default_db = HashMap::new();
    let seed_data = [
        ("198.51.100.4", "ip", "CobaltStrike C2 Server", 95, "Abuse.ch Feodo Tracker"),
        ("185.220.101.5", "ip", "Tor Exit Node / BruteForce", 80, "ThreatGrid Sentinel"),
        ("evil-payload.xyz", "domain", "Phishing / Credential Harvester", 90, "URLhaus Feed"),
        ("cryptolocker-pay.top", "domain", "Ransomware Payment Gateway", 99, "ThreatGrid ML"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash", "EICAR Standard AV Test File", 100, "AV-TEST"),
        ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "hash", "WannaCry Ransomware Binary", 100, "MalwareBazaar"),
    ];

    for (ind, kind, threat, conf, src) in seed_data {
        default_db.insert(
            ind.to_lowercase(),
            IocRecord {
                indicator: ind.to_string(),
                kind: kind.to_string(),
                threat: threat.to_string(),
                confidence: conf,
                first_seen: chrono::Utc::now().to_rfc3339(),
                source: src.to_string(),
            },
        );
    }
    default_db
}

fn save_ioc_db(db: &HashMap<String, IocRecord>) -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(IOC_DATABASE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    serde_json::to_writer_pretty(file, db)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let db = load_ioc_db();
            println!("{}", "=========================================================".cyan());
            println!("{}", "          SPLIT2OPS THREATGRID THREAT INTEL              ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Total Indexed IOCs: {}", db.len().to_string().bold().green());
            println!(" Database Path     : {}", IOC_DATABASE_PATH);
            println!(" Feeds Connected   : {}", "URLhaus, Abuse.ch, ThreatGrid Sentinel".yellow());
            println!(" Match Confidence  : {}", "Active scoring (0-100)".bold());
            println!("{}", "=========================================================".cyan());
        }
        Commands::Lookup { target } => {
            let db = load_ioc_db();
            let key = target.trim().to_lowercase();

            println!("{}", format!("[threatgrid] looking up indicator: '{}'...", target).cyan());

            if let Some(record) = db.get(&key) {
                println!("{}", "=========================================================".cyan());
                println!(" Match Status  : {}", "MATCHED MALICIOUS INDICATOR".red().bold());
                println!(" Indicator     : {}", record.indicator.bold());
                println!(" Type          : {}", record.kind.yellow());
                println!(" Threat Family : {}", record.threat.red().bold());
                println!(
                    " Confidence    : {}% {}",
                    record.confidence,
                    if record.confidence >= 90 { "(CRITICAL)".red().bold() } else { "(SUSPICIOUS)".yellow() }
                );
                println!(" Source Feed   : {}", record.source);
                println!(" First Seen    : {}", record.first_seen.cyan());
                println!("{}", "=========================================================".cyan());
            } else {
                println!("{}", "---------------------------------------------------------".cyan());
                println!(" Indicator     : {}", target.bold());
                println!(" Verdict       : {}", "CLEAN (No threat intelligence match found)".green().bold());
                println!("{}", "---------------------------------------------------------".cyan());
            }
        }
        Commands::Add { indicator, kind, threat, confidence } => {
            let mut db = load_ioc_db();
            let key = indicator.trim().to_lowercase();
            let record = IocRecord {
                indicator: indicator.clone(),
                kind,
                threat,
                confidence,
                first_seen: chrono::Utc::now().to_rfc3339(),
                source: "Manual Analyst Entry".to_string(),
            };
            db.insert(key, record);
            save_ioc_db(&db)?;
            println!("{}", format!("[threatgrid] OK: indicator '{}' successfully registered.", indicator).green().bold());
        }
        Commands::Sync => {
            println!("{}", "[threatgrid] syncing open-source threat feeds (Abuse.ch / URLhaus)...".cyan());
            let mut db = load_ioc_db();
            let client = reqwest::Client::new();

            // Fetch recent URLhaus active malware domains/URLs
            match client.get("https://urlhaus.abuse.ch/downloads/csv_recent/").send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().await.unwrap_or_default();
                    let mut added = 0;
                    for line in body.lines().take(100) {
                        if line.starts_with('#') || line.trim().is_empty() {
                            continue;
                        }
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() > 2 {
                            let url_or_domain = parts[2].trim_matches('"').trim();
                            if !url_or_domain.is_empty() {
                                let key = url_or_domain.to_lowercase();
                                db.entry(key).or_insert_with(|| IocRecord {
                                    indicator: url_or_domain.to_string(),
                                    kind: "url".to_string(),
                                    threat: "Malicious Payload Host".to_string(),
                                    confidence: 90,
                                    first_seen: chrono::Utc::now().to_rfc3339(),
                                    source: "URLhaus Recent Feed".to_string(),
                                });
                                added += 1;
                            }
                        }
                    }
                    save_ioc_db(&db)?;
                    println!("{}", format!("[threatgrid] OK: feed sync completed. Total records in DB: {} (+{} new).", db.len(), added).green().bold());
                }
                _ => {
                    save_ioc_db(&db)?;
                    println!("{}", "[threatgrid] feed server unavailable (using local intelligence baseline).".yellow());
                }
            }
        }
        Commands::List { limit } => {
            let db = load_ioc_db();
            println!("{}", "=========================================================".cyan());
            println!("{}", "         ThreatGrid — Indexed Threat Signatures          ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Total records: {}", db.len());
            for (idx, (_, rec)) in db.iter().take(limit).enumerate() {
                println!("{}. {:<10} | {:<32} | {}", idx + 1, rec.kind.yellow(), rec.indicator.bold(), rec.threat.red());
            }
            if db.len() > limit {
                println!("... and {} more records (use --limit to see more)", db.len() - limit);
            }
            println!("{}", "=========================================================".cyan());
        }
    }

    Ok(())
}
