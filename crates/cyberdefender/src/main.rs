//! S2O CyberDefender — hash scan + local hash rules + Defender probe (Phase 2 shell).

use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use s2o_ioc::IocStore;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberdefender")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.3.0")]
#[command(about = "S2O CyberDefender: hash scan + local rules (Phase 2 shell)", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    /// Local signature / hash rules file
    #[arg(long, global = true, default_value = ".aegis/defender-rules.json")]
    rules: PathBuf,

    /// ThreatGrid IOC store (hash IOCs)
    #[arg(long, global = true, default_value = ".aegis/ioc-store.json")]
    ioc_store: PathBuf,

    /// Optional yara-lite patterns file (one `name: needle` per line)
    #[arg(long, global = true, default_value = ".aegis/yara-lite.rules")]
    patterns: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// SHA-256 scan a file or directory (first-level files, max 64)
    Scan {
        path: String,
    },
    /// Write / refresh local rules seed file
    UpdateDefs,
    Realtime {
        action: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LocalRules {
    version: String,
    /// SHA-256 hex (lowercase) treated as malicious
    #[serde(default)]
    blocked_hashes: Vec<String>,
    /// Path substring matches (case-insensitive)
    #[serde(default)]
    blocked_name_substrings: Vec<String>,
}

impl LocalRules {
    fn seed() -> Self {
        Self {
            version: "0.1.0".into(),
            blocked_hashes: vec![],
            blocked_name_substrings: vec!["eicar".into()],
        }
    }

    fn hash_set(&self) -> BTreeSet<String> {
        self.blocked_hashes
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    }

    fn name_hit(&self, path: &Path) -> Option<String> {
        let s = path.to_string_lossy().to_ascii_lowercase();
        for sub in &self.blocked_name_substrings {
            let sub = sub.to_ascii_lowercase();
            if !sub.is_empty() && s.contains(&sub) {
                return Some(sub);
            }
        }
        None
    }
}

fn load_rules(path: &Path) -> LocalRules {
    if !path.exists() {
        return LocalRules::seed();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(LocalRules::seed)
}

fn save_rules(path: &Path, rules: &LocalRules) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let text = serde_json::to_string_pretty(rules).unwrap_or_else(|_| "{}".into());
    fs::write(path, text)
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit(
    event_log: &Path,
    action: EventAction,
    severity: Severity,
    message: impl Into<String>,
    attrs: &[(&str, serde_json::Value)],
    ioc: Option<Ioc>,
) {
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

/// yara-lite: lines like `eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE`
fn load_patterns(path: &Path) -> Vec<(String, String)> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, needle)) = line.split_once(':') {
            let name = name.trim().to_string();
            let needle = needle.trim().to_string();
            if !name.is_empty() && !needle.is_empty() {
                out.push((name, needle));
            }
        }
    }
    out
}

fn content_pattern_hit(path: &Path, patterns: &[(String, String)]) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }
    let Ok(mut f) = File::open(path) else {
        return None;
    };
    // Cap read at 2 MiB for T0 scan
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut total = 0usize;
    loop {
        let Ok(n) = f.read(&mut tmp) else {
            return None;
        };
        if n == 0 {
            break;
        }
        total += n;
        buf.extend_from_slice(&tmp[..n]);
        if total >= 2 * 1024 * 1024 {
            break;
        }
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        // binary: search as bytes for needle utf8
        for (name, needle) in patterns {
            if !needle.is_empty() && buf.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                return Some(name.clone());
            }
        }
        return None;
    };
    for (name, needle) in patterns {
        if text.contains(needle) {
            return Some(name.clone());
        }
    }
    None
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
            if files.len() >= 64 {
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
            let rules = load_rules(&cli.rules);

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
            println!(" Rules file        : {}", cli.rules.display());
            println!(
                " Local hash rules  : {}",
                rules.blocked_hashes.len().to_string().yellow()
            );
            println!(
                " Name substr rules : {}",
                rules.blocked_name_substrings.len().to_string().yellow()
            );
            let ioc_hashes = IocStore::load(&cli.ioc_store)
                .map(|s| s.count_by_kind(s2o_ioc::IocKind::Hash))
                .unwrap_or(0);
            let patterns = load_patterns(&cli.patterns).len();
            println!(" IOC hash rules    : {ioc_hashes}");
            println!(" yara-lite patterns: {patterns} ({})", cli.patterns.display());
            println!(
                " Implemented       : {}",
                "SHA-256 + local rules + ThreatGrid hashes + yara-lite content + Defender".green()
            );
            println!(
                " Not implemented   : {}",
                "full YARA-X engine, realtime FS shield, cloud defs".red()
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
                &[
                    ("defender_active", serde_json::json!(is_active)),
                    ("hash_rules", serde_json::json!(rules.blocked_hashes.len())),
                ],
                None,
            );
        }
        Commands::UpdateDefs => {
            let mut rules = load_rules(&cli.rules);
            if rules.version.is_empty() {
                rules = LocalRules::seed();
            }
            // Ensure seed name rule exists
            if rules.blocked_name_substrings.is_empty() {
                rules.blocked_name_substrings.push("eicar".into());
            }
            if rules.version.is_empty() {
                rules.version = "0.1.0".into();
            }
            save_rules(&cli.rules, &rules)?;
            if !cli.patterns.exists() {
                let seed = "# S2O yara-lite patterns (name: needle)\n# eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE\n";
                if let Some(p) = cli.patterns.parent() {
                    let _ = fs::create_dir_all(p);
                }
                let _ = fs::write(&cli.patterns, seed);
            }
            println!(
                "{}",
                format!(
                    "[cyberdefender] wrote local rules {} (hashes={}, names={}); patterns {}",
                    cli.rules.display(),
                    rules.blocked_hashes.len(),
                    rules.blocked_name_substrings.len(),
                    cli.patterns.display()
                )
                .green()
                .bold()
            );
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                "local defender rules updated",
                &[("rules_path", serde_json::json!(cli.rules.display().to_string()))],
                None,
            );
        }
        Commands::Scan { path } => {
            let root = PathBuf::from(&path);
            let rules = load_rules(&cli.rules);
            let mut hash_set = rules.hash_set();
            if let Ok(ioc) = IocStore::load(&cli.ioc_store) {
                for e in ioc.entries {
                    if e.kind == s2o_ioc::IocKind::Hash {
                        hash_set.insert(e.value.to_ascii_lowercase());
                    }
                }
            }
            let patterns = load_patterns(&cli.patterns);
            println!(
                "{}",
                format!(
                    "[cyberdefender] scanning '{}' ({} hash rules, {} patterns)...",
                    root.display(),
                    hash_set.len(),
                    patterns.len()
                )
                .cyan()
            );

            let targets = match collect_targets(&root) {
                Ok(t) if !t.is_empty() => t,
                Ok(_) => {
                    eprintln!("{}", "[cyberdefender] no files to scan".yellow());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("{}", format!("Scan Error: {e}").red());
                    std::process::exit(1);
                }
            };

            let mut hashed = 0u32;
            let mut blocked = 0u32;
            for t in &targets {
                if let Some(sub) = rules.name_hit(t) {
                    blocked += 1;
                    println!(
                        "{}",
                        "---------------------------------------------------------".cyan()
                    );
                    println!(" Target File  : {}", t.display().to_string().bold());
                    println!(
                        " Verdict      : {}",
                        format!("BLOCKED (name rule: {sub})").red().bold()
                    );
                    emit(
                        &cli.event_log,
                        EventAction::Blocked,
                        Severity::High,
                        format!("name rule hit: {}", t.display()),
                        &[
                            ("path", serde_json::json!(t.display().to_string())),
                            ("rule", serde_json::json!(sub)),
                            ("verdict", serde_json::json!("blocked_name")),
                        ],
                        None,
                    );
                    continue;
                }

                if let Some(rule) = content_pattern_hit(t, &patterns) {
                    blocked += 1;
                    println!(
                        "{}",
                        "---------------------------------------------------------".cyan()
                    );
                    println!(" Target File  : {}", t.display().to_string().bold());
                    println!(
                        " Verdict      : {}",
                        format!("BLOCKED (yara-lite: {rule})").red().bold()
                    );
                    emit(
                        &cli.event_log,
                        EventAction::Blocked,
                        Severity::High,
                        format!("yara-lite hit: {}", t.display()),
                        &[
                            ("path", serde_json::json!(t.display().to_string())),
                            ("rule", serde_json::json!(rule)),
                            ("verdict", serde_json::json!("blocked_pattern")),
                        ],
                        None,
                    );
                    continue;
                }

                match calculate_file_hash(t) {
                    Ok(hash) => {
                        hashed += 1;
                        let hit = hash_set.contains(&hash);
                        if hit {
                            blocked += 1;
                        }
                        println!(
                            "{}",
                            "---------------------------------------------------------".cyan()
                        );
                        println!(" Target File  : {}", t.display().to_string().bold());
                        println!(" SHA-256 Hash : {}", hash.yellow());
                        if hit {
                            println!(
                                " Verdict      : {}",
                                "BLOCKED (hash rule / ThreatGrid)".red().bold()
                            );
                            emit(
                                &cli.event_log,
                                EventAction::Blocked,
                                Severity::High,
                                format!("hash rule hit: {}", t.display()),
                                &[
                                    ("path", serde_json::json!(t.display().to_string())),
                                    ("sha256", serde_json::json!(hash)),
                                    ("verdict", serde_json::json!("blocked_hash")),
                                ],
                                Some(Ioc::Hash(hash)),
                            );
                        } else {
                            println!(
                                " Verdict      : {}",
                                "clean (no local rule match)".green()
                            );
                            emit(
                                &cli.event_log,
                                EventAction::Allowed,
                                Severity::Info,
                                format!("file clean: {}", t.display()),
                                &[
                                    ("path", serde_json::json!(t.display().to_string())),
                                    ("sha256", serde_json::json!(hash)),
                                    ("verdict", serde_json::json!("clean")),
                                ],
                                Some(Ioc::Hash(hash)),
                            );
                        }
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
            println!(" Files hashed: {hashed}/{}  blocked: {blocked}", targets.len());
            if blocked > 0 {
                std::process::exit(3);
            }
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
