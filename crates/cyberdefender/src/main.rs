//! S2O CyberDefender — hash scan + local rules + yara-lite + YARA-X + Defender probe.

mod yara_lite;
mod yara_x_engine;

use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use s2o_ioc::IocStore;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use yara_lite::{content_pattern_hit, load_patterns, match_buffer, Pattern};
use yara_x_engine::YaraEngine;

#[derive(Parser)]
#[command(name = "cyberdefender")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.5.0")]
#[command(about = "S2O CyberDefender: hash + yara-lite + YARA-X scan", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    /// Local signature / hash rules file
    #[arg(long, global = true, default_value = ".aegis/defender-rules.json")]
    rules: PathBuf,

    /// ThreatGrid IOC store (hash IOCs)
    #[arg(long, global = true, default_value = ".aegis/ioc-store.json")]
    ioc_store: PathBuf,

    /// YARA-lite patterns file
    #[arg(long, global = true, default_value = ".aegis/yara-lite.rules")]
    patterns: PathBuf,

    /// YARA-X rule directory (*.yar / *.yara)
    #[arg(long, global = true, default_value = ".aegis/yara")]
    yara_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// SHA-256 + yara-lite (+ optional YARA-X) scan a file or directory
    Scan {
        path: String,
        /// Move blocked files into quarantine dir
        #[arg(long)]
        quarantine: bool,
        #[arg(long, default_value = ".aegis/quarantine")]
        quarantine_dir: PathBuf,
        /// Walk subdirectories
        #[arg(long)]
        recursive: bool,
        #[arg(long, default_value_t = 256)]
        max_files: usize,
        /// Max bytes read per file for content scanners (default 2 MiB)
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_bytes: usize,
        /// Also scan with YARA-X rules from --yara-dir
        #[arg(long)]
        yara: bool,
        /// Only run YARA-X (skip name/hash/yara-lite)
        #[arg(long)]
        yara_only: bool,
    },
    /// Write / refresh local rules + yara-lite + YARA-X seed
    UpdateDefs,
    /// Manage / inspect yara-lite patterns
    Patterns {
        #[command(subcommand)]
        command: PatternsCmd,
    },
    /// Manage / scan with YARA-X (.yar) rules
    Yara {
        #[command(subcommand)]
        command: YaraCmd,
    },
    /// Poll a directory for new/changed files and scan them
    Watch {
        path: String,
        #[arg(long, default_value_t = 3000)]
        interval_ms: u64,
        #[arg(long)]
        recursive: bool,
        #[arg(long, default_value_t = 256)]
        max_files: usize,
        /// Exit after this many blocks (0 = forever)
        #[arg(long, default_value_t = 0)]
        max_blocks: u32,
        #[arg(long)]
        quarantine: bool,
        #[arg(long, default_value = ".aegis/quarantine")]
        quarantine_dir: PathBuf,
        /// Include YARA-X in watch scans
        #[arg(long)]
        yara: bool,
    },
    /// List / restore / purge quarantined files
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCmd,
    },
    Realtime {
        action: String,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantine directory entries
    List {
        #[arg(long, default_value = ".aegis/quarantine")]
        dir: PathBuf,
    },
    /// Restore a quarantined file by name or path (uses sidecar .meta.json)
    Restore {
        /// File name under quarantine dir, or full path
        target: String,
        #[arg(long, default_value = ".aegis/quarantine")]
        dir: PathBuf,
        /// Overwrite existing original path
        #[arg(long)]
        force: bool,
        /// Destination override (default: original path from meta)
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Delete quarantine files (and meta); older_days=0 deletes all
    Purge {
        #[arg(long, default_value = ".aegis/quarantine")]
        dir: PathBuf,
        /// Age in days; **0 = all entries**
        #[arg(long, default_value_t = 30)]
        older_days: u64,
        /// Actually delete (default dry-run)
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum PatternsCmd {
    /// List loaded rules
    List,
    /// Write default seed rules if missing (or --force)
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Test patterns against a file or --text string
    Test {
        /// File to test (optional if --text)
        path: Option<PathBuf>,
        #[arg(long)]
        text: Option<String>,
    },
}

#[derive(Subcommand)]
enum YaraCmd {
    /// Write seed .yar rules into --yara-dir
    Init {
        #[arg(long)]
        force: bool,
    },
    /// List rule files and compiled rule count
    List,
    /// Test YARA-X against a file or --text
    Test {
        path: Option<PathBuf>,
        #[arg(long)]
        text: Option<String>,
    },
    /// Scan path with YARA-X only
    Scan {
        path: String,
        #[arg(long)]
        recursive: bool,
        #[arg(long, default_value_t = 256)]
        max_files: usize,
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_bytes: usize,
        #[arg(long)]
        quarantine: bool,
        #[arg(long, default_value = ".aegis/quarantine")]
        quarantine_dir: PathBuf,
    },
    /// Download a remote .yar/.yara (or text) ruleset into --yara-dir (capped lab feed)
    Pull {
        /// HTTP(S) URL of a YARA rules file
        url: String,
        /// Output filename under --yara-dir
        #[arg(long, default_value = "pulled.yar")]
        name: String,
        /// Max download bytes (safety cap)
        #[arg(long, default_value_t = 512 * 1024)]
        max_bytes: usize,
        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LocalRules {
    version: String,
    #[serde(default)]
    blocked_hashes: Vec<String>,
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

fn quarantine_meta_path(qfile: &Path) -> PathBuf {
    // foo.bin → foo.meta.json ; preserve stem
    let stem = qfile
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    qfile
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.meta.json"))
}

fn quarantine_file(src: &Path, qdir: &Path) -> std::io::Result<PathBuf> {
    fs::create_dir_all(qdir)?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let name = src
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.bin");
    let dest = qdir.join(format!("{ts}_{name}"));
    if fs::rename(src, &dest).is_err() {
        fs::copy(src, &dest)?;
        let _ = fs::remove_file(src);
    }
    let meta = serde_json::json!({
        "original": src.display().to_string(),
        "quarantined": dest.display().to_string(),
        "at": chrono::Utc::now().to_rfc3339(),
    });
    fs::write(
        quarantine_meta_path(&dest),
        serde_json::to_string_pretty(&meta).unwrap_or_else(|_| "{}".into()),
    )?;
    Ok(dest)
}

#[derive(Debug, Deserialize)]
struct QuarantineMeta {
    original: String,
    #[allow(dead_code)]
    quarantined: String,
    #[serde(default)]
    at: String,
}

fn list_quarantine_entries(dir: &Path) -> Vec<(PathBuf, Option<QuarantineMeta>)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with(".meta.json") {
            continue;
        }
        let meta = fs::read_to_string(quarantine_meta_path(&p))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        out.push((p, meta));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn collect_targets(
    path: &Path,
    recursive: bool,
    max_files: usize,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err(format!("path not found: {}", path.display()).into());
    }
    let mut files = Vec::new();
    if recursive {
        fn walk(dir: &Path, files: &mut Vec<PathBuf>, max: usize) -> std::io::Result<()> {
            if files.len() >= max {
                return Ok(());
            }
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_file() {
                    files.push(p);
                    if files.len() >= max {
                        return Ok(());
                    }
                } else if p.is_dir() {
                    // skip obvious noise
                    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if name.eq_ignore_ascii_case("node_modules")
                        || name.eq_ignore_ascii_case(".git")
                        || name.eq_ignore_ascii_case("target")
                    {
                        continue;
                    }
                    walk(&p, files, max)?;
                }
            }
            Ok(())
        }
        walk(path, &mut files, max_files)?;
    } else {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                files.push(p);
            }
            if files.len() >= max_files {
                break;
            }
        }
    }
    Ok(files)
}

fn file_sig(path: &Path) -> Option<(u64, u64)> {
    let meta = fs::metadata(path).ok()?;
    let len = meta.len();
    #[cfg(windows)]
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    #[cfg(not(windows))]
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some((len, mtime))
}

struct ScanCtx<'a> {
    rules: &'a LocalRules,
    hash_set: &'a BTreeSet<String>,
    patterns: &'a [Pattern],
    yara: Option<&'a YaraEngine>,
    yara_only: bool,
    event_log: &'a Path,
    max_bytes: usize,
    quarantine: bool,
    quarantine_dir: &'a Path,
}

struct ScanStats {
    hashed: u32,
    blocked: u32,
    quarantined: u32,
}

fn scan_one(t: &Path, ctx: &ScanCtx, quiet_clean: bool) -> ScanStats {
    let mut st = ScanStats {
        hashed: 0,
        blocked: 0,
        quarantined: 0,
    };
    let maybe_q = |t: &Path| -> Option<PathBuf> {
        if !ctx.quarantine {
            return None;
        }
        match quarantine_file(t, ctx.quarantine_dir) {
            Ok(dest) => {
                println!(
                    " Quarantine   : {}",
                    dest.display().to_string().yellow().bold()
                );
                Some(dest)
            }
            Err(e) => {
                eprintln!("{}", format!(" quarantine failed: {e}").red());
                None
            }
        }
    };

    if !ctx.yara_only {
        if let Some(sub) = ctx.rules.name_hit(t) {
            st.blocked += 1;
            println!(
                "{}",
                "---------------------------------------------------------".cyan()
            );
            println!(" Target File  : {}", t.display().to_string().bold());
            println!(
                " Verdict      : {}",
                format!("BLOCKED (name rule: {sub})").red().bold()
            );
            let qpath = maybe_q(t);
            if qpath.is_some() {
                st.quarantined += 1;
            }
            emit(
                ctx.event_log,
                EventAction::Quarantined,
                Severity::High,
                format!("name rule hit: {}", t.display()),
                &[
                    ("path", serde_json::json!(t.display().to_string())),
                    ("rule", serde_json::json!(sub)),
                    ("verdict", serde_json::json!("blocked_name")),
                    (
                        "quarantined",
                        serde_json::json!(qpath.map(|p| p.display().to_string())),
                    ),
                ],
                None,
            );
            return st;
        }

        if let Some((rule, sev)) = content_pattern_hit(t, ctx.patterns, ctx.max_bytes) {
            st.blocked += 1;
            println!(
                "{}",
                "---------------------------------------------------------".cyan()
            );
            println!(" Target File  : {}", t.display().to_string().bold());
            println!(
                " Verdict      : {}",
                format!("BLOCKED (yara-lite: {rule})").red().bold()
            );
            let qpath = maybe_q(t);
            if qpath.is_some() {
                st.quarantined += 1;
            }
            emit(
                ctx.event_log,
                EventAction::Quarantined,
                sev,
                format!("yara-lite hit: {}", t.display()),
                &[
                    ("path", serde_json::json!(t.display().to_string())),
                    ("rule", serde_json::json!(rule)),
                    ("verdict", serde_json::json!("blocked_pattern")),
                    (
                        "quarantined",
                        serde_json::json!(qpath.map(|p| p.display().to_string())),
                    ),
                ],
                None,
            );
            return st;
        }
    }

    if let Some(eng) = ctx.yara {
        match eng.scan_file(t, ctx.max_bytes) {
            Ok(hits) if !hits.is_empty() => {
                st.blocked += 1;
                let rule = hits.join(",");
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(" Target File  : {}", t.display().to_string().bold());
                println!(
                    " Verdict      : {}",
                    format!("BLOCKED (yara-x: {rule})").red().bold()
                );
                let qpath = maybe_q(t);
                if qpath.is_some() {
                    st.quarantined += 1;
                }
                emit(
                    ctx.event_log,
                    EventAction::Quarantined,
                    Severity::High,
                    format!("yara-x hit: {}", t.display()),
                    &[
                        ("path", serde_json::json!(t.display().to_string())),
                        ("rule", serde_json::json!(rule)),
                        ("rules", serde_json::json!(hits)),
                        ("verdict", serde_json::json!("blocked_yara_x")),
                        (
                            "quarantined",
                            serde_json::json!(qpath.map(|p| p.display().to_string())),
                        ),
                    ],
                    None,
                );
                return st;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}", format!("  yara-x skip {}: {e}", t.display()).yellow());
            }
        }
        if ctx.yara_only {
            if !quiet_clean {
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(" Target File  : {}", t.display().to_string().bold());
                println!(" Verdict      : {}", "clean (yara-x)".green());
            }
            return st;
        }
    } else if ctx.yara_only {
        eprintln!("[cyberdefender] --yara-only requires compiled YARA-X rules");
        return st;
    }

    match calculate_file_hash(t) {
        Ok(hash) => {
            st.hashed += 1;
            let hit = ctx.hash_set.contains(&hash);
            if hit {
                st.blocked += 1;
            }
            if hit || !quiet_clean {
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(" Target File  : {}", t.display().to_string().bold());
                println!(" SHA-256 Hash : {}", hash.yellow());
            }
            if hit {
                println!(
                    " Verdict      : {}",
                    "BLOCKED (hash rule / ThreatGrid)".red().bold()
                );
                let qpath = maybe_q(t);
                if qpath.is_some() {
                    st.quarantined += 1;
                }
                emit(
                    ctx.event_log,
                    EventAction::Quarantined,
                    Severity::High,
                    format!("hash rule hit: {}", t.display()),
                    &[
                        ("path", serde_json::json!(t.display().to_string())),
                        ("sha256", serde_json::json!(hash)),
                        ("verdict", serde_json::json!("blocked_hash")),
                        (
                            "quarantined",
                            serde_json::json!(qpath.map(|p| p.display().to_string())),
                        ),
                    ],
                    Some(Ioc::Hash(hash)),
                );
            } else if !quiet_clean {
                println!(
                    " Verdict      : {}",
                    "clean (no local rule match)".green()
                );
                emit(
                    ctx.event_log,
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
    st
}

fn try_load_yara(dir: &Path, require: bool) -> Option<YaraEngine> {
    match YaraEngine::compile_dir(dir) {
        Ok(eng) => Some(eng),
        Err(e) => {
            if require {
                eprintln!("{}", format!("[cyberdefender] yara-x: {e}").red());
            }
            None
        }
    }
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
            let (patterns, perrs) = load_patterns(&cli.patterns);
            let yara_files = yara_x_engine::collect_rule_files(&cli.yara_dir);
            let yara_eng = try_load_yara(&cli.yara_dir, false);

            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "      S2O CyberDefender (Phase 2/3 shell)                "
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
            println!(" IOC hash rules    : {ioc_hashes}");
            println!(
                " yara-lite patterns: {} ({})",
                patterns.len(),
                cli.patterns.display()
            );
            if !perrs.is_empty() {
                println!(" pattern errors    : {}", perrs.len().to_string().red());
            }
            println!(
                " YARA-X engine     : {} (yara-x {})",
                "enabled".green(),
                yara_x_engine::engine_version()
            );
            println!(" YARA-X rules dir  : {}", cli.yara_dir.display());
            println!(
                " YARA-X rule files : {}",
                yara_files.len().to_string().yellow()
            );
            if let Some(ref eng) = yara_eng {
                println!(
                    " YARA-X rules      : {}",
                    eng.rule_count.to_string().yellow()
                );
            } else if yara_files.is_empty() {
                println!(
                    " YARA-X rules      : {}",
                    "none (run: cyberdefender yara init)".yellow()
                );
            } else {
                println!(
                    " YARA-X rules      : {}",
                    "compile failed".red()
                );
            }
            println!(
                " Implemented       : {}",
                "SHA-256 + name + yara-lite + YARA-X + IOC + quarantine list/restore + Defender"
                    .green()
            );
            println!(
                " Not implemented   : {}",
                "realtime FS minifilter, cloud signature feed".red()
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
                    ("patterns", serde_json::json!(patterns.len())),
                    ("yara_files", serde_json::json!(yara_files.len())),
                    (
                        "yara_rules",
                        serde_json::json!(yara_eng.as_ref().map(|e| e.rule_count).unwrap_or(0)),
                    ),
                ],
                None,
            );
        }
        Commands::UpdateDefs => {
            let mut rules = load_rules(&cli.rules);
            if rules.version.is_empty() {
                rules = LocalRules::seed();
            }
            if rules.blocked_name_substrings.is_empty() {
                rules.blocked_name_substrings.push("eicar".into());
            }
            if rules.version.is_empty() {
                rules.version = "0.1.0".into();
            }
            save_rules(&cli.rules, &rules)?;
            if !cli.patterns.exists() {
                if let Some(p) = cli.patterns.parent() {
                    let _ = fs::create_dir_all(p);
                }
                let _ = fs::write(&cli.patterns, yara_lite::default_seed());
            }
            let yara_seed = yara_x_engine::write_seed_rules(&cli.yara_dir, false)?;
            println!(
                "{}",
                format!(
                    "[cyberdefender] wrote local rules {} (hashes={}, names={}); patterns {}; yara {}",
                    cli.rules.display(),
                    rules.blocked_hashes.len(),
                    rules.blocked_name_substrings.len(),
                    cli.patterns.display(),
                    yara_seed.display()
                )
                .green()
                .bold()
            );
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                "local defender rules updated",
                &[
                    (
                        "rules_path",
                        serde_json::json!(cli.rules.display().to_string()),
                    ),
                    (
                        "yara_dir",
                        serde_json::json!(cli.yara_dir.display().to_string()),
                    ),
                ],
                None,
            );
        }
        Commands::Patterns { command } => match command {
            PatternsCmd::List => {
                let (patterns, errs) = load_patterns(&cli.patterns);
                println!(
                    "[cyberdefender] {} rules from {}",
                    patterns.len(),
                    cli.patterns.display()
                );
                for p in &patterns {
                    println!(
                        "  [{:?}] {:<8} {:<24} {}",
                        p.severity,
                        p.kind_label(),
                        p.name,
                        p.display_body()
                    );
                }
                for e in errs {
                    eprintln!("  ! {e}");
                }
            }
            PatternsCmd::Init { force } => {
                if cli.patterns.exists() && !force {
                    println!(
                        "[cyberdefender] {} exists (use --force to overwrite)",
                        cli.patterns.display()
                    );
                } else {
                    if let Some(p) = cli.patterns.parent() {
                        fs::create_dir_all(p)?;
                    }
                    fs::write(&cli.patterns, yara_lite::default_seed())?;
                    println!(
                        "{}",
                        format!("[cyberdefender] wrote {}", cli.patterns.display())
                            .green()
                            .bold()
                    );
                }
            }
            PatternsCmd::Test { path, text } => {
                let (patterns, errs) = load_patterns(&cli.patterns);
                for e in &errs {
                    eprintln!("! {e}");
                }
                if patterns.is_empty() {
                    eprintln!("[cyberdefender] no patterns loaded");
                    std::process::exit(2);
                }
                let buf = if let Some(t) = text {
                    t.into_bytes()
                } else if let Some(p) = path {
                    fs::read(&p)?
                } else {
                    eprintln!("[cyberdefender] pass a path or --text");
                    std::process::exit(2);
                };
                let hits = match_buffer(&patterns, &buf);
                if hits.is_empty() {
                    println!("{}", "no matches".green());
                    std::process::exit(0);
                }
                for h in &hits {
                    println!(
                        "{} {} ({})",
                        "HIT".red().bold(),
                        h.name,
                        h.kind_label()
                    );
                }
                std::process::exit(3);
            }
        },
        Commands::Yara { command } => match command {
            YaraCmd::Init { force } => {
                let path = yara_x_engine::write_seed_rules(&cli.yara_dir, force)?;
                if path.exists() && !force {
                    // write_seed_rules returns existing path without overwrite
                    let already = yara_x_engine::collect_rule_files(&cli.yara_dir);
                    if !already.is_empty() && !force {
                        println!(
                            "[cyberdefender] {} exists ({} rule file(s); use --force to overwrite seed)",
                            cli.yara_dir.display(),
                            already.len()
                        );
                    }
                }
                println!(
                    "{}",
                    format!(
                        "[cyberdefender] yara-x seed ready: {} (engine {})",
                        path.display(),
                        yara_x_engine::engine_version()
                    )
                    .green()
                    .bold()
                );
            }
            YaraCmd::List => {
                let files = yara_x_engine::collect_rule_files(&cli.yara_dir);
                println!(
                    "[cyberdefender] YARA-X {} — dir {}",
                    yara_x_engine::engine_version(),
                    cli.yara_dir.display()
                );
                if files.is_empty() {
                    println!("  (no .yar/.yara files — run: cyberdefender yara init)");
                }
                for f in &files {
                    println!("  file  {}", f.display());
                }
                match YaraEngine::compile_dir(&cli.yara_dir) {
                    Ok(eng) => {
                        println!("  compiled rules: {}", eng.rule_count);
                        for s in &eng.sources {
                            println!("  source  {}", s.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("  compile WARN: {e}");
                        eprintln!("  (files listed; fix duplicates before scan --yara)");
                    }
                }
            }
            YaraCmd::Test { path, text } => {
                let eng = match YaraEngine::compile_dir(&cli.yara_dir) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[cyberdefender] {e}");
                        std::process::exit(2);
                    }
                };
                let hits = if let Some(t) = text {
                    eng.scan_bytes(t.as_bytes())?
                } else if let Some(p) = path {
                    eng.scan_file(&p, 2 * 1024 * 1024)?
                } else {
                    eprintln!("[cyberdefender] pass a path or --text");
                    std::process::exit(2);
                };
                if hits.is_empty() {
                    println!("{}", "no matches".green());
                    std::process::exit(0);
                }
                for h in &hits {
                    println!("{} {}", "HIT".red().bold(), h);
                }
                std::process::exit(3);
            }
            YaraCmd::Pull {
                url,
                name,
                max_bytes,
                force,
            } => {
                let fname = name
                    .trim()
                    .trim_start_matches(['/', '\\'])
                    .to_string();
                if fname.is_empty() || fname.contains("..") {
                    eprintln!("[cyberdefender] invalid --name");
                    std::process::exit(2);
                }
                fs::create_dir_all(&cli.yara_dir)?;
                let dest = cli.yara_dir.join(&fname);
                if dest.exists() && !force {
                    eprintln!(
                        "[cyberdefender] {} exists (use --force)",
                        dest.display()
                    );
                    std::process::exit(3);
                }
                println!("[cyberdefender] pulling {url} (max_bytes={max_bytes})...");
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(60))
                    .user_agent("S2O-CyberDefender/0.5 (+yara pull)")
                    .build()?;
                let res = client.get(&url).send().await?;
                if !res.status().is_success() {
                    eprintln!("[cyberdefender] HTTP {}", res.status());
                    std::process::exit(1);
                }
                let bytes = res.bytes().await?;
                if bytes.len() > max_bytes {
                    eprintln!(
                        "[cyberdefender] download {} bytes exceeds max_bytes={max_bytes}",
                        bytes.len()
                    );
                    std::process::exit(1);
                }
                // basic sanity: look like YARA text
                let text = String::from_utf8_lossy(&bytes);
                if !text.contains("rule ") && !text.contains("rule\t") {
                    eprintln!("[cyberdefender] WARN: body may not be YARA (no 'rule ' token)");
                }
                // validate this source alone (dir may already have same rule names)
                match YaraEngine::compile_source(&text, &fname) {
                    Ok(eng) => {
                        fs::write(&dest, &bytes)?;
                        println!(
                            "{}",
                            format!(
                                "[cyberdefender] wrote {} ({} bytes); file rules={}",
                                dest.display(),
                                bytes.len(),
                                eng.rule_count
                            )
                            .green()
                            .bold()
                        );
                        if let Err(e) = YaraEngine::compile_dir(&cli.yara_dir) {
                            eprintln!(
                                "[cyberdefender] WARN: full yara-dir compile: {e} (resolve duplicate rule names)"
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("[cyberdefender] download rejected (compile): {e}");
                        std::process::exit(2);
                    }
                }
            }
            YaraCmd::Scan {
                path,
                recursive,
                max_files,
                max_bytes,
                quarantine,
                quarantine_dir,
            } => {
                let eng = match YaraEngine::compile_dir(&cli.yara_dir) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[cyberdefender] {e}");
                        std::process::exit(2);
                    }
                };
                let root = PathBuf::from(&path);
                let rules = load_rules(&cli.rules);
                let hash_set = BTreeSet::new();
                let patterns: Vec<Pattern> = vec![];
                println!(
                    "{}",
                    format!(
                        "[cyberdefender] yara-x scan '{}' rules={} files_dir={}",
                        root.display(),
                        eng.rule_count,
                        cli.yara_dir.display()
                    )
                    .cyan()
                );
                let targets = match collect_targets(&root, recursive, max_files) {
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
                let ctx = ScanCtx {
                    rules: &rules,
                    hash_set: &hash_set,
                    patterns: &patterns,
                    yara: Some(&eng),
                    yara_only: true,
                    event_log: &cli.event_log,
                    max_bytes,
                    quarantine,
                    quarantine_dir: &quarantine_dir,
                };
                let mut blocked = 0u32;
                let mut quarantined = 0u32;
                for t in &targets {
                    let st = scan_one(t, &ctx, false);
                    blocked += st.blocked;
                    quarantined += st.quarantined;
                }
                println!(
                    " Files: {}  blocked: {blocked}  quarantined: {quarantined}",
                    targets.len()
                );
                if blocked > 0 {
                    std::process::exit(3);
                }
            }
        },
        Commands::Scan {
            path,
            quarantine,
            quarantine_dir,
            recursive,
            max_files,
            max_bytes,
            yara,
            yara_only,
        } => {
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
            let (patterns, perrs) = load_patterns(&cli.patterns);
            for e in &perrs {
                eprintln!("[cyberdefender] pattern: {e}");
            }
            let want_yara = yara || yara_only;
            let yara_eng = if want_yara {
                try_load_yara(&cli.yara_dir, true)
            } else {
                None
            };
            if want_yara && yara_eng.is_none() {
                std::process::exit(2);
            }
            println!(
                "{}",
                format!(
                    "[cyberdefender] scanning '{}' recursive={} max_files={} ({} hashes, {} patterns, yara-x={})...",
                    root.display(),
                    recursive,
                    max_files,
                    hash_set.len(),
                    patterns.len(),
                    yara_eng
                        .as_ref()
                        .map(|e| e.rule_count.to_string())
                        .unwrap_or_else(|| "off".into())
                )
                .cyan()
            );

            let targets = match collect_targets(&root, recursive, max_files) {
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

            let ctx = ScanCtx {
                rules: &rules,
                hash_set: &hash_set,
                patterns: &patterns,
                yara: yara_eng.as_ref(),
                yara_only,
                event_log: &cli.event_log,
                max_bytes,
                quarantine,
                quarantine_dir: &quarantine_dir,
            };
            let mut hashed = 0u32;
            let mut blocked = 0u32;
            let mut quarantined = 0u32;
            for t in &targets {
                let st = scan_one(t, &ctx, false);
                hashed += st.hashed;
                blocked += st.blocked;
                quarantined += st.quarantined;
            }
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Files: {}  hashed: {hashed}  blocked: {blocked}  quarantined: {quarantined}",
                targets.len()
            );
            if blocked > 0 {
                std::process::exit(3);
            }
        }
        Commands::Watch {
            path,
            interval_ms,
            recursive,
            max_files,
            max_blocks,
            quarantine,
            quarantine_dir,
            yara,
        } => {
            let root = PathBuf::from(&path);
            if !root.exists() {
                eprintln!("[cyberdefender] path not found: {}", root.display());
                std::process::exit(2);
            }
            let rules = load_rules(&cli.rules);
            let mut hash_set = rules.hash_set();
            if let Ok(ioc) = IocStore::load(&cli.ioc_store) {
                for e in ioc.entries {
                    if e.kind == s2o_ioc::IocKind::Hash {
                        hash_set.insert(e.value.to_ascii_lowercase());
                    }
                }
            }
            let (patterns, _) = load_patterns(&cli.patterns);
            let yara_eng = if yara {
                try_load_yara(&cli.yara_dir, true)
            } else {
                None
            };
            if yara && yara_eng.is_none() {
                std::process::exit(2);
            }
            println!(
                "[cyberdefender] watch {} interval={}ms recursive={} yara-x={} (Ctrl+C to stop)",
                root.display(),
                interval_ms,
                recursive,
                yara_eng
                    .as_ref()
                    .map(|e| e.rule_count.to_string())
                    .unwrap_or_else(|| "off".into())
            );
            let mut seen: BTreeMap<PathBuf, (u64, u64)> = BTreeMap::new();
            // seed without scanning
            if let Ok(targets) = collect_targets(&root, recursive, max_files) {
                for t in targets {
                    if let Some(sig) = file_sig(&t) {
                        seen.insert(t, sig);
                    }
                }
            }
            println!("[cyberdefender] seed {} files", seen.len());
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("defender watch start seed={}", seen.len()),
                &[
                    ("path", serde_json::json!(root.display().to_string())),
                    ("seed", serde_json::json!(seen.len())),
                    ("yara", serde_json::json!(yara)),
                ],
                None,
            );
            let mut blocks = 0u32;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms.max(500))).await;
                let Ok(targets) = collect_targets(&root, recursive, max_files) else {
                    continue;
                };
                let ctx = ScanCtx {
                    rules: &rules,
                    hash_set: &hash_set,
                    patterns: &patterns,
                    yara: yara_eng.as_ref(),
                    yara_only: false,
                    event_log: &cli.event_log,
                    max_bytes: 2 * 1024 * 1024,
                    quarantine,
                    quarantine_dir: &quarantine_dir,
                };
                let mut live = BTreeMap::new();
                for t in targets {
                    let Some(sig) = file_sig(&t) else {
                        continue;
                    };
                    let changed = match seen.get(&t) {
                        None => true,
                        Some(old) => *old != sig,
                    };
                    if changed {
                        println!(
                            "{} {}",
                            " SCAN ".cyan().bold(),
                            t.display()
                        );
                        let st = scan_one(&t, &ctx, true);
                        if st.blocked > 0 {
                            blocks += st.blocked;
                            if max_blocks > 0 && blocks >= max_blocks {
                                println!("[cyberdefender] watch max_blocks={max_blocks} reached");
                                return Ok(());
                            }
                        }
                    }
                    live.insert(t, sig);
                }
                seen = live;
            }
        }
        Commands::Quarantine { command } => match command {
            QuarantineCmd::List { dir } => {
                if !dir.is_dir() {
                    println!("[cyberdefender] quarantine empty/missing: {}", dir.display());
                    return Ok(());
                }
                let entries = list_quarantine_entries(&dir);
                println!(
                    "[cyberdefender] quarantine {} ({} file(s))",
                    dir.display(),
                    entries.len()
                );
                for (p, meta) in entries {
                    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("?");
                    match meta {
                        Some(m) => println!(
                            "  {}  ← {}  ({})",
                            name.bold(),
                            m.original,
                            if m.at.is_empty() { "-" } else { &m.at }
                        ),
                        None => println!("  {}  (no meta)", name.yellow()),
                    }
                }
            }
            QuarantineCmd::Restore { target, dir, force, to } => {
                let qpath = {
                    let t = PathBuf::from(&target);
                    if t.is_file() {
                        t
                    } else {
                        dir.join(&target)
                    }
                };
                if !qpath.is_file() {
                    eprintln!("[cyberdefender] not found: {}", qpath.display());
                    std::process::exit(2);
                }
                let meta_path = quarantine_meta_path(&qpath);
                let meta: QuarantineMeta = if meta_path.exists() {
                    serde_json::from_str(&fs::read_to_string(&meta_path)?)?
                } else {
                    eprintln!(
                        "[cyberdefender] missing meta {}; cannot restore to original",
                        meta_path.display()
                    );
                    std::process::exit(2);
                };
                let dest = to.unwrap_or_else(|| PathBuf::from(&meta.original));
                if dest.exists() && !force {
                    eprintln!(
                        "[cyberdefender] destination exists (use --force): {}",
                        dest.display()
                    );
                    std::process::exit(3);
                }
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                if fs::rename(&qpath, &dest).is_err() {
                    fs::copy(&qpath, &dest)?;
                    let _ = fs::remove_file(&qpath);
                }
                let _ = fs::remove_file(&meta_path);
                println!(
                    "{}",
                    format!(
                        "[cyberdefender] restored {} → {}",
                        qpath.display(),
                        dest.display()
                    )
                    .green()
                    .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("quarantine restore: {}", dest.display()),
                    &[
                        ("path", serde_json::json!(dest.display().to_string())),
                        ("from", serde_json::json!(qpath.display().to_string())),
                    ],
                    None,
                );
            }
            QuarantineCmd::Purge {
                dir,
                older_days,
                apply,
            } => {
                if !dir.is_dir() {
                    println!("[cyberdefender] nothing to purge");
                    return Ok(());
                }
                let cutoff = if older_days == 0 {
                    None
                } else {
                    Some(
                        chrono::Utc::now() - chrono::Duration::days(older_days as i64),
                    )
                };
                let mut n = 0u32;
                for (p, meta) in list_quarantine_entries(&dir) {
                    let old = if cutoff.is_none() {
                        true
                    } else {
                        let cut = cutoff.unwrap();
                        let at = meta
                            .as_ref()
                            .and_then(|m| chrono::DateTime::parse_from_rfc3339(&m.at).ok())
                            .map(|t| t.with_timezone(&chrono::Utc));
                        match at {
                            Some(t) => t < cut,
                            None => fs::metadata(&p)
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| {
                                    let secs = d.as_secs() as i64;
                                    chrono::DateTime::from_timestamp(secs, 0)
                                        .map(|dt| dt < cut)
                                        .unwrap_or(false)
                                })
                                .unwrap_or(false),
                        }
                    };
                    if !old {
                        continue;
                    }
                    n += 1;
                    if apply {
                        let _ = fs::remove_file(&p);
                        let _ = fs::remove_file(quarantine_meta_path(&p));
                        println!("  deleted {}", p.display());
                    } else {
                        println!("  would delete {}", p.display());
                    }
                }
                if apply {
                    println!(
                        "{}",
                        format!("[cyberdefender] purge deleted {n} file(s) older than {older_days}d")
                            .green()
                            .bold()
                    );
                } else {
                    println!(
                        "[cyberdefender] purge dry-run: {n} file(s) older than {older_days}d (use --apply)"
                    );
                }
            }
        },
        Commands::Realtime { action } => {
            eprintln!(
                "[cyberdefender] kernel realtime shield not implemented (action={action})."
            );
            eprintln!("Use: cyberdefender watch <dir>  for userspace poll scan");
            std::process::exit(2);
        }
    }

    Ok(())
}
