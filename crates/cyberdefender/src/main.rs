//! S2O CyberDefender — hash scan + local rules + yara-lite + Defender probe.

mod yara_lite;

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

#[derive(Parser)]
#[command(name = "cyberdefender")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.4.0")]
#[command(about = "S2O CyberDefender: hash + yara-lite (substr/re/hex) scan", long_about = None)]
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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// SHA-256 + yara-lite scan a file or directory
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
        /// Max bytes read per file for yara-lite (default 2 MiB)
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_bytes: usize,
    },
    /// Write / refresh local rules + yara-lite seed
    UpdateDefs,
    /// Manage / inspect yara-lite patterns
    Patterns {
        #[command(subcommand)]
        command: PatternsCmd,
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
    },
    Realtime {
        action: String,
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
        dest.with_extension("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap_or_else(|_| "{}".into()),
    )?;
    Ok(dest)
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
                " Implemented       : {}",
                "SHA-256 + name + yara-lite (substr/re/hex) + IOC + Defender".green()
            );
            println!(
                " Not implemented   : {}",
                "full YARA-X engine, realtime FS minifilter, cloud defs".red()
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
                &[(
                    "rules_path",
                    serde_json::json!(cli.rules.display().to_string()),
                )],
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
        Commands::Scan {
            path,
            quarantine,
            quarantine_dir,
            recursive,
            max_files,
            max_bytes,
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
            println!(
                "{}",
                format!(
                    "[cyberdefender] scanning '{}' recursive={} max_files={} ({} hashes, {} patterns)...",
                    root.display(),
                    recursive,
                    max_files,
                    hash_set.len(),
                    patterns.len()
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
            println!(
                "[cyberdefender] watch {} interval={}ms recursive={} (Ctrl+C to stop)",
                root.display(),
                interval_ms,
                recursive
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
