//! `aegis` — single operator front door for the suite kernel.

mod config;

use clap::{Parser, Subcommand};
use colored::*;
use config::SuiteConfig;
use s2o_kernel::{
    apply_policy, collect_platform_status, compute_posture_score, create_firewall_engine, demo_mode,
    host_id, load_policy_file, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{AegisEvent, HealthState, PolicyDocument, SCHEMA_VERSION};
use s2o_store::EventStore;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aegis")]
#[command(author = "Split2ops Software")]
#[command(version = "0.1.0")]
#[command(about = "S2O Aegis operator CLI — one front door to the suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print suite / kernel versions
    Version,
    /// Honest platform matrix (same as aegisd status)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Kernel / host doctor
    Doctor,
    /// Full audit report (status + posture + data files)
    Report {
        #[arg(long)]
        json: bool,
        /// Write report to path (in addition to stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Policy operations
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Recent events from the local store
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Rotate the local event log now (archives to events.jsonl.1 …)
    Rotate {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5)]
        keep: usize,
    },
    /// Follow live events from the JSONL store
    Watch {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        #[arg(long, default_value_t = 5)]
        from_recent: usize,
    },
    /// Run response playbooks against recent events (dry-run by default)
    Playbook {
        #[command(subcommand)]
        command: PlaybookCmd,
    },
    /// Zip the .aegis data directory
    Backup {
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Output zip path (default .aegis-backup-<timestamp>.zip)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore a backup zip into the data directory (merge)
    Restore {
        /// Path to backup zip
        zip: PathBuf,
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Allow overwriting existing files
        #[arg(long)]
        force: bool,
    },
    /// Non-interactive self-test (exit 1 on failure)
    Selftest {
        #[arg(long, default_value_t = 40)]
        min_posture: u32,
    },
    /// First-time bootstrap of .aegis data + starter policy/playbooks/gate
    Setup {
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Apply edge policy pack after seeding
        #[arg(long, default_value_t = true)]
        apply_policy: bool,
        /// Skip policy apply
        #[arg(long)]
        no_policy: bool,
    },
    /// Show or write suite config (.aegis/config.json)
    Config {
        #[command(subcommand)]
        command: ConfigCmd,
    },
    /// Run a product CLI if on PATH / target/debug (best-effort shim)
    Run {
        /// Product binary: cyberwall, cyberdns, cyberdefender, cyberedr, ...
        product: String,
        /// Args forwarded to the product
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Windows Service / Scheduled Task control for aegisd (T1 packaging)
    Service {
        #[command(subcommand)]
        command: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Show SCM / Scheduled Task state for S2OAegisd
    Status {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
    /// Register Windows Service (requires Administrator)
    Install {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
        /// Path to aegisd.exe (default: next to aegis / target)
        #[arg(long)]
        bin: Option<PathBuf>,
        /// Defaults to %LOCALAPPDATA%\S2O\Aegis\data
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:9090")]
        health_bind: String,
        /// Also register AtLogOn Scheduled Task (user-level fallback)
        #[arg(long)]
        task: bool,
    },
    /// Remove Windows Service registration
    Uninstall {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
        #[arg(long)]
        task: bool,
    },
    /// Start the service (or Scheduled Task)
    Start {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
    /// Stop the service
    Stop {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
}

fn default_service_data_dir() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base).join("S2O").join("Aegis").join("data");
    }
    PathBuf::from(".aegis")
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print effective config (file + defaults)
    Show {
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
    },
    /// Write default config file
    Init {
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Apply {
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
    },
    Example {
        /// wall | edge
        #[arg(long, default_value = "edge")]
        kind: String,
    },
}

#[derive(Subcommand)]
enum PlaybookCmd {
    /// Write a starter playbook file
    Init {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
    },
    /// Evaluate playbooks against recent events
    Run {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Actually perform actions (default is dry-run)
        #[arg(long)]
        apply: bool,
    },
    /// Continuously follow events and run matching playbooks
    Watch {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        /// Actually perform actions (default is dry-run)
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookFile {
    rules: Vec<PlaybookRule>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookRule {
    name: String,
    #[serde(default)]
    enabled: bool,
    when: PlaybookWhen,
    then: Vec<PlaybookAction>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookWhen {
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    message_contains: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookAction {
    #[serde(rename = "type")]
    action_type: String,
    #[serde(default)]
    attr: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    /// Webhook URL for action_type = webhook
    #[serde(default)]
    url: Option<String>,
}

fn default_playbooks() -> PlaybookFile {
    PlaybookFile {
        rules: vec![
            PlaybookRule {
                name: "echo-dns-blocks".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: Some("cyberdns".into()),
                    action: Some("blocked".into()),
                    severity: None,
                    message_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "log".into(),
                    attr: None,
                    domain: None,
                    url: None,
                }],
            },
            PlaybookRule {
                name: "seed-blocklist-from-dns-attr".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: Some("cyberdns".into()),
                    action: Some("blocked".into()),
                    severity: Some("high".into()),
                    message_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "dns_block_attr".into(),
                    attr: Some("domain".into()),
                    domain: None,
                    url: None,
                }],
            },
            PlaybookRule {
                name: "webhook-on-high-block".into(),
                enabled: false,
                when: PlaybookWhen {
                    product: None,
                    action: Some("blocked".into()),
                    severity: Some("high".into()),
                    message_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "webhook".into(),
                    attr: None,
                    domain: None,
                    url: Some("http://127.0.0.1:9999/hook".into()),
                }],
            },
        ],
    }
}

fn event_matches(ev: &s2o_schema::AegisEvent, when: &PlaybookWhen) -> bool {
    if let Some(ref p) = when.product {
        let id = ev.product.as_str();
        let name = format!("{:?}", ev.product).to_ascii_lowercase();
        let pf = p.to_ascii_lowercase();
        if id != pf && !name.contains(&pf) {
            return false;
        }
    }
    if let Some(ref a) = when.action {
        if !format!("{:?}", ev.action).eq_ignore_ascii_case(a) {
            return false;
        }
    }
    if let Some(ref s) = when.severity {
        if !format!("{:?}", ev.severity).eq_ignore_ascii_case(s) {
            return false;
        }
    }
    if let Some(ref m) = when.message_contains {
        if !ev.message.to_ascii_lowercase().contains(&m.to_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn zip_dir(src_dir: &Path, zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{Read, Write};
    use walkdir::WalkDir;
    use zip::write::FileOptions;
    use zip::ZipWriter;

    if let Some(p) = zip_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let file = File::create(zip_path)?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let src_dir = src_dir.canonicalize().unwrap_or_else(|_| src_dir.to_path_buf());

    for entry in WalkDir::new(&src_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let rel = path.strip_prefix(&src_dir).unwrap_or(path);
        let name = rel.to_string_lossy().replace('\\', "/");
        zip.start_file(name, options)?;
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        zip.write_all(&buf)?;
    }
    zip.finish()?;
    Ok(())
}

fn unzip_to(zip_path: &Path, dest: &Path, force: bool) -> Result<usize, Box<dyn std::error::Error>> {
    use std::fs::File;
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut n = 0usize;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(p) => dest.join(p),
            None => continue,
        };
        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
            continue;
        }
        if outpath.exists() && !force {
            continue;
        }
        if let Some(p) = outpath.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut outfile = File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;
        n += 1;
    }
    Ok(n)
}

async fn run_playbook_actions(
    rule: &PlaybookRule,
    ev: &AegisEvent,
    apply: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for act in &rule.then {
        match act.action_type.as_str() {
            "log" => {
                println!("    -> log (ok)");
            }
            "dns_block_attr" => {
                let key = act.attr.as_deref().unwrap_or("domain");
                let domain = ev
                    .attrs
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| act.domain.clone());
                match domain {
                    Some(d) if apply => {
                        append_dns_block(&d)?;
                        println!("    -> dns_block {d} APPLIED");
                    }
                    Some(d) => {
                        println!("    -> dns_block {d} (dry-run)");
                    }
                    None => println!("    -> dns_block skipped (no domain)"),
                }
            }
            "dns_block" => {
                if let Some(d) = &act.domain {
                    if apply {
                        append_dns_block(d)?;
                        println!("    -> dns_block {d} APPLIED");
                    } else {
                        println!("    -> dns_block {d} (dry-run)");
                    }
                }
            }
            "webhook" => {
                let url = act.url.clone().unwrap_or_default();
                if url.is_empty() {
                    println!("    -> webhook skipped (no url)");
                } else if apply {
                    let body = serde_json::json!({
                        "rule": rule.name,
                        "event_id": ev.id.to_string(),
                        "product": ev.product.as_str(),
                        "action": format!("{:?}", ev.action),
                        "severity": format!("{:?}", ev.severity),
                        "message": ev.message,
                        "attrs": ev.attrs,
                        "host_id": ev.host_id,
                        "ts": ev.ts.to_rfc3339(),
                    });
                    match reqwest::Client::new()
                        .post(&url)
                        .json(&body)
                        .timeout(std::time::Duration::from_secs(5))
                        .send()
                        .await
                    {
                        Ok(r) => println!("    -> webhook {} status={}", url, r.status()),
                        Err(e) => println!("    -> webhook {} ERROR {e}", url),
                    }
                } else {
                    println!("    -> webhook {url} (dry-run)");
                }
            }
            other => println!("    -> unknown action {other}"),
        }
    }
    Ok(())
}

fn append_dns_block(domain: &str) -> std::io::Result<()> {
    let path = Path::new(".aegis/dns-blocklist.txt");
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Ok(());
    }
    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    if existing.lines().any(|l| l.trim().eq_ignore_ascii_case(&d)) {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{d}")?;
    Ok(())
}

fn find_product_bin(name: &str) -> Option<PathBuf> {
    let suffixes = ["", ".exe"];
    let candidates = [
        format!("target/debug/{name}"),
        format!("target/release/{name}"),
        name.to_string(),
    ];
    for c in &candidates {
        for suf in &suffixes {
            let p = PathBuf::from(format!("{c}{suf}"));
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn resolve_aegisd_bin(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p);
        }
    }
    find_product_bin("aegisd")
}

fn sc_query(name: &str) -> Option<String> {
    let out = Command::new("sc").args(["query", name]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() || text.contains("STATE") {
        Some(text)
    } else {
        None
    }
}

fn run_sc(args: &[&str]) -> Result<(i32, String, String), Box<dyn std::error::Error>> {
    let out = Command::new("sc").args(args).output()?;
    let code = out.status.code().unwrap_or(1);
    Ok((
        code,
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Version => {
            println!("aegis-cli          0.1.0");
            println!("s2o-kernel         {KERNEL_VERSION}");
            println!("s2o-schema         {SCHEMA_VERSION}");
            println!("phase              {PHASE_LABEL}");
            println!("tier_ceiling       {}", TIER_CEILING.as_str());
        }
        Commands::Status { json } => {
            let status = collect_platform_status(&fw).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "    S2O AEGIS  (operator front door)                      "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Phase        : {}", status.phase);
                println!(" OS           : {}", status.os.as_str());
                println!(" Tier ceiling : {}", status.tier_ceiling.as_str());
                println!(" Host         : {}", status.host_id);
                println!(
                    " Demo mode    : {}",
                    if status.demo_mode { "ON" } else { "OFF" }
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                for m in &status.modules {
                    let state_col = match m.state {
                        HealthState::Implemented => m.state.as_str().green().bold(),
                        HealthState::Partial => m.state.as_str().yellow().bold(),
                        HealthState::Demo => m.state.as_str().yellow().bold(),
                        HealthState::Degraded => m.state.as_str().red().bold(),
                        _ => m.state.as_str().red(),
                    };
                    println!(" {:<16} {}", m.id.bold(), state_col);
                    println!("                  {}", m.detail);
                }
            }
        }
        Commands::Doctor => {
            println!("{}", "Aegis doctor".bold().green());
            println!(" kernel       : {KERNEL_VERSION}");
            println!(" schema       : {SCHEMA_VERSION}");
            println!(" phase        : {PHASE_LABEL}");
            println!(" tier ceiling : {}", TIER_CEILING.as_str());
            println!(" host_id      : {}", host_id());
            println!(
                " demo_mode    : {}",
                if demo_mode() { "ON" } else { "OFF" }
            );
            match collect_platform_status(&fw).await.modules.iter().find(|m| m.id == "cyberwall") {
                Some(m) => println!(" cyberwall    : {} — {}", m.state.as_str(), m.detail),
                None => println!(" cyberwall    : missing from matrix"),
            }
            let event_log = PathBuf::from(".aegis/events.jsonl");
            if event_log.exists() {
                let store = EventStore::open(&event_log)?;
                println!(
                    " event_log    : {} ({} events)",
                    event_log.display(),
                    store.count()?
                );
            } else {
                println!(
                    " event_log    : {} (missing)",
                    event_log.display()
                );
            }
            let bl = PathBuf::from(".aegis/dns-blocklist.txt");
            println!(
                " dns_blocklist: {} ({})",
                bl.display(),
                if bl.exists() { "present" } else { "missing" }
            );
        }
        Commands::Report { json, out } => {
            let status = collect_platform_status(&fw).await;
            let posture = compute_posture_score(&fw).await?;
            let event_log = PathBuf::from(".aegis/events.jsonl");
            let event_count = if event_log.exists() {
                EventStore::open(&event_log)?.count().unwrap_or(0)
            } else {
                0
            };
            let event_bytes = if event_log.exists() {
                EventStore::open(&event_log)?.len_bytes().unwrap_or(0)
            } else {
                0
            };
            let files = [
                (".aegis/events.jsonl", event_log.exists()),
                (".aegis/dns-blocklist.txt", Path::new(".aegis/dns-blocklist.txt").exists()),
                (".aegis/ioc-store.json", Path::new(".aegis/ioc-store.json").exists()),
                (".aegis/gate-routes.json", Path::new(".aegis/gate-routes.json").exists()),
                (".aegis/wg0.conf", Path::new(".aegis/wg0.conf").exists()),
                (".aegis/defender-rules.json", Path::new(".aegis/defender-rules.json").exists()),
            ];
            let by_state = {
                let mut m = std::collections::BTreeMap::new();
                for modu in &status.modules {
                    *m.entry(modu.state.as_str().to_string()).or_insert(0u32) += 1;
                }
                m
            };
            let report = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "platform": status,
                "posture": posture,
                "event_log": {
                    "path": event_log.display().to_string(),
                    "events": event_count,
                    "bytes": event_bytes,
                },
                "data_files": files.iter().map(|(p, ok)| serde_json::json!({"path": p, "present": ok})).collect::<Vec<_>>(),
                "module_state_counts": by_state,
                "kernel_version": KERNEL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "phase": PHASE_LABEL,
                "tier_ceiling": TIER_CEILING.as_str(),
            });
            let text = if json {
                serde_json::to_string_pretty(&report)?
            } else {
                let mut md = String::new();
                md.push_str("# S2O Aegis Audit Report\n\n");
                md.push_str(&format!("- **Host:** {}\n", status.host_id));
                md.push_str(&format!("- **OS:** {}\n", status.os.as_str()));
                md.push_str(&format!("- **Phase:** {}\n", status.phase));
                md.push_str(&format!("- **Tier:** {}\n", status.tier_ceiling.as_str()));
                md.push_str(&format!(
                    "- **Posture:** {} / {} {}\n",
                    posture.score,
                    posture.max_score,
                    if posture.passes(50) { "PASS@50" } else { "BELOW 50" }
                ));
                md.push_str(&format!("- **Events:** {event_count} ({event_bytes} bytes)\n\n"));
                md.push_str("## Modules\n\n");
                md.push_str("| ID | State | Detail |\n|----|-------|--------|\n");
                for m in &status.modules {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        m.id,
                        m.state.as_str(),
                        m.detail.replace('|', "/")
                    ));
                }
                md.push_str("\n## Data files\n\n");
                for (p, ok) in &files {
                    md.push_str(&format!(
                        "- `{}`: {}\n",
                        p,
                        if *ok { "present" } else { "missing" }
                    ));
                }
                md.push_str("\n## Posture checks\n\n");
                for c in &posture.checks {
                    md.push_str(&format!(
                        "- [{}] **{}** ({}) — {}\n",
                        if c.pass { "PASS" } else { "FAIL" },
                        c.id,
                        c.weight,
                        c.detail
                    ));
                }
                md
            };
            if let Some(path) = out {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, &text)?;
                eprintln!("[aegis] wrote {}", path.display());
            }
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
        }
        Commands::Policy { command } => match command {
            PolicyCmd::Example { kind } => {
                let doc = if kind.eq_ignore_ascii_case("wall") {
                    PolicyDocument::example_wall_enable()
                } else {
                    PolicyDocument::example_edge_pack()
                };
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            PolicyCmd::Apply { path, event_log } => {
                let doc = load_policy_file(&path)?;
                let store = Arc::new(EventStore::open(&event_log)?);
                let result = apply_policy(&doc, &fw, Some(store)).await?;
                if result.ok {
                    println!(
                        "{}",
                        format!("[aegis] policy OK: {}", result.policy_name)
                            .green()
                            .bold()
                    );
                } else {
                    println!(
                        "{}",
                        format!("[aegis] policy incomplete: {}", result.policy_name)
                            .yellow()
                            .bold()
                    );
                }
                for a in &result.applied {
                    println!("  applied : {}", a.green());
                }
                for s in &result.skipped {
                    println!("  skipped : {}", s.dimmed());
                }
                for e in &result.errors {
                    println!("  error   : {}", e.red());
                }
                if !result.ok {
                    std::process::exit(1);
                }
            }
        },
        Commands::Events { event_log, limit } => {
            if !event_log.exists() {
                eprintln!("[aegis] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let events = store.recent(limit)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        Commands::Rotate { event_log, keep } => {
            let store = EventStore::open_with_rotation(&event_log, 0, keep)?;
            let before = store.len_bytes().unwrap_or(0);
            store.rotate()?;
            println!(
                "[aegis] rotated {} (was {} bytes) → {}.1",
                event_log.display(),
                before,
                event_log.display()
            );
        }
        Commands::Watch {
            event_log,
            interval_ms,
            from_recent,
        } => {
            println!(
                "[aegis] watching {} (Ctrl+C to stop)",
                event_log.display()
            );
            let store = EventStore::open(&event_log)?;
            if from_recent > 0 {
                for ev in store.recent(from_recent)? {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
                println!("{}", "---- live ----".dimmed());
            }
            let mut offset = store.byte_len().unwrap_or(0);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                let store = EventStore::open(&event_log)?;
                let (next, events) = store.read_since(offset)?;
                offset = next;
                for ev in events {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
            }
        }
        Commands::Playbook { command } => match command {
            PlaybookCmd::Init { path } => {
                if let Some(p) = path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                let pb = default_playbooks();
                std::fs::write(&path, serde_json::to_string_pretty(&pb)?)?;
                println!(
                    "{}",
                    format!("[aegis] wrote playbook {}", path.display())
                        .green()
                        .bold()
                );
            }
            PlaybookCmd::Run {
                path,
                event_log,
                limit,
                apply,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                if !event_log.exists() {
                    eprintln!("[aegis] no event log");
                    std::process::exit(1);
                }
                let store = EventStore::open(&event_log)?;
                let events = store.recent(limit)?;
                let mode = if apply { "APPLY" } else { "DRY-RUN" };
                println!(
                    "[aegis] playbook {} ({} rules, {} events window)",
                    mode,
                    pb.rules.len(),
                    events.len()
                );
                let mut fired = 0u32;
                for rule in pb.rules.iter().filter(|r| r.enabled) {
                    for ev in &events {
                        if !event_matches(ev, &rule.when) {
                            continue;
                        }
                        fired += 1;
                        println!(
                            "  rule={} event={} | {}",
                            rule.name.yellow(),
                            ev.id,
                            ev.message
                        );
                        run_playbook_actions(rule, ev, apply).await?;
                    }
                }
                println!("[aegis] playbook complete: {fired} rule hits");
            }
            PlaybookCmd::Watch {
                path,
                event_log,
                interval_ms,
                apply,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let mode = if apply { "APPLY" } else { "DRY-RUN" };
                println!(
                    "[aegis] playbook watch {} on {} (Ctrl+C to stop)",
                    mode,
                    event_log.display()
                );
                let store = EventStore::open(&event_log)?;
                let mut offset = store.byte_len().unwrap_or(0);
                // de-dupe rule+event pairs within process lifetime
                let mut seen: HashSet<String> = HashSet::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                    // reload playbooks each tick so edits apply live
                    let pb = match std::fs::read_to_string(&path) {
                        Ok(t) => serde_json::from_str::<PlaybookFile>(&t).unwrap_or(pb.clone()),
                        Err(_) => pb.clone(),
                    };
                    let store = EventStore::open(&event_log)?;
                    let (next, events) = store.read_since(offset)?;
                    offset = next;
                    for ev in events {
                        for rule in pb.rules.iter().filter(|r| r.enabled) {
                            if !event_matches(&ev, &rule.when) {
                                continue;
                            }
                            let key = format!("{}:{}", rule.name, ev.id);
                            if !seen.insert(key) {
                                continue;
                            }
                            println!(
                                "  rule={} event={} | {}",
                                rule.name.yellow(),
                                ev.id,
                                ev.message
                            );
                            run_playbook_actions(rule, &ev, apply).await?;
                        }
                    }
                }
            }
        },
        Commands::Config { command } => match command {
            ConfigCmd::Show { path } => {
                let cfg = SuiteConfig::load(&path);
                println!("{}", serde_json::to_string_pretty(&cfg)?);
                if path.exists() {
                    eprintln!("(from {})", path.display());
                } else {
                    eprintln!("(defaults; no file at {})", path.display());
                }
            }
            ConfigCmd::Init { path } => {
                let cfg = SuiteConfig::default();
                cfg.save(&path)?;
                println!(
                    "{}",
                    format!("[aegis] wrote {}", path.display()).green().bold()
                );
            }
        },
        Commands::Setup {
            data_dir,
            apply_policy,
            no_policy,
        } => {
            std::fs::create_dir_all(&data_dir)?;
            println!(
                "{}",
                format!("[aegis] setup data dir {}", data_dir.display())
                    .green()
                    .bold()
            );

            // Touch event log
            let event_log = data_dir.join("events.jsonl");
            let _ = EventStore::open(&event_log)?;

            // Suite config
            let cfg_path = data_dir.join("config.json");
            if !cfg_path.exists() {
                let mut cfg = SuiteConfig::default();
                cfg.data_dir = data_dir.display().to_string();
                cfg.event_log = event_log.display().to_string();
                cfg.playbooks = data_dir.join("playbooks.json").display().to_string();
                cfg.gate_config = data_dir.join("gate-routes.json").display().to_string();
                cfg.save(&cfg_path)?;
                println!("  + {}", cfg_path.display());
            }

            // DNS blocklist seed
            let bl = data_dir.join("dns-blocklist.txt");
            if !bl.exists() {
                std::fs::write(
                    &bl,
                    "# S2O CyberDNS blocklist\nmalware.test.s2o\nphishing.test.s2o\n",
                )?;
                println!("  + {}", bl.display());
            }

            // Defender rules
            let rules = data_dir.join("defender-rules.json");
            if !rules.exists() {
                let seed = serde_json::json!({
                    "version": "0.1.0",
                    "blocked_hashes": [],
                    "blocked_name_substrings": ["eicar"]
                });
                std::fs::write(&rules, serde_json::to_string_pretty(&seed)?)?;
                println!("  + {}", rules.display());
            }

            // yara-lite
            let yara = data_dir.join("yara-lite.rules");
            if !yara.exists() {
                std::fs::write(
                    &yara,
                    "# name: needle\n# eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE\n",
                )?;
                println!("  + {}", yara.display());
            }

            // playbooks
            let pb = data_dir.join("playbooks.json");
            if !pb.exists() {
                std::fs::write(&pb, serde_json::to_string_pretty(&default_playbooks())?)?;
                println!("  + {}", pb.display());
            }

            // gate routes
            let gate = data_dir.join("gate-routes.json");
            if !gate.exists() {
                let g = serde_json::json!({
                    "listen": "127.0.0.1:18443",
                    "min_score": 50,
                    "routes": [{
                        "name": "demo",
                        "path_prefix": "/",
                        "upstream": "https://example.com"
                    }]
                });
                std::fs::write(&gate, serde_json::to_string_pretty(&g)?)?;
                println!("  + {}", gate.display());
            }

            // IOC store empty
            let ioc = data_dir.join("ioc-store.json");
            if !ioc.exists() {
                let s = serde_json::json!({
                    "version": "0.1.0",
                    "updated_at": chrono::Utc::now().to_rfc3339(),
                    "entries": []
                });
                std::fs::write(&ioc, serde_json::to_string_pretty(&s)?)?;
                println!("  + {}", ioc.display());
            }

            // edge policy example copy
            let policy_src = PathBuf::from("policies/examples/edge-pack.json");
            let policy_dst = data_dir.join("edge-pack.json");
            if policy_src.exists() && !policy_dst.exists() {
                std::fs::copy(&policy_src, &policy_dst)?;
                println!("  + {}", policy_dst.display());
            }

            let do_policy = apply_policy && !no_policy;
            if do_policy {
                let path = if policy_dst.exists() {
                    policy_dst
                } else {
                    policy_src
                };
                if path.exists() {
                    println!("[aegis] applying policy {} ...", path.display());
                    let doc = load_policy_file(&path)?;
                    let store = Arc::new(EventStore::open(&event_log)?);
                    let result = s2o_kernel::apply_policy(&doc, &fw, Some(store)).await?;
                    if result.ok {
                        println!("{}", "[aegis] policy OK".green().bold());
                    } else {
                        println!("{}", "[aegis] policy incomplete".yellow().bold());
                        for e in &result.errors {
                            println!("  error: {e}");
                        }
                    }
                }
            }

            println!("{}", "[aegis] setup complete".green().bold());
            println!("Next:");
            println!("  aegis doctor");
            println!("  aegis selftest");
            println!("  aegis status");
            println!("  cyberztna serve --tls");
        }
        Commands::Backup { data_dir, out } => {
            if !data_dir.exists() {
                eprintln!("[aegis] data dir missing: {}", data_dir.display());
                std::process::exit(1);
            }
            let out = out.unwrap_or_else(|| {
                let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
                PathBuf::from(format!(".aegis-backup-{ts}.zip"))
            });
            zip_dir(&data_dir, &out)?;
            println!(
                "{}",
                format!("[aegis] backup wrote {}", out.display())
                    .green()
                    .bold()
            );
        }
        Commands::Restore {
            zip,
            data_dir,
            force,
        } => {
            if !zip.exists() {
                eprintln!("[aegis] zip missing: {}", zip.display());
                std::process::exit(1);
            }
            std::fs::create_dir_all(&data_dir)?;
            let n = unzip_to(&zip, &data_dir, force)?;
            println!(
                "{}",
                format!(
                    "[aegis] restored {n} files into {} (force={force})",
                    data_dir.display()
                )
                .green()
                .bold()
            );
        }
        Commands::Selftest { min_posture } => {
            let mut failed = 0u32;
            let mut checks = Vec::new();
            checks.push(("kernel_version", !KERNEL_VERSION.is_empty()));
            checks.push(("schema_version", !SCHEMA_VERSION.is_empty()));
            let status = collect_platform_status(&fw).await;
            checks.push(("modules_count_9", status.modules.len() == 9));
            let wall_ok = status
                .modules
                .iter()
                .any(|m| m.id == "cyberwall" && matches!(m.state, HealthState::Implemented | HealthState::Partial));
            checks.push(("cyberwall_present", wall_ok));
            match compute_posture_score(&fw).await {
                Ok(p) => {
                    checks.push(("posture_compute", true));
                    checks.push(("posture_min", p.score >= min_posture));
                    println!(
                        " posture_score={} min={} {}",
                        p.score,
                        min_posture,
                        if p.score >= min_posture {
                            "PASS".green().bold()
                        } else {
                            "FAIL".red().bold()
                        }
                    );
                }
                Err(e) => {
                    checks.push(("posture_compute", false));
                    checks.push(("posture_min", false));
                    eprintln!(" posture error: {e}");
                }
            }
            let el = PathBuf::from(".aegis/events.jsonl");
            if el.exists() {
                match EventStore::open(&el) {
                    Ok(s) => {
                        let _ = s.count();
                        checks.push(("event_store", true));
                    }
                    Err(_) => checks.push(("event_store", false)),
                }
            } else {
                // creatable is enough
                match EventStore::open(&el) {
                    Ok(_) => checks.push(("event_store", true)),
                    Err(_) => checks.push(("event_store", false)),
                }
            }
            println!("{}", "Aegis selftest".bold().green());
            for (name, ok) in &checks {
                if *ok {
                    println!("  [PASS] {name}");
                } else {
                    println!("  [FAIL] {}", name.red());
                    failed += 1;
                }
            }
            if failed > 0 {
                println!(
                    "{}",
                    format!("SELFTEST FAIL ({failed} checks)").red().bold()
                );
                std::process::exit(1);
            }
            println!("{}", "SELFTEST PASS".green().bold());
        }
        Commands::Service { command } => {
            if !cfg!(windows) {
                eprintln!("[aegis] service commands are Windows-only (use systemd unit on Linux later)");
                std::process::exit(2);
            }
            match command {
                ServiceCmd::Status { name } => {
                    println!("{}", "Aegis service status".bold().green());
                    println!(" Service name : {name}");
                    match sc_query(&name) {
                        Some(text) => {
                            for line in text.lines().take(12) {
                                println!("  {line}");
                            }
                            let running = text.to_ascii_uppercase().contains("RUNNING");
                            println!(
                                " Summary      : {}",
                                if running {
                                    "RUNNING".green().bold().to_string()
                                } else {
                                    "installed (not running or stopped)".yellow().to_string()
                                }
                            );
                        }
                        None => {
                            println!(" SCM          : {}", "not installed".yellow());
                        }
                    }
                    // Scheduled task probe
                    let task = Command::new("schtasks")
                        .args(["/Query", "/TN", "S2O-Aegisd", "/FO", "LIST"])
                        .output();
                    match task {
                        Ok(o) if o.status.success() => {
                            println!(" Task S2O-Aegisd: {}", "registered".green());
                        }
                        _ => println!(" Task S2O-Aegisd: {}", "not registered".dimmed()),
                    }
                }
                ServiceCmd::Install {
                    name,
                    bin,
                    data_dir,
                    health_bind,
                    task,
                } => {
                    let Some(exe) = resolve_aegisd_bin(bin) else {
                        eprintln!("[aegis] aegisd.exe not found — build first or pass --bin");
                        std::process::exit(2);
                    };
                    let data_dir = data_dir.unwrap_or_else(default_service_data_dir);
                    std::fs::create_dir_all(&data_dir)?;
                    let event_log = data_dir.join("events.jsonl");
                    // binPath for sc: quoted exe + --run-as-service + flags
                    let bin_path = format!(
                        "\"{}\" --run-as-service --event-log \"{}\" --health-bind {}",
                        exe.display(),
                        event_log.display(),
                        health_bind
                    );
                    println!("[aegis] installing service {name}");
                    println!("  binPath : {bin_path}");
                    let (code, stdout, stderr) = run_sc(&[
                        "create",
                        &name,
                        &format!("binPath= {bin_path}"),
                        "start= auto",
                        "DisplayName= S2O Aegis Suite Kernel (aegisd)",
                    ])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!(
                            "[aegis] sc create failed (exit {code}). Run elevated Administrator shell."
                        );
                        std::process::exit(code);
                    }
                    let _ = run_sc(&[
                        "description",
                        &name,
                        "S2O Aegis control plane: health HTTP, status matrix, event store",
                    ]);
                    println!("{}", format!("[aegis] service {name} installed").green().bold());
                    println!("  start : aegis service start --name {name}");
                    if task {
                        let action = format!(
                            "\"{}\" start --event-log \"{}\" --health-bind {}",
                            exe.display(),
                            event_log.display(),
                            health_bind
                        );
                        let out = Command::new("schtasks")
                            .args([
                                "/Create",
                                "/TN",
                                "S2O-Aegisd",
                                "/SC",
                                "ONLOGON",
                                "/RL",
                                "LIMITED",
                                "/F",
                                "/TR",
                                &action,
                            ])
                            .output()?;
                        if out.status.success() {
                            println!("  task  : S2O-Aegisd registered (AtLogOn)");
                        } else {
                            eprintln!(
                                "  task  : failed: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        }
                    }
                }
                ServiceCmd::Uninstall { name, task } => {
                    let _ = run_sc(&["stop", &name]);
                    let (code, stdout, stderr) = run_sc(&["delete", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!("[aegis] sc delete exit {code} (may need Administrator)");
                    } else {
                        println!("{}", format!("[aegis] service {name} removed").yellow());
                    }
                    if task {
                        let _ = Command::new("schtasks")
                            .args(["/Delete", "/TN", "S2O-Aegisd", "/F"])
                            .status();
                        println!("[aegis] task S2O-Aegisd delete attempted");
                    }
                }
                ServiceCmd::Start { name } => {
                    let (code, stdout, stderr) = run_sc(&["start", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        // fallback task
                        let t = Command::new("schtasks")
                            .args(["/Run", "/TN", "S2O-Aegisd"])
                            .output()?;
                        if t.status.success() {
                            println!("[aegis] started via Scheduled Task S2O-Aegisd");
                        } else {
                            eprintln!("[aegis] service start failed (exit {code})");
                            std::process::exit(code);
                        }
                    } else {
                        println!("{}", format!("[aegis] service {name} started").green().bold());
                    }
                }
                ServiceCmd::Stop { name } => {
                    let (code, stdout, stderr) = run_sc(&["stop", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!("[aegis] service stop exit {code}");
                        std::process::exit(code);
                    }
                    println!("{}", format!("[aegis] service {name} stopped").yellow());
                }
            }
        }
        Commands::Run { product, args } => {
            let bin = find_product_bin(&product).ok_or_else(|| {
                format!(
                    "product binary '{product}' not found (build with cargo build -p {product} or similar)"
                )
            })?;
            let status = Command::new(&bin).args(&args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}
