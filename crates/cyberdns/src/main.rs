//! S2O CyberDNS — DoH resolve, blocklist, local UDP proxy, system DNS bind.

mod blocklist;
mod doh;
mod serve;
mod system_dns;

use blocklist::{
    is_allowed, is_blocked, load_allowlist, load_blocklist, normalize_domain, save_allowlist,
    save_blocklist,
};
use clap::{Parser, Subcommand};
use colored::*;
use s2o_ioc::IocStore;
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::fs;
use std::path::{Path, PathBuf};

/// Count non-comment domain lines and raw duplicates before set-normalize.
fn list_line_stats(path: &Path) -> (usize, usize, bool) {
    if !path.exists() {
        return (0, 0, false);
    }
    let Ok(text) = fs::read_to_string(path) else {
        return (0, 0, true);
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut lines = 0usize;
    let mut dups = 0usize;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        lines += 1;
        let n = normalize_domain(line);
        if !seen.insert(n) {
            dups += 1;
        }
    }
    (lines, dups, true)
}

fn domain_denied(
    blocklist: &Path,
    allowlist: &Path,
    ioc_path: &Path,
    domain: &str,
) -> Option<&'static str> {
    // Allowlist overrides blocklist and IOC deny.
    if let Ok(set) = load_allowlist(allowlist) {
        if is_allowed(&set, domain) {
            return None;
        }
    }
    if let Ok(set) = load_blocklist(blocklist) {
        if is_blocked(&set, domain) {
            return Some("blocklist");
        }
    }
    if let Ok(store) = IocStore::load(ioc_path) {
        if store.is_domain_blocked(domain).is_some() {
            return Some("threatgrid_ioc");
        }
    }
    None
}

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.4.0")]
#[command(about = "S2O CyberDNS Guard: DoH + blocklist + local UDP proxy + system DNS", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/dns-blocklist.txt")]
    blocklist: PathBuf,

    /// Domains that always resolve (override blocklist + IOC)
    #[arg(long, global = true, default_value = ".aegis/dns-allowlist.txt")]
    allowlist: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    /// ThreatGrid local IOC store (optional)
    #[arg(long, global = true, default_value = ".aegis/ioc-store.json")]
    ioc_store: PathBuf,

    /// DoH base URLs tried in order (repeatable). Default: Cloudflare then Google.
    #[arg(long = "doh", global = true)]
    doh: Vec<String>,

    #[command(subcommand)]
    command: Commands,
}

fn doh_endpoints(cli: &Cli) -> Vec<String> {
    if cli.doh.is_empty() {
        doh::DEFAULT_DOH_ENDPOINTS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        cli.doh.clone()
    }
}

#[derive(Subcommand)]
enum Commands {
    Status {
        #[arg(long)]
        json: bool,
    },
    Resolve {
        domain: String,
        #[arg(long)]
        json: bool,
    },
    Block { domain: String },
    Unblock { domain: String },
    /// Add domain to allowlist (overrides block/IOC)
    Allow { domain: String },
    /// Remove domain from allowlist
    Unallow { domain: String },
    /// List blocklist (default) or --allow
    List {
        #[arg(long)]
        allow: bool,
        /// Max domains to print (0 = all)
        #[arg(long, default_value_t = 0)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Export blocklist or allowlist as json/csv/text
    Export {
        /// block | allow
        #[arg(long, default_value = "block")]
        list: String,
        /// json | csv | text
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rewrite list file without duplicate domains (dry-run by default)
    Dedupe {
        /// block | allow
        #[arg(long, default_value = "block")]
        list: String,
        /// Actually rewrite the file
        #[arg(long)]
        apply: bool,
    },
    /// Import domains from a text file into block or allow list
    Import {
        /// Path to domain list (one per line; # comments ok; hosts-style supported)
        path: PathBuf,
        /// block | allow
        #[arg(long, default_value = "block")]
        list: String,
        /// Max domains to import (safety cap)
        #[arg(long, default_value_t = 10_000)]
        max: usize,
        /// Dry-run: report counts only
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate lists, overlap, IOC, optional DoH probe
    Doctor {
        /// Resolve example.com via DoH chain
        #[arg(long)]
        probe_doh: bool,
        #[arg(long)]
        json: bool,
    },
    /// Diagnose allow/block/IOC decision for a domain (no DoH)
    Check {
        domain: String,
        #[arg(long)]
        json: bool,
    },
    /// Local UDP DNS proxy (allowlist > blocklist + DoH A answers)
    Serve {
        /// Prefer high ports (5353 is often blocked on Windows / Hyper-V)
        #[arg(short, long, default_value = "127.0.0.1:53553")]
        listen: String,
        /// Print query counters every N seconds (0 = off)
        #[arg(long, default_value_t = 30)]
        stats_secs: u64,
    },
    /// Point OS resolver at local proxy / restore (hijack-lite T0)
    SystemDns {
        #[command(subcommand)]
        command: SystemDnsCmd,
    },
}

#[derive(Subcommand)]
enum SystemDnsCmd {
    /// Show current system DNS configuration
    Show,
    /// Backup current DNS then set primary to SERVER (default 127.0.0.1)
    Set {
        #[arg(long, default_value = "127.0.0.1")]
        server: String,
        /// Windows interface name (default: all interfaces)
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
    },
    /// Restore DNS from backup file
    Restore {
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
    },
    /// Only write backup without changing DNS
    Backup {
        #[arg(long, default_value = ".aegis/dns-system-backup.json")]
        backup: PathBuf,
    },
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
    domain: &str,
) {
    if let Ok(store) = EventStore::open(event_log) {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::CyberDns,
            EventKind::Dns,
            action,
            severity,
            message,
        )
        .with_attr("domain", serde_json::json!(domain))
        .with_ioc(Ioc::Domain(normalize_domain(domain)));
        let _ = store.append(&ev);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let doh_eps = doh_endpoints(&cli);

    match cli.command {
        Commands::Status { json } => {
            let set = load_blocklist(&cli.blocklist)?;
            let ioc_n = IocStore::load(&cli.ioc_store)
                .map(|s| s.entries.len())
                .unwrap_or(0);
            let allow = load_allowlist(&cli.allowlist).unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "product": "cyberdns",
                        "blocklist": cli.blocklist.display().to_string(),
                        "blocklist_count": set.len(),
                        "allowlist": cli.allowlist.display().to_string(),
                        "allowlist_count": allow.len(),
                        "ioc_store": cli.ioc_store.display().to_string(),
                        "ioc_count": ioc_n,
                        "doh_chain": doh_eps,
                        "event_log": cli.event_log.display().to_string(),
                        "implemented": "DoH multi-resolver + allowlist/blocklist + IOC + UDP stats + system-dns",
                        "not_implemented": "DoT, full recursive, transparent redirector",
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "        S2O CyberDNS Guard (Phase 2 shell)               "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    " Implemented       : {}",
                    "DoH multi-resolver + allowlist/blocklist + IOC + UDP stats + system-dns".green()
                );
                println!(" IOC store         : {} ({} entries)", cli.ioc_store.display(), ioc_n);
                println!(
                    " Not implemented   : {}",
                    "DoT, full recursive, transparent redirector".red()
                );
                println!(
                    " DoH chain         : {}",
                    doh_eps.join(" → ").yellow()
                );
                println!(" Blocklist path    : {}", cli.blocklist.display());
                println!(" Blocked domains   : {}", set.len());
                println!(" Allowlist path    : {}", cli.allowlist.display());
                println!(" Allowed domains   : {}", allow.len().to_string().green());
                println!(" Event log         : {}", cli.event_log.display());
                println!(
                    " Proxy             : {}",
                    "cyberdns serve --listen 127.0.0.1:53553".yellow()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
        }
        Commands::List { allow, limit, json } => {
            let (kind, path, set) = if allow {
                (
                    "allow",
                    cli.allowlist.display().to_string(),
                    load_allowlist(&cli.allowlist)?,
                )
            } else {
                (
                    "block",
                    cli.blocklist.display().to_string(),
                    load_blocklist(&cli.blocklist)?,
                )
            };
            let total = set.len();
            let domains: Vec<String> = if limit == 0 {
                set.into_iter().collect()
            } else {
                set.into_iter().take(limit).collect()
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "list": kind,
                        "path": path,
                        "total": total,
                        "shown": domains.len(),
                        "domains": domains,
                    }))?
                );
            } else if domains.is_empty() {
                println!("[cyberdns] {kind}list empty ({path})");
            } else {
                for d in &domains {
                    println!("{d}");
                }
                if limit > 0 && total > domains.len() {
                    println!("[cyberdns] … {total} total; showing {} (--limit)", domains.len());
                }
            }
        }
        Commands::Export { list, format, out } => {
            let allow = list.eq_ignore_ascii_case("allow")
                || list.eq_ignore_ascii_case("allowlist");
            let path = if allow {
                &cli.allowlist
            } else {
                &cli.blocklist
            };
            let set = if allow {
                load_allowlist(path)?
            } else {
                load_blocklist(path)?
            };
            let kind = if allow { "allow" } else { "block" };
            let text = if format.eq_ignore_ascii_case("csv") {
                let mut s = String::from("list,domain\n");
                for d in &set {
                    s.push_str(&format!("{kind},{d}\n"));
                }
                s
            } else if format.eq_ignore_ascii_case("text") {
                let mut s = String::new();
                for d in &set {
                    s.push_str(d);
                    s.push('\n');
                }
                s
            } else {
                serde_json::to_string_pretty(&serde_json::json!({
                    "list": kind,
                    "path": path.display().to_string(),
                    "count": set.len(),
                    "domains": set.iter().cloned().collect::<Vec<_>>(),
                }))?
            };
            if let Some(p) = out {
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&p, &text)?;
                println!(
                    "{}",
                    format!(
                        "[cyberdns] exported {} {} domain(s) → {}",
                        set.len(),
                        kind,
                        p.display()
                    )
                    .green()
                    .bold()
                );
            } else {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
            }
        }
        Commands::Dedupe { list, apply } => {
            let allow = list.eq_ignore_ascii_case("allow")
                || list.eq_ignore_ascii_case("allowlist");
            let path = if allow {
                cli.allowlist.clone()
            } else {
                cli.blocklist.clone()
            };
            if !path.exists() {
                eprintln!("[cyberdns] missing {}", path.display());
                std::process::exit(2);
            }
            let (raw_lines, dups, _) = list_line_stats(&path);
            let set = if allow {
                load_allowlist(&path)?
            } else {
                load_blocklist(&path)?
            };
            let unique = set.len();
            if dups == 0 && raw_lines == unique {
                println!(
                    "[cyberdns] {} already unique ({} domains)",
                    path.display(),
                    unique
                );
            } else if !apply {
                println!(
                    "[cyberdns] dedupe dry-run {}: raw_lines={raw_lines} unique={unique} dups={dups} (use --apply)",
                    path.display()
                );
            } else if allow {
                save_allowlist(&path, &set)?;
                println!(
                    "{}",
                    format!(
                        "[cyberdns] dedupe APPLIED {} → {unique} domains (removed {dups} dups)",
                        path.display()
                    )
                    .green()
                    .bold()
                );
            } else {
                save_blocklist(&path, &set)?;
                println!(
                    "{}",
                    format!(
                        "[cyberdns] dedupe APPLIED {} → {unique} domains (removed {dups} dups)",
                        path.display()
                    )
                    .green()
                    .bold()
                );
            }
        }
        Commands::Import {
            path,
            list,
            max,
            dry_run,
        } => {
            if !path.exists() {
                eprintln!("[cyberdns] missing import file {}", path.display());
                std::process::exit(2);
            }
            let allow = list.eq_ignore_ascii_case("allow")
                || list.eq_ignore_ascii_case("allowlist");
            let dest = if allow {
                cli.allowlist.clone()
            } else {
                cli.blocklist.clone()
            };
            let text = fs::read_to_string(&path)?;
            let mut candidates: Vec<String> = Vec::new();
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                // hosts-style: "0.0.0.0 evil.com" or "127.0.0.1 evil.com"
                let domain = if line.contains(char::is_whitespace) {
                    line.split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim()
                } else {
                    line
                };
                let d = normalize_domain(domain);
                if d.is_empty() || d.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                candidates.push(d);
                if candidates.len() >= max {
                    break;
                }
            }
            let mut set = if allow {
                load_allowlist(&dest)?
            } else {
                load_blocklist(&dest)?
            };
            let before = set.len();
            let mut added = 0usize;
            for d in &candidates {
                if set.insert(d.clone()) {
                    added += 1;
                }
            }
            let kind = if allow { "allow" } else { "block" };
            if dry_run {
                println!(
                    "[cyberdns] import dry-run → {kind}list: scanned={} new={added} already={} total_after={}",
                    candidates.len(),
                    before,
                    before + added
                );
            } else {
                if allow {
                    save_allowlist(&dest, &set)?;
                } else {
                    save_blocklist(&dest, &set)?;
                }
                println!(
                    "{}",
                    format!(
                        "[cyberdns] imported {added} new {kind} domain(s) from {} → {} (total {})",
                        path.display(),
                        dest.display(),
                        set.len()
                    )
                    .green()
                    .bold()
                );
                if added > 0 {
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Info,
                        format!("dns import {kind} added={added} from={}", path.display()),
                        "import",
                    );
                }
            }
        }
        Commands::Doctor { probe_doh, json } => {
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut notes: Vec<serde_json::Value> = Vec::new();
            let mut check = |label: &str, good: bool, soft: bool, detail: &str| {
                notes.push(serde_json::json!({
                    "label": label,
                    "ok": good,
                    "warn": soft && !good,
                    "detail": detail,
                }));
                if good {
                    ok += 1;
                    if !json {
                        println!("  {} {} — {}", "OK".green().bold(), label, detail);
                    }
                } else if soft {
                    warn += 1;
                    if !json {
                        println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                    }
                } else {
                    fail += 1;
                    if !json {
                        println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                    }
                }
            };

            if !json {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      S2O CyberDNS doctor                                "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            let (bl_lines, bl_dups, bl_present) = list_line_stats(&cli.blocklist);
            let block = load_blocklist(&cli.blocklist).unwrap_or_default();
            check(
                "blocklist file",
                bl_present,
                true,
                &if bl_present {
                    format!(
                        "{} ({} unique, {} raw lines, {} dups)",
                        cli.blocklist.display(),
                        block.len(),
                        bl_lines,
                        bl_dups
                    )
                } else {
                    format!("{} missing", cli.blocklist.display())
                },
            );
            if bl_dups > 0 {
                check(
                    "blocklist dups",
                    false,
                    true,
                    &format!("{bl_dups} duplicate lines (load dedupes)"),
                );
            }

            let (al_lines, al_dups, al_present) = list_line_stats(&cli.allowlist);
            let allow = load_allowlist(&cli.allowlist).unwrap_or_default();
            check(
                "allowlist file",
                al_present || allow.is_empty(),
                true,
                &if al_present {
                    format!(
                        "{} ({} unique, {} raw, {} dups)",
                        cli.allowlist.display(),
                        allow.len(),
                        al_lines,
                        al_dups
                    )
                } else {
                    format!("{} missing (ok if unused)", cli.allowlist.display())
                },
            );

            let overlap: Vec<_> = allow.intersection(&block).cloned().collect();
            check(
                "allow∩block",
                overlap.is_empty(),
                true,
                &if overlap.is_empty() {
                    "no overlap".into()
                } else {
                    format!(
                        "{} domain(s) in both (allow wins): {}",
                        overlap.len(),
                        overlap.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    )
                },
            );

            let ioc_domains = if cli.ioc_store.exists() {
                IocStore::load(&cli.ioc_store)
                    .map(|s| s.count_by_kind(s2o_ioc::IocKind::Domain))
                    .unwrap_or(0)
            } else {
                0
            };
            check(
                "ioc store",
                cli.ioc_store.exists(),
                true,
                &if cli.ioc_store.exists() {
                    format!(
                        "{} ({} domain IOCs)",
                        cli.ioc_store.display(),
                        ioc_domains
                    )
                } else {
                    format!("{} missing", cli.ioc_store.display())
                },
            );

            check(
                "event log",
                cli.event_log.exists(),
                true,
                &format!("{}", cli.event_log.display()),
            );

            check(
                "doh chain",
                !doh_eps.is_empty(),
                false,
                &doh_eps.join(" → "),
            );

            let mut doh_detail = serde_json::Value::Null;
            if probe_doh {
                match doh::resolve_a_strings("example.com", &doh_eps).await {
                    Ok((ips, used)) if !ips.is_empty() => {
                        check(
                            "doh probe",
                            true,
                            false,
                            &format!("example.com → {} via {used}", ips.join(",")),
                        );
                        doh_detail = serde_json::json!({
                            "ok": true,
                            "resolver": used,
                            "ips": ips,
                        });
                    }
                    Ok((_, used)) => {
                        check(
                            "doh probe",
                            false,
                            true,
                            &format!("no A for example.com via {used}"),
                        );
                        doh_detail = serde_json::json!({"ok": false, "resolver": used});
                    }
                    Err(e) => {
                        check("doh probe", false, false, &format!("error: {e}"));
                        doh_detail = serde_json::json!({"ok": false, "error": e.to_string()});
                    }
                }
            } else if !json {
                println!(
                    "  {} doh probe — skipped (pass --probe-doh)",
                    "SKIP".dimmed()
                );
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "blocklist_unique": block.len(),
                        "allowlist_unique": allow.len(),
                        "overlap": overlap,
                        "ioc_domains": ioc_domains,
                        "doh_endpoints": doh_eps,
                        "doh_probe": doh_detail,
                        "checks": notes,
                    }))?
                );
            } else {
                println!(
                    " Summary: {} ok, {} warn, {} fail",
                    ok.to_string().green(),
                    warn.to_string().yellow(),
                    fail.to_string().red()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
            if fail > 0 {
                std::process::exit(1);
            }
        }
        Commands::Check { domain, json } => {
            let d = normalize_domain(&domain);
            if d.is_empty() {
                eprintln!("[cyberdns] empty domain");
                std::process::exit(2);
            }
            let allow = load_allowlist(&cli.allowlist).unwrap_or_default();
            let block = load_blocklist(&cli.blocklist).unwrap_or_default();
            let allowed = is_allowed(&allow, &d);
            let blocked = is_blocked(&block, &d);
            let ioc_hit = IocStore::load(&cli.ioc_store)
                .ok()
                .and_then(|s| s.is_domain_blocked(&d).map(|e| e.value.clone()));
            let denied = domain_denied(&cli.blocklist, &cli.allowlist, &cli.ioc_store, &d);
            let decision = if allowed {
                "ALLOW (allowlist)"
            } else if let Some(r) = denied {
                match r {
                    "blocklist" => "DENY (blocklist)",
                    "threatgrid_ioc" => "DENY (threatgrid_ioc)",
                    other => other,
                }
            } else {
                "ALLOW (would resolve)"
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "domain": d,
                        "decision": decision,
                        "allowlist_hit": allowed,
                        "blocklist_hit": blocked,
                        "ioc_hit": ioc_hit,
                        "deny_reason": denied,
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    format!("  CyberDNS check: {d}").bold().green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    " Decision   : {}",
                    if denied.is_some() && !allowed {
                        decision.red().bold().to_string()
                    } else {
                        decision.green().bold().to_string()
                    }
                );
                println!(
                    " Allowlist  : {}",
                    if allowed {
                        "HIT (overrides block/IOC)".green().to_string()
                    } else {
                        "miss".dimmed().to_string()
                    }
                );
                println!(
                    " Blocklist  : {}",
                    if blocked {
                        "HIT".red().to_string()
                    } else {
                        "miss".dimmed().to_string()
                    }
                );
                println!(
                    " ThreatGrid : {}",
                    match &ioc_hit {
                        Some(v) => format!("HIT ({v})").red().to_string(),
                        None => "miss".dimmed().to_string(),
                    }
                );
                println!(" Note       : check does not call DoH (use resolve)");
            }
            if denied.is_some() && !allowed {
                std::process::exit(3);
            }
        }
        Commands::Block { domain } => {
            let d = normalize_domain(&domain);
            if d.is_empty() {
                eprintln!("[cyberdns] empty domain");
                std::process::exit(2);
            }
            let mut set = load_blocklist(&cli.blocklist)?;
            if set.insert(d.clone()) {
                save_blocklist(&cli.blocklist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] blocked {d} ({} total)", set.len())
                        .red()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::Medium,
                    format!("domain added to blocklist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] already blocked: {d}");
            }
        }
        Commands::Unblock { domain } => {
            let d = normalize_domain(&domain);
            let mut set = load_blocklist(&cli.blocklist)?;
            if set.remove(&d) {
                save_blocklist(&cli.blocklist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] unblocked {d}").green().bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("domain removed from blocklist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] not in blocklist: {d}");
            }
        }
        Commands::Allow { domain } => {
            let d = normalize_domain(&domain);
            if d.is_empty() {
                eprintln!("[cyberdns] empty domain");
                std::process::exit(2);
            }
            let mut set = load_allowlist(&cli.allowlist)?;
            if set.insert(d.clone()) {
                save_allowlist(&cli.allowlist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] allowed {d} ({} total)", set.len())
                        .green()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("domain added to allowlist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] already allowed: {d}");
            }
        }
        Commands::Unallow { domain } => {
            let d = normalize_domain(&domain);
            let mut set = load_allowlist(&cli.allowlist)?;
            if set.remove(&d) {
                save_allowlist(&cli.allowlist, &set)?;
                println!(
                    "{}",
                    format!("[cyberdns] unallowed {d}").yellow().bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Observed,
                    Severity::Info,
                    format!("domain removed from allowlist: {d}"),
                    &d,
                );
            } else {
                println!("[cyberdns] not in allowlist: {d}");
            }
        }
        Commands::Resolve { domain, json } => {
            let d = normalize_domain(&domain);
            if let Some(reason) =
                domain_denied(&cli.blocklist, &cli.allowlist, &cli.ioc_store, &d)
            {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "domain": d,
                            "decision": "blocked",
                            "reason": reason,
                            "ips": [],
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!("[CYBERDNS] BLOCKED by {reason}: {d}")
                            .red()
                            .bold()
                    );
                }
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::High,
                    format!("resolve denied ({reason}): {d}"),
                    &d,
                );
                std::process::exit(3);
            }

            if !json {
                println!(
                    "{}",
                    format!(
                        "[CYBERDNS] Resolving '{d}' via DoH ({})...",
                        doh_eps.join(" → ")
                    )
                    .cyan()
                );
            }
            match doh::resolve_a_strings(&d, &doh_eps).await {
                Ok((ips, used)) if !ips.is_empty() => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "domain": d,
                                "decision": "allowed",
                                "reason": null,
                                "resolver": used,
                                "ips": ips,
                            }))?
                        );
                    } else {
                        println!(" DoH resolver  : {}", used.yellow());
                        for ip in &ips {
                            println!(" Resolved IP   : {}", ip.green().bold());
                        }
                    }
                    emit(
                        &cli.event_log,
                        EventAction::Allowed,
                        Severity::Info,
                        format!("resolve ok: {d} via {used}"),
                        &d,
                    );
                }
                Ok((_, used)) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "domain": d,
                                "decision": "nxdomain",
                                "reason": null,
                                "resolver": used,
                                "ips": [],
                            }))?
                        );
                    } else {
                        println!("{}", "NXDOMAIN / no A records.".yellow());
                        println!(" DoH resolver  : {used}");
                    }
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Low,
                        format!("resolve nxdomain: {d} via {used}"),
                        &d,
                    );
                }
                Err(e) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "domain": d,
                                "decision": "error",
                                "error": e.to_string(),
                                "ips": [],
                            }))?
                        );
                    } else {
                        eprintln!("{}", format!("DoH error: {e}").red());
                    }
                    std::process::exit(1);
                }
            }
        }
        Commands::Serve { listen, stats_secs } => {
            serve::run_proxy(
                &listen,
                &cli.blocklist,
                &cli.allowlist,
                &cli.ioc_store,
                &cli.event_log,
                stats_secs,
                doh_eps,
            )
            .await?;
        }
        Commands::SystemDns { command } => match command {
            SystemDnsCmd::Show => match system_dns::show_current() {
                Ok(s) => print!("{s}"),
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
            SystemDnsCmd::Backup { backup } => match system_dns::backup_current(&backup) {
                Ok(b) => {
                    println!(
                        "[cyberdns] backup wrote {} ({} server(s), {} iface(s))",
                        backup.display(),
                        b.servers.len(),
                        b.interfaces.len()
                    );
                }
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
            SystemDnsCmd::Set {
                server,
                interface,
                backup,
            } => {
                println!(
                    "{}",
                    "[cyberdns] system-dns set requires elevation on Windows (Admin) / root on Linux"
                        .yellow()
                );
                match system_dns::set_system_dns(&server, interface.as_deref(), &backup) {
                    Ok(msg) => {
                        println!("{}", format!("[cyberdns] {msg}").green().bold());
                        println!("Start proxy: cyberdns serve --listen 127.0.0.1:53  (or map 53→53553)");
                        println!("Note: many OS stacks need port 53; serve on 53553 + portproxy if needed.");
                        emit(
                            &cli.event_log,
                            EventAction::Observed,
                            Severity::High,
                            format!("system dns set server={server}"),
                            &server,
                        );
                    }
                    Err(e) => {
                        eprintln!("[cyberdns] {e}");
                        std::process::exit(1);
                    }
                }
            }
            SystemDnsCmd::Restore { backup } => match system_dns::restore_system_dns(&backup) {
                Ok(msg) => {
                    println!("{}", format!("[cyberdns] {msg}").green().bold());
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Medium,
                        "system dns restored from backup",
                        "restore",
                    );
                }
                Err(e) => {
                    eprintln!("[cyberdns] {e}");
                    std::process::exit(1);
                }
            },
        },
    }

    Ok(())
}
