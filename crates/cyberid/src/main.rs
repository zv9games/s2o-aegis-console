//! S2O CyberID — endpoint posture scoring + local sessions (Phase 2/3).

use clap::{Parser, Subcommand};
use colored::*;
use s2o_kernel::create_firewall_engine;
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_session::SessionStore;
use s2o_store::EventStore;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "cyberid")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.3.0")]
#[command(about = "S2O CyberID: posture scoring + local session tokens", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/sessions.json")]
    sessions: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// Validate posture signals + session store health
    Doctor {
        #[arg(long, default_value_t = 40)]
        min_score: u32,
    },
    /// Device posture from live OS + suite signals
    Posture {
        #[arg(long, default_value_t = 50)]
        min_score: u32,
        #[arg(long)]
        json: bool,
    },
    /// Mint a local session token after posture gate passes
    Authenticate {
        user: String,
        #[arg(long, default_value_t = 50)]
        min_score: u32,
        #[arg(long, default_value_t = 8)]
        ttl_hours: i64,
    },
    /// List sessions (active by default)
    Sessions {
        /// Include revoked/expired
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        /// Filter by user (case-insensitive)
        #[arg(long)]
        user: Option<String>,
    },
    /// Export sessions to json/csv
    #[command(name = "sessions-export")]
    SessionsExport {
        /// Include revoked/expired
        #[arg(long)]
        all: bool,
        /// json | csv
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Remove expired/revoked sessions from the store
    Gc,
    /// Revoke a token/id, or all sessions for --user
    Revoke {
        /// Session token or id (optional if --user set)
        token: Option<String>,
        /// Revoke all sessions for this user
        #[arg(long)]
        user: Option<String>,
    },
    Verify { token: String },
}

#[derive(serde::Serialize)]
struct Check {
    id: &'static str,
    pass: bool,
    weight: u32,
    detail: String,
}

#[derive(serde::Serialize)]
struct PostureReport {
    score: u32,
    max_score: u32,
    pass: bool,
    min_score: u32,
    checks: Vec<Check>,
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
) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::CyberId,
            EventKind::Auth,
            action,
            severity,
            message,
        );
        for (k, v) in attrs {
            ev = ev.with_attr(*k, v.clone());
        }
        let _ = store.append(&ev);
    }
}

fn bitlocker_or_encryption_hint() -> (bool, String) {
    if cfg!(windows) {
        if let Ok(out) = Command::new("manage-bde").args(["-status", "C:"]).output() {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if text.contains("protection on") || text.contains("percentage encrypted: 100") {
                return (true, "BitLocker reports protection on (C:)".into());
            }
            if out.status.success() {
                return (false, "BitLocker present but not fully protected".into());
            }
        }
        return (
            false,
            "BitLocker status unavailable (need admin / manage-bde)".into(),
        );
    }
    if let Ok(out) = Command::new("lsblk")
        .args(["-o", "NAME,TYPE,FSTYPE"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        if text.contains("crypto_luks") || text.contains("crypt") {
            return (true, "lsblk shows crypt/LUKS volume".into());
        }
    }
    (false, "disk encryption not verified on this OS".into())
}

fn compute_score() -> Result<(u32, Vec<Check>), Box<dyn std::error::Error>> {
    // Async firewall status is filled in by caller for posture; this is for auth path.
    Ok((0, vec![]))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "        S2O CyberID (Phase 2/3)                          "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "posture + doctor + sessions (mint/list/revoke/verify/gc)".green()
            );
            println!(
                " Not implemented   : {}",
                "OIDC/FIDO2, enterprise PAM, federated IdP".red()
            );
            println!(
                " Sessions file     : {} ({})",
                cli.sessions.display(),
                if cli.sessions.exists() {
                    "present".green().to_string()
                } else {
                    "missing".yellow().to_string()
                }
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            let _ = compute_score();
        }
        Commands::Doctor { min_score } => {
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut check = |label: &str, good: bool, detail: &str, soft: bool| {
                if good {
                    ok += 1;
                    println!("  {} {} — {}", "OK".green().bold(), label, detail);
                } else if soft {
                    warn += 1;
                    println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                } else {
                    fail += 1;
                    println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                }
            };
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "      S2O CyberID doctor                                 "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );

            let fw = create_firewall_engine();
            let st = cyberwall_core::FirewallEngine::get_status(fw.as_ref()).await?;
            check(
                "firewall",
                st.enabled,
                &format!("enabled={} {}", st.enabled, st.backend_driver),
                false,
            );
            if cfg!(windows) {
                check(
                    "defender",
                    st.defender_active,
                    &format!("WinDefend active={}", st.defender_active),
                    false,
                );
            } else {
                check("defender", true, "N/A on non-Windows", false);
            }
            check(
                "ioc store",
                Path::new(".aegis/ioc-store.json").exists(),
                ".aegis/ioc-store.json",
                true, // soft: lab hosts may lack IOC yet
            );
            check(
                "dns blocklist",
                Path::new(".aegis/dns-blocklist.txt").exists(),
                ".aegis/dns-blocklist.txt",
                true,
            );
            let (enc_ok, enc_detail) = bitlocker_or_encryption_hint();
            check("disk encryption", enc_ok, &enc_detail, true);

            // recompute posture via same path as Posture (inline simplified)
            let mut score = 0u32;
            let mut max = 0u32;
            for (pass, w) in [
                (st.enabled, 30u32),
                (st.defender_active || !cfg!(windows), 25),
                (Path::new(".aegis/ioc-store.json").exists(), 15),
                (Path::new(".aegis/dns-blocklist.txt").exists(), 15),
                (enc_ok, 15),
            ] {
                max += w;
                if pass {
                    score += w;
                }
            }
            let pct = if max > 0 { (score * 100) / max } else { 0 };
            check(
                "posture floor",
                pct >= min_score,
                &format!("score={pct} min={min_score}"),
                false,
            );

            let store = SessionStore::load(&cli.sessions);
            let active: Vec<_> = store.active().collect();
            let expired = store.sessions.len().saturating_sub(active.len());
            check(
                "session store",
                true,
                &format!(
                    "{} total={} active={} expired/revoked={}",
                    cli.sessions.display(),
                    store.sessions.len(),
                    active.len(),
                    expired
                ),
                false,
            );
            // mint+verify round-trip in memory only if we can write
            let mut probe = SessionStore::default();
            let s = probe.mint("selftest", &host_id(), pct, 1);
            let verified = probe.verify(&s.token).is_some();
            check("session mint/verify", verified, "in-memory round-trip", false);

            println!(
                "{}",
                "---------------------------------------------------------".cyan()
            );
            println!(" Summary: ok={ok} warn={warn} fail={fail}");
            if fail > 0 {
                std::process::exit(2);
            }
        }
        Commands::Posture { min_score, json } => {
            let fw = create_firewall_engine();
            let st = cyberwall_core::FirewallEngine::get_status(fw.as_ref()).await?;

            let mut checks = Vec::new();
            checks.push(Check {
                id: "firewall_enabled",
                pass: st.enabled,
                weight: 30,
                detail: format!("enabled={} backend={}", st.enabled, st.backend_driver),
            });
            checks.push(Check {
                id: "defender_or_av",
                pass: st.defender_active || !cfg!(windows),
                weight: 25,
                detail: if cfg!(windows) {
                    format!("WinDefend active={}", st.defender_active)
                } else {
                    "non-Windows: AV check N/A (counted as pass)".into()
                },
            });
            let ioc_ok = Path::new(".aegis/ioc-store.json").exists();
            checks.push(Check {
                id: "threatgrid_ioc_store",
                pass: ioc_ok,
                weight: 15,
                detail: if ioc_ok {
                    "IOC store present".into()
                } else {
                    "missing .aegis/ioc-store.json (run cyberintel sync)".into()
                },
            });
            let bl_ok = Path::new(".aegis/dns-blocklist.txt").exists();
            checks.push(Check {
                id: "dns_blocklist",
                pass: bl_ok,
                weight: 15,
                detail: if bl_ok {
                    "DNS blocklist present".into()
                } else {
                    "missing .aegis/dns-blocklist.txt".into()
                },
            });
            let (enc_ok, enc_detail) = bitlocker_or_encryption_hint();
            checks.push(Check {
                id: "disk_encryption",
                pass: enc_ok,
                weight: 15,
                detail: enc_detail,
            });

            let score: u32 = checks.iter().map(|c| if c.pass { c.weight } else { 0 }).sum();
            let max_score: u32 = checks.iter().map(|c| c.weight).sum();
            let pass = score >= min_score;
            let report = PostureReport {
                score,
                max_score,
                pass,
                min_score,
                checks,
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      CyberID endpoint posture                            "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                for c in &report.checks {
                    let mark = if c.pass {
                        "PASS".green().bold()
                    } else {
                        "FAIL".red().bold()
                    };
                    println!(" [{:>2}] {:<22} {}  {}", c.weight, c.id, mark, c.detail);
                }
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(
                    " Score             : {} / {}  (min {})",
                    if pass {
                        score.to_string().green().bold().to_string()
                    } else {
                        score.to_string().red().bold().to_string()
                    },
                    max_score,
                    min_score
                );
                println!(
                    " Gate              : {}",
                    if pass {
                        "ALLOW".green().bold()
                    } else {
                        "DENY".red().bold()
                    }
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            emit(
                &cli.event_log,
                if pass {
                    EventAction::Allowed
                } else {
                    EventAction::Blocked
                },
                if pass {
                    Severity::Info
                } else {
                    Severity::High
                },
                format!("posture score={score}/{max_score} pass={pass}"),
                &[
                    ("score", serde_json::json!(score)),
                    ("max_score", serde_json::json!(max_score)),
                    ("min_score", serde_json::json!(min_score)),
                    ("pass", serde_json::json!(pass)),
                ],
            );

            if !pass {
                std::process::exit(3);
            }
        }
        Commands::Authenticate {
            user,
            min_score,
            ttl_hours,
        } => {
            let fw = create_firewall_engine();
            let st = cyberwall_core::FirewallEngine::get_status(fw.as_ref()).await?;
            let mut score = 0u32;
            if st.enabled {
                score += 30;
            }
            if st.defender_active || !cfg!(windows) {
                score += 25;
            }
            if Path::new(".aegis/ioc-store.json").exists() {
                score += 15;
            }
            if Path::new(".aegis/dns-blocklist.txt").exists() {
                score += 15;
            }
            let (enc_ok, _) = bitlocker_or_encryption_hint();
            if enc_ok {
                score += 15;
            }
            if score < min_score {
                eprintln!(
                    "[cyberid] authenticate DENY for '{user}': posture {score} < {min_score}"
                );
                emit(
                    &cli.event_log,
                    EventAction::Blocked,
                    Severity::High,
                    format!("auth deny user={user} score={score}"),
                    &[
                        ("user", serde_json::json!(user)),
                        ("score", serde_json::json!(score)),
                        ("min_score", serde_json::json!(min_score)),
                    ],
                );
                std::process::exit(3);
            }
            let mut store = SessionStore::load(&cli.sessions);
            let session = store.mint(&user, &host_id(), score, ttl_hours);
            store.save(&cli.sessions)?;
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "      CyberID session issued                             "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(" User     : {}", user.bold());
            println!(" Score    : {score}");
            println!(" Token    : {}", session.token.yellow().bold());
            println!(" Expires  : {}", session.expires_at);
            println!(" Store    : {}", cli.sessions.display());
            println!(" Header   : X-Aegis-Session: {}", session.token);
            println!(
                "{}",
                "=========================================================".cyan()
            );
            emit(
                &cli.event_log,
                EventAction::Allowed,
                Severity::Info,
                format!("auth ok user={user} session={}", session.id),
                &[
                    ("user", serde_json::json!(user)),
                    ("session_id", serde_json::json!(session.id)),
                    ("score", serde_json::json!(score)),
                ],
            );
        }
        Commands::Sessions { all, json, user } => {
            let store = SessionStore::load(&cli.sessions);
            let user_f = user.as_ref().map(|u| u.to_ascii_lowercase());
            let rows: Vec<_> = if all {
                store
                    .sessions
                    .iter()
                    .filter(|s| {
                        user_f
                            .as_ref()
                            .map(|u| s.user.to_ascii_lowercase() == *u)
                            .unwrap_or(true)
                    })
                    .collect()
            } else {
                store
                    .active()
                    .filter(|s| {
                        user_f
                            .as_ref()
                            .map(|u| s.user.to_ascii_lowercase() == *u)
                            .unwrap_or(true)
                    })
                    .collect()
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "path": cli.sessions.display().to_string(),
                        "all": all,
                        "user": user,
                        "count": rows.len(),
                        "sessions": rows,
                    }))?
                );
            } else if rows.is_empty() {
                println!(
                    "[cyberid] no {} sessions{}",
                    if all { "matching" } else { "active" },
                    user.as_ref()
                        .map(|u| format!(" for user={u}"))
                        .unwrap_or_default()
                );
            } else {
                for s in rows {
                    let state = if s.revoked {
                        "revoked"
                    } else if store.verify(&s.token).is_none() {
                        "expired"
                    } else {
                        "active"
                    };
                    println!(
                        "{}  user={} score={} exp={} last_used={} [{}]",
                        s.token,
                        s.user,
                        s.posture_score,
                        s.expires_at,
                        s.last_used.as_deref().unwrap_or("-"),
                        state
                    );
                }
            }
        }
        Commands::SessionsExport {
            all,
            format,
            user,
            out,
        } => {
            let store = SessionStore::load(&cli.sessions);
            let user_f = user.as_ref().map(|u| u.to_ascii_lowercase());
            let rows: Vec<_> = if all {
                store
                    .sessions
                    .iter()
                    .filter(|s| {
                        user_f
                            .as_ref()
                            .map(|u| s.user.to_ascii_lowercase() == *u)
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            } else {
                store
                    .active()
                    .filter(|s| {
                        user_f
                            .as_ref()
                            .map(|u| s.user.to_ascii_lowercase() == *u)
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            };
            let text = if format.eq_ignore_ascii_case("csv") {
                let mut s = String::from(
                    "id,user,host_id,posture_score,issued_at,expires_at,revoked,last_used,token_prefix\n",
                );
                for r in &rows {
                    let prefix = &r.token[..r.token.len().min(16)];
                    s.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        r.id,
                        r.user.replace(',', " "),
                        r.host_id.replace(',', " "),
                        r.posture_score,
                        r.issued_at,
                        r.expires_at,
                        r.revoked,
                        r.last_used.as_deref().unwrap_or(""),
                        prefix,
                    ));
                }
                s
            } else {
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": cli.sessions.display().to_string(),
                    "all": all,
                    "user": user,
                    "count": rows.len(),
                    "sessions": rows,
                }))?
            };
            if let Some(path) = out {
                if let Some(p) = path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::write(&path, &text)?;
                println!(
                    "{}",
                    format!(
                        "[cyberid] exported {} session(s) → {}",
                        rows.len(),
                        path.display()
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
        Commands::Gc => {
            let mut store = SessionStore::load(&cli.sessions);
            let n = store.gc();
            store.save(&cli.sessions)?;
            println!("[cyberid] gc removed {n} session(s); active={}", store.active().count());
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("session gc removed={n}"),
                &[("removed", serde_json::json!(n))],
            );
        }
        Commands::Revoke { token, user } => {
            let mut store = SessionStore::load(&cli.sessions);
            if let Some(ref u) = user {
                let n = store.revoke_user(u);
                if n == 0 {
                    eprintln!("[cyberid] no active sessions for user={u}");
                    std::process::exit(1);
                }
                store.save(&cli.sessions)?;
                println!(
                    "{}",
                    format!("[cyberid] revoked {n} session(s) for user={u}")
                        .yellow()
                        .bold()
                );
                emit(
                    &cli.event_log,
                    EventAction::Observed,
                    Severity::Info,
                    format!("session revoke user={u} n={n}"),
                    &[
                        ("user", serde_json::json!(u)),
                        ("revoked", serde_json::json!(n)),
                    ],
                );
            } else if let Some(ref tok) = token {
                if store.revoke_token(tok) {
                    store.save(&cli.sessions)?;
                    println!("{}", "[cyberid] session revoked".yellow().bold());
                    emit(
                        &cli.event_log,
                        EventAction::Observed,
                        Severity::Info,
                        "session revoked",
                        &[(
                            "token_prefix",
                            serde_json::json!(&tok[..tok.len().min(16)]),
                        )],
                    );
                } else {
                    eprintln!("[cyberid] token not found");
                    std::process::exit(1);
                }
            } else {
                eprintln!("[cyberid] provide TOKEN or --user");
                std::process::exit(2);
            }
        }
        Commands::Verify { token } => {
            let store = SessionStore::load(&cli.sessions);
            match store.verify(&token) {
                Some(s) => {
                    println!(
                        "OK user={} score={} exp={}",
                        s.user, s.posture_score, s.expires_at
                    );
                }
                None => {
                    eprintln!("INVALID");
                    std::process::exit(3);
                }
            }
        }
    }

    Ok(())
}
