//! S2O Gate — posture-gated HTTP reverse proxy (Phase 3 start / T0).

mod config;
mod proxy;
mod tls;

use clap::{Parser, Subcommand};
use colored::*;
use config::{default_config, load_config, save_config};
use s2o_kernel::{compute_posture_score, create_firewall_engine, host_id};
use s2o_schema::{AegisEvent, EventAction, EventKind, ProductId, Severity};
use s2o_store::EventStore;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cyberztna")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.2.0")]
#[command(about = "S2O Gate: posture-gated reverse proxy (ZTNA MVP)", long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = ".aegis/gate-routes.json")]
    config: PathBuf,

    #[arg(long, global = true, default_value = ".aegis/events.jsonl")]
    event_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    /// Write a starter route config
    Init,
    /// List configured routes
    Routes,
    /// Run posture-gated reverse proxy
    Serve {
        /// Override listen address
        #[arg(long)]
        listen: Option<String>,
        /// Override minimum posture score
        #[arg(long)]
        min_score: Option<u32>,
        /// Single-route mode: upstream base URL (ignores multi-route path match except /)
        #[arg(long)]
        upstream: Option<String>,
        /// Enable HTTPS with self-signed cert (or existing PEM paths)
        #[arg(long)]
        tls: bool,
        #[arg(long, default_value = ".aegis/gate-cert.pem")]
        tls_cert: PathBuf,
        #[arg(long, default_value = ".aegis/gate-key.pem")]
        tls_key: PathBuf,
    },
    /// Check posture only (same kernel score Gate uses)
    Check {
        #[arg(long, default_value_t = 50)]
        min_score: u32,
    },
    /// Connect shorthand: print how to reach an app route
    Connect { app: String },
    /// Show recent Gate events from the suite event log
    Audit {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

fn emit(event_log: &Path, action: EventAction, severity: Severity, message: impl Into<String>, attrs: &[(&str, serde_json::Value)]) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::Gate,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            let fw = create_firewall_engine();
            let posture = compute_posture_score(&fw).await?;
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                "{}",
                "     S2O Gate / ZeroTrust Gateway (MVP)                  "
                    .bold()
                    .green()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
            println!(
                " Implemented       : {}",
                "posture-gated HTTP/HTTPS reverse proxy + routes + self-signed TLS".green()
            );
            println!(
                " Not implemented   : {}",
                "mTLS client certs, IdP OIDC, multi-POP SASE".red()
            );
            println!(" Config            : {}", cli.config.display());
            println!(" Routes            : {}", cfg.routes.len());
            println!(" Default min_score : {}", cfg.min_score);
            println!(
                " Live posture      : {} / {}",
                posture.score, posture.max_score
            );
            println!(
                " Serve             : {}",
                "cyberztna serve  (or --upstream http://127.0.0.1:8080)".yellow()
            );
            println!(
                "{}",
                "=========================================================".cyan()
            );
        }
        Commands::Init => {
            let cfg = default_config();
            save_config(&cli.config, &cfg)?;
            println!(
                "{}",
                format!("[gate] wrote {}", cli.config.display())
                    .green()
                    .bold()
            );
            println!("Edit routes, then: cyberztna serve");
        }
        Commands::Routes => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            if cfg.routes.is_empty() {
                println!("[gate] no routes — run: cyberztna init");
            } else {
                println!("listen={} min_score={}", cfg.listen, cfg.min_score);
                for r in &cfg.routes {
                    println!(
                        "  {:<16} prefix={:<12} -> {}",
                        r.name, r.path_prefix, r.upstream
                    );
                }
            }
        }
        Commands::Check { min_score } => {
            let fw = create_firewall_engine();
            let posture = compute_posture_score(&fw).await?;
            let pass = posture.passes(min_score);
            println!("posture_score={} max={} min={} pass={}", posture.score, posture.max_score, min_score, pass);
            for c in &posture.checks {
                println!(
                    "  [{}] {} {}",
                    if c.pass { "PASS" } else { "FAIL" },
                    c.id,
                    c.detail
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
                format!("gate check score={} pass={}", posture.score, pass),
                &[
                    ("score", serde_json::json!(posture.score)),
                    ("min_score", serde_json::json!(min_score)),
                    ("pass", serde_json::json!(pass)),
                ],
            );
            if !pass {
                std::process::exit(3);
            }
        }
        Commands::Serve {
            listen,
            min_score,
            upstream,
            tls,
            tls_cert,
            tls_key,
        } => {
            let mut cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            if let Some(l) = listen {
                cfg.listen = l;
            }
            if let Some(m) = min_score {
                cfg.min_score = m;
            }
            if let Some(u) = upstream {
                cfg.routes = vec![config::GateRoute {
                    name: "default".into(),
                    path_prefix: "/".into(),
                    upstream: u,
                }];
            }
            if cfg.routes.is_empty() {
                eprintln!("[gate] no routes configured — run cyberztna init or pass --upstream");
                std::process::exit(2);
            }
            let scheme = if tls { "https" } else { "http" };
            println!(
                "[gate] starting on {}://{} min_score={} routes={} tls={}",
                scheme,
                cfg.listen,
                cfg.min_score,
                cfg.routes.len(),
                tls
            );
            for r in &cfg.routes {
                println!("  {} {} -> {}", r.name, r.path_prefix, r.upstream);
            }
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!("gate serve listen={} tls={}", cfg.listen, tls),
                &[
                    ("listen", serde_json::json!(cfg.listen)),
                    ("min_score", serde_json::json!(cfg.min_score)),
                    ("tls", serde_json::json!(tls)),
                ],
            );
            let tls_files = if tls {
                Some(proxy::TlsFiles {
                    cert: tls_cert,
                    key: tls_key,
                })
            } else {
                None
            };
            proxy::run(cfg, cli.event_log, tls_files).await?;
        }
        Commands::Connect { app } => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            if let Some(r) = cfg.routes.iter().find(|r| r.name == app) {
                println!("App route '{app}':");
                println!("  prefix   : {}", r.path_prefix);
                println!("  upstream : {}", r.upstream);
                println!("  access   : http://{}/  (via cyberztna serve)", cfg.listen);
                println!("  gate     : posture score >= {}", cfg.min_score);
            } else {
                eprintln!("[gate] unknown app '{app}'. Known:");
                for r in &cfg.routes {
                    eprintln!("  - {}", r.name);
                }
                std::process::exit(1);
            }
        }
        Commands::Audit { limit } => {
            if !cli.event_log.exists() {
                println!("[gate] no event log yet");
                return Ok(());
            }
            let store = EventStore::open(&cli.event_log)?;
            let events = store.recent(limit * 5)?;
            let mut n = 0;
            for e in events.into_iter().rev() {
                if e.product != ProductId::Gate {
                    continue;
                }
                println!(
                    "[{}] {:?} {} ",
                    e.ts.to_rfc3339(),
                    e.action,
                    e.message
                );
                n += 1;
                if n >= limit {
                    break;
                }
            }
            if n == 0 {
                println!("[gate] no Gate events in log");
            }
        }
    }

    Ok(())
}
