//! S2O Gate — posture-gated HTTP reverse proxy (Phase 3 start / T0).

mod config;
mod jwt;
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
#[command(version = "0.4.0")]
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
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Write a starter route config
    Init,
    /// List configured routes
    Routes {
        #[arg(long)]
        json: bool,
    },
    /// Add or update a route in gate-routes.json
    RouteAdd {
        name: String,
        /// Path prefix (e.g. /app or /)
        #[arg(long, default_value = "/")]
        path_prefix: String,
        /// Upstream base URL
        #[arg(long)]
        upstream: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove a route by name
    RouteRemove {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Export access log lines (json/csv/text) with optional --since/--filter
    AccessExport {
        #[arg(long, default_value = ".aegis/gate-access.log")]
        log: PathBuf,
        /// json | csv | text
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        filter: Option<String>,
        /// Time lower bound: relative (`15m`, `1h`, `24h`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Generate lab mTLS CA + server + client certs
    Mtls {
        #[command(subcommand)]
        command: MtlsCmd,
    },
    /// Mint / verify local HS256 JWT (OIDC-lite; same secret as serve --jwt-secret)
    Jwt {
        #[command(subcommand)]
        command: JwtCmd,
    },
    /// OAuth 2.0 lab client (device-code + authorization-code against aegisd)
    Oauth {
        #[command(subcommand)]
        command: OauthCmd,
    },
    /// Validate routes config, certs, access log, posture (read-only)
    Doctor {
        #[arg(long, default_value = ".aegis/gate-access.log")]
        access_log: PathBuf,
        #[arg(long, default_value = ".aegis/sessions.json")]
        sessions: PathBuf,
        #[arg(long, default_value = ".aegis/gate-cert.pem")]
        tls_cert: PathBuf,
        #[arg(long, default_value = ".aegis/gate-key.pem")]
        tls_key: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Summarize Gate access log (ALLOW/DENY counts)
    AccessStats {
        #[arg(long, default_value = ".aegis/gate-access.log")]
        log: PathBuf,
        /// Only count lines containing this substring (optional)
        #[arg(long)]
        filter: Option<String>,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
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
        /// Require client certs signed by this CA PEM (implies --tls)
        #[arg(long)]
        mtls_ca: Option<PathBuf>,
        /// Append access lines to this file
        #[arg(long, default_value = ".aegis/gate-access.log")]
        access_log: PathBuf,
        /// Disable access log file
        #[arg(long)]
        no_access_log: bool,
        /// Require CyberID session (X-Aegis-Session or Authorization: Bearer)
        #[arg(long)]
        require_session: bool,
        #[arg(long, default_value = ".aegis/sessions.json")]
        sessions: PathBuf,
        /// HS256 secret for local JWT Bearer tokens (OIDC-lite)
        #[arg(long, env = "S2O_GATE_JWT_SECRET")]
        jwt_secret: Option<String>,
        /// RS256 JWKS JSON or public PEM path (OIDC-lite JWKS)
        #[arg(long, env = "S2O_GATE_JWT_JWKS")]
        jwt_jwks: Option<PathBuf>,
        /// Fetch JWKS from HTTP(S) URL at serve start (OIDC-lite remote JWKS)
        #[arg(long, env = "S2O_GATE_JWT_JWKS_URL")]
        jwt_jwks_url: Option<String>,
        /// Optional cache file when using --jwt-jwks-url
        #[arg(long, default_value = ".aegis/jwt/jwks-remote-cache.json")]
        jwt_jwks_cache: PathBuf,
        /// OIDC issuer URL — fetch /.well-known/openid-configuration + jwks_uri
        #[arg(long, env = "S2O_GATE_OIDC_ISSUER")]
        oidc_issuer: Option<String>,
        /// Require token iss claim equals discovered issuer (default true with --oidc-issuer)
        #[arg(long, default_value_t = true)]
        oidc_validate_iss: bool,
        /// Skip iss claim check even when using --oidc-issuer
        #[arg(long)]
        no_oidc_validate_iss: bool,
        /// Allow only these client IPs / CIDRs (repeatable). Empty = all.
        #[arg(long = "allow-ip")]
        allow_ips: Vec<String>,
        /// Max requests per client IP per minute (0 = off)
        #[arg(long, default_value_t = 0)]
        rate_limit: u32,
        /// Reject sessions/JWTs whose mint-time posture is below min_score
        #[arg(long)]
        enforce_session_posture: bool,
    },
    /// Check posture only (same kernel score Gate uses)
    Check {
        #[arg(long, default_value_t = 50)]
        min_score: u32,
        #[arg(long)]
        json: bool,
    },
    /// Connect shorthand: print how to reach an app route
    Connect {
        app: String,
        #[arg(long)]
        json: bool,
    },
    /// Show recent Gate events from the suite event log
    Audit {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MtlsCmd {
    /// Write CA + server + client PEMs for lab mTLS
    Init {
        #[arg(long, default_value = ".aegis/mtls")]
        dir: PathBuf,
        #[arg(long, default_value = "gate-client")]
        client_cn: String,
        #[arg(long)]
        force: bool,
    },
    /// Show whether lab PKI files exist
    Status {
        #[arg(long, default_value = ".aegis/mtls")]
        dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// HTTPS request with lab client cert (mTLS smoke; rustls, not Windows schannel)
    Probe {
        #[arg(long, default_value = "https://127.0.0.1:18443/")]
        url: String,
        #[arg(long, default_value = ".aegis/mtls")]
        dir: PathBuf,
        /// Also try without client cert (expect TLS failure when mTLS required)
        #[arg(long)]
        also_plain: bool,
    },
}

#[derive(Subcommand)]
enum JwtCmd {
    /// Mint a local HS256 JWT
    Mint {
        user: String,
        #[arg(long, env = "S2O_GATE_JWT_SECRET")]
        secret: Option<String>,
        /// Use RS256 private key PEM (lab: .aegis/jwt/jwt-private.pem)
        #[arg(long)]
        rsa_key: Option<PathBuf>,
        #[arg(long)]
        kid: Option<String>,
        #[arg(long, default_value_t = 8)]
        ttl_hours: i64,
        #[arg(long)]
        posture: Option<u32>,
        #[arg(long, default_value = "s2o-cyberid")]
        issuer: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a JWT against secret or JWKS/public PEM
    Verify {
        token: String,
        #[arg(long, env = "S2O_GATE_JWT_SECRET")]
        secret: Option<String>,
        #[arg(long, env = "S2O_GATE_JWT_JWKS")]
        jwks: Option<PathBuf>,
        /// Expected iss claim
        #[arg(long)]
        iss: Option<String>,
        /// Discover OIDC issuer and verify with its JWKS
        #[arg(long)]
        oidc_issuer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Generate lab RS256 keypair + JWKS under a directory
    Keygen {
        #[arg(long, default_value = ".aegis/jwt")]
        dir: PathBuf,
        #[arg(long, default_value = "")]
        kid: String,
        #[arg(long)]
        force: bool,
    },
    /// Download remote JWKS (or PEM) to a file
    FetchJwks {
        #[arg(long)]
        url: String,
        #[arg(long, default_value = ".aegis/jwt/jwks-remote-cache.json")]
        out: PathBuf,
    },
    /// Discover OIDC provider via /.well-known/openid-configuration
    OidcDiscover {
        /// Issuer base URL (e.g. http://127.0.0.1:9090)
        issuer: String,
        /// Also fetch and cache JWKS
        #[arg(long)]
        fetch_jwks: bool,
        #[arg(long, default_value = ".aegis/jwt/jwks-remote-cache.json")]
        jwks_out: PathBuf,
    },
}

#[derive(Subcommand)]
enum OauthCmd {
    /// Start device authorization and poll until approved (prints access_token)
    Device {
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        issuer: String,
        #[arg(long, default_value = "s2o-gate")]
        client_id: String,
        /// Max seconds to poll
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
    /// Approve a user_code on the issuer (lab operator step)
    Approve {
        user_code: String,
        #[arg(long, default_value = "operator")]
        user: String,
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        issuer: String,
    },
    /// Authorization-code grant (lab): auto-approve + token exchange
    Code {
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        issuer: String,
        #[arg(long, default_value = "s2o-gate")]
        client_id: String,
        #[arg(long, default_value = "operator")]
        user: String,
        /// OOB by default (prints code + exchanges without browser redirect)
        #[arg(long, default_value = "urn:ietf:wg:oauth:2.0:oob")]
        redirect_uri: String,
        #[arg(long, default_value = "lab")]
        state: String,
        /// Only print authorize URL (no auto-approve)
        #[arg(long)]
        url_only: bool,
        /// Exchange an existing authorization code
        #[arg(long)]
        code: Option<String>,
    },
}

/// Minimal form url-encode for OAuth query/body params.
fn urlencoding_form(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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

/// Parse relative duration (`15m`, `1h`, `24h`, `7d`) or RFC3339 into a UTC lower bound.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --since value".into());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return Err(format!(
            "invalid --since '{s}' (use 15m, 1h, 24h, 7d, or RFC3339)"
        ));
    }
    let unit = *bytes.last().unwrap() as char;
    let num_str = &s[..s.len() - 1];
    let n: i64 = num_str.parse().map_err(|_| {
        format!("invalid --since '{s}' (use 15m, 1h, 24h, 7d, or RFC3339)")
    })?;
    if n <= 0 {
        return Err("--since duration must be positive".into());
    }
    let now = chrono::Utc::now();
    match unit {
        's' | 'S' => Ok(now - chrono::Duration::seconds(n)),
        'm' | 'M' => Ok(now - chrono::Duration::minutes(n)),
        'h' | 'H' => Ok(now - chrono::Duration::hours(n)),
        'd' | 'D' => Ok(now - chrono::Duration::days(n)),
        'w' | 'W' => Ok(now - chrono::Duration::weeks(n)),
        _ => Err(format!(
            "invalid --since unit in '{s}' (use s/m/h/d/w or RFC3339)"
        )),
    }
}

fn access_line_ts(line: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let tok = line.split_whitespace().next()?;
    chrono::DateTime::parse_from_rfc3339(tok)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Best-effort parse of gate access log line into structured fields.
fn parse_access_line(line: &str) -> serde_json::Value {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let ts = tokens.first().copied().unwrap_or("");
    let decision = tokens
        .iter()
        .find(|t| **t == "ALLOW" || **t == "DENY")
        .copied()
        .unwrap_or("");
    let mut reason = None;
    let mut status = None;
    let mut route = None;
    let mut user = None;
    let mut ip = None;
    let mut path = None;
    let mut method = None;
    if let Some(idx) = line.find("reason=") {
        reason = line[idx + 7..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string());
    }
    if let Some(idx) = line.find("status=") {
        status = line[idx + 7..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string());
    }
    if let Some(idx) = line.find("route=") {
        route = line[idx + 6..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string());
    }
    if let Some(idx) = line.find("user=") {
        user = line[idx + 5..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string());
    }
    if let Some(idx) = line.find("ip=") {
        ip = line[idx + 3..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string());
    }
    if let Some(pos) = tokens.iter().position(|t| *t == "ALLOW" || *t == "DENY") {
        if tokens[pos] == "ALLOW" {
            method = tokens.get(pos + 1).map(|s| (*s).to_string());
            path = tokens.get(pos + 2).map(|s| (*s).to_string());
        } else {
            path = tokens.get(pos + 1).map(|s| (*s).to_string());
        }
    }
    serde_json::json!({
        "raw": line,
        "ts": ts,
        "decision": decision,
        "method": method,
        "path": path,
        "reason": reason,
        "status": status,
        "route": route,
        "user": user,
        "ip": ip,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { json } => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            let fw = create_firewall_engine();
            let posture = compute_posture_score(&fw).await?;
            if json {
                let routes: Vec<_> = cfg
                    .routes
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": r.name,
                            "path_prefix": r.path_prefix,
                            "upstream": r.upstream,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "product": "cyberztna",
                        "config": cli.config.display().to_string(),
                        "config_present": cli.config.exists(),
                        "route_count": cfg.routes.len(),
                        "routes": routes,
                        "min_score": cfg.min_score,
                        "posture_score": posture.score,
                        "posture_max": posture.max_score,
                        "posture_pass": posture.score >= cfg.min_score,
                        "implemented": "posture+session+JWT/OIDC, TLS/mTLS, allowlist, rate-limit, doctor, access-stats",
                        "not_implemented": "production browser IdP UI, multi-POP SASE",
                    }))?
                );
            } else {
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
                    "posture+session+JWT/OIDC, TLS/mTLS, allowlist, rate-limit, doctor, access-stats"
                        .green()
                );
                println!(
                    " Not implemented   : {}",
                    "production browser IdP UI, multi-POP SASE".red()
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
        }
        Commands::Doctor {
            access_log,
            sessions,
            tls_cert,
            tls_key,
            json,
        } => {
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
                    "      S2O Gate doctor                                    "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            let cfg = match load_config(&cli.config) {
                Ok(c) => {
                    check(
                        "config file",
                        true,
                        false,
                        &format!("{}", cli.config.display()),
                    );
                    c
                }
                Err(e) => {
                    check(
                        "config file",
                        false,
                        true,
                        &format!(
                            "{} — {} (defaults used; run: cyberztna init)",
                            cli.config.display(),
                            e
                        ),
                    );
                    default_config()
                }
            };

            check(
                "listen",
                !cfg.listen.trim().is_empty() && cfg.listen.contains(':'),
                false,
                &cfg.listen,
            );
            check(
                "min_score",
                cfg.min_score > 0 && cfg.min_score <= 100,
                true,
                &format!("{}", cfg.min_score),
            );
            check(
                "routes",
                !cfg.routes.is_empty(),
                false,
                &if cfg.routes.is_empty() {
                    "no routes configured".into()
                } else {
                    format!(
                        "{} route(s): {}",
                        cfg.routes.len(),
                        cfg.routes
                            .iter()
                            .map(|r| format!("{}→{}", r.path_prefix, r.upstream))
                            .take(5)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            );
            for r in &cfg.routes {
                if r.upstream.trim().is_empty() {
                    check(
                        &format!("route {}", r.name),
                        false,
                        false,
                        "empty upstream",
                    );
                } else if !(r.upstream.starts_with("http://") || r.upstream.starts_with("https://"))
                {
                    check(
                        &format!("route {}", r.name),
                        false,
                        true,
                        &format!("upstream not http(s): {}", r.upstream),
                    );
                }
                if r.path_prefix.is_empty() || !r.path_prefix.starts_with('/') {
                    check(
                        &format!("route {} path", r.name),
                        false,
                        true,
                        &format!("path_prefix should start with / (got {:?})", r.path_prefix),
                    );
                }
            }

            if !cfg.allow_ips.is_empty() {
                check(
                    "ip allowlist",
                    true,
                    false,
                    &format!("{} entr(y/ies)", cfg.allow_ips.len()),
                );
            } else {
                check(
                    "ip allowlist",
                    false,
                    true,
                    "empty (all client IPs allowed)",
                );
            }
            check(
                "rate limit",
                true,
                false,
                &if cfg.rate_limit_per_minute == 0 {
                    "disabled".into()
                } else {
                    format!("{} req/min per IP", cfg.rate_limit_per_minute)
                },
            );
            check(
                "session flags",
                true,
                false,
                &format!(
                    "require_session={} enforce_session_posture={}",
                    cfg.require_session, cfg.enforce_session_posture
                ),
            );

            let access_lines = if access_log.exists() {
                std::fs::read_to_string(&access_log)
                    .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                    .unwrap_or(0)
            } else {
                0
            };
            check(
                "access log",
                access_log.exists(),
                true,
                &if access_log.exists() {
                    format!("{} ({} lines)", access_log.display(), access_lines)
                } else {
                    format!("{} missing (created on serve)", access_log.display())
                },
            );

            let cert_ok = tls_cert.exists() && tls_key.exists();
            check(
                "tls pem pair",
                cert_ok,
                true,
                &if cert_ok {
                    format!(
                        "{} + {} present (use --tls on serve)",
                        tls_cert.display(),
                        tls_key.display()
                    )
                } else {
                    "missing (HTTP-only unless --tls; run serve --tls once to mint lab certs)"
                        .into()
                },
            );

            let sess = s2o_session::SessionStore::load(&sessions);
            let active = sess.active().count();
            check(
                "sessions store",
                sessions.exists(),
                true,
                &if sessions.exists() {
                    format!(
                        "{} ({} total, {} active)",
                        sessions.display(),
                        sess.sessions.len(),
                        active
                    )
                } else {
                    format!("{} missing (mint via cyberid authenticate)", sessions.display())
                },
            );

            check(
                "event log",
                cli.event_log.exists(),
                true,
                &format!("{}", cli.event_log.display()),
            );

            let fw = create_firewall_engine();
            let posture = compute_posture_score(&fw).await?;
            let passes = posture.passes(cfg.min_score);
            check(
                "host posture vs min_score",
                passes,
                true,
                &format!(
                    "score={}/{} min={} {}",
                    posture.score,
                    posture.max_score,
                    cfg.min_score,
                    if passes { "PASS" } else { "BELOW (gate would deny)" }
                ),
            );

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "listen": cfg.listen,
                        "min_score": cfg.min_score,
                        "routes": cfg.routes.len(),
                        "access_log_lines": access_lines,
                        "sessions_active": active,
                        "posture_score": posture.score,
                        "posture_pass": passes,
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
                    " {}",
                    "Note: doctor does not start the proxy (use cyberztna serve)."
                        .dimmed()
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
        Commands::AccessStats {
            log,
            filter,
            since,
            json,
        } => {
            use std::collections::BTreeMap;
            use std::fs;
            use std::io::{BufRead, BufReader};

            if !log.exists() {
                eprintln!("[gate] access log missing: {}", log.display());
                std::process::exit(2);
            }
            let since_bound = match since.as_ref() {
                Some(s) => match parse_since(s) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        eprintln!("[gate] {e}");
                        std::process::exit(2);
                    }
                },
                None => None,
            };
            let f = fs::File::open(&log)?;
            let mut total = 0u64;
            let mut allow = 0u64;
            let mut deny = 0u64;
            let mut skipped_ts = 0u64;
            let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
            let mut by_status: BTreeMap<String, u64> = BTreeMap::new();
            let mut by_path: BTreeMap<String, u64> = BTreeMap::new();
            for line in BufReader::new(f).lines().flatten() {
                if let Some(ref filt) = filter {
                    if !line.contains(filt.as_str()) {
                        continue;
                    }
                }
                if let Some(bound) = since_bound {
                    match access_line_ts(&line) {
                        Some(ts) if ts >= bound => {}
                        Some(_) => {
                            skipped_ts += 1;
                            continue;
                        }
                        None => {
                            skipped_ts += 1;
                            continue;
                        }
                    }
                }
                total += 1;
                if line.contains(" ALLOW ") {
                    allow += 1;
                } else if line.contains(" DENY ") {
                    deny += 1;
                }
                // reason=...
                if let Some(idx) = line.find("reason=") {
                    let rest = &line[idx + 7..];
                    let reason = rest
                        .split_whitespace()
                        .next()
                        .unwrap_or("unknown")
                        .to_string();
                    *by_reason.entry(reason).or_default() += 1;
                }
                // status=NNN on ALLOW lines
                if let Some(idx) = line.find("status=") {
                    let rest = &line[idx + 7..];
                    let st = rest
                        .split_whitespace()
                        .next()
                        .unwrap_or("?")
                        .to_string();
                    *by_status.entry(st).or_default() += 1;
                }
                // path is usually the 4th/5th token after ALLOW/DENY METHOD path
                // Format: ts ALLOW METHOD path ...  or ts DENY path reason=...
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = tokens.iter().position(|t| *t == "ALLOW" || *t == "DENY") {
                    let path_tok = if tokens[pos] == "ALLOW" {
                        tokens.get(pos + 2)
                    } else {
                        tokens.get(pos + 1)
                    };
                    if let Some(p) = path_tok {
                        if p.starts_with('/') {
                            *by_path.entry((*p).to_string()).or_default() += 1;
                        }
                    }
                }
            }
            if json {
                let out = serde_json::json!({
                    "log": log.display().to_string(),
                    "since": since,
                    "total": total,
                    "allow": allow,
                    "deny": deny,
                    "skipped_outside_since": skipped_ts,
                    "by_reason": by_reason,
                    "by_status": by_status,
                    "by_path": by_path,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      Gate access stats                                "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Log    : {}", log.display());
                if let Some(ref s) = since {
                    println!(" Since  : {s}");
                }
                println!(" Total  : {total}");
                println!(" Allow  : {}", allow.to_string().green());
                println!(" Deny   : {}", deny.to_string().red());
                if !by_reason.is_empty() {
                    println!("-- deny reasons --");
                    for (k, v) in &by_reason {
                        println!("  {k:<16} {v}");
                    }
                }
                if !by_status.is_empty() {
                    println!("-- upstream status (allow) --");
                    for (k, v) in &by_status {
                        println!("  {k:<8} {v}");
                    }
                }
                if !by_path.is_empty() {
                    println!("-- top paths --");
                    let mut paths: Vec<_> = by_path.into_iter().collect();
                    paths.sort_by(|a, b| b.1.cmp(&a.1));
                    for (k, v) in paths.into_iter().take(15) {
                        println!("  {v:<6} {k}");
                    }
                }
            }
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
        Commands::Routes { json } => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "config": cli.config.display().to_string(),
                        "listen": cfg.listen,
                        "min_score": cfg.min_score,
                        "require_session": cfg.require_session,
                        "rate_limit_per_minute": cfg.rate_limit_per_minute,
                        "allow_ips": cfg.allow_ips,
                        "routes": cfg.routes,
                    }))?
                );
            } else if cfg.routes.is_empty() {
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
        Commands::RouteAdd {
            name,
            path_prefix,
            upstream,
            json,
        } => {
            use config::GateRoute;
            let mut cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            let prefix = if path_prefix.trim().is_empty() {
                "/".into()
            } else if path_prefix.starts_with('/') {
                path_prefix
            } else {
                format!("/{path_prefix}")
            };
            let up = upstream.trim().to_string();
            if up.is_empty()
                || !(up.starts_with("http://") || up.starts_with("https://"))
            {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": "--upstream must be http(s)://…",
                        }))?
                    );
                } else {
                    eprintln!("[gate] --upstream must be http(s)://…");
                }
                std::process::exit(2);
            }
            let updated = if let Some(r) = cfg.routes.iter_mut().find(|r| r.name == name) {
                r.path_prefix = prefix.clone();
                r.upstream = up.clone();
                true
            } else {
                cfg.routes.push(GateRoute {
                    name: name.clone(),
                    path_prefix: prefix.clone(),
                    upstream: up.clone(),
                });
                false
            };
            save_config(&cli.config, &cfg)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "updated": updated,
                        "added": !updated,
                        "name": name,
                        "path_prefix": prefix,
                        "upstream": up,
                        "route_count": cfg.routes.len(),
                        "config": cli.config.display().to_string(),
                    }))?
                );
            } else if updated {
                println!(
                    "{}",
                    format!(
                        "[gate] updated route '{name}' prefix={prefix} → {up}"
                    )
                    .green()
                    .bold()
                );
                println!("  wrote {}", cli.config.display());
            } else {
                println!(
                    "{}",
                    format!("[gate] added route '{name}' prefix={prefix} → {up}")
                        .green()
                        .bold()
                );
                println!("  wrote {}", cli.config.display());
            }
        }
        Commands::RouteRemove { name, json } => {
            let mut cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            let before = cfg.routes.len();
            cfg.routes.retain(|r| r.name != name);
            if cfg.routes.len() == before {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": "route not found",
                            "name": name,
                        }))?
                    );
                } else {
                    eprintln!("[gate] route not found: {name}");
                }
                std::process::exit(1);
            }
            save_config(&cli.config, &cfg)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "removed": name,
                        "route_count": cfg.routes.len(),
                        "config": cli.config.display().to_string(),
                    }))?
                );
            } else {
                println!(
                    "{}",
                    format!(
                        "[gate] removed route '{name}' ({} left) → {}",
                        cfg.routes.len(),
                        cli.config.display()
                    )
                    .yellow()
                );
            }
        }
        Commands::AccessExport {
            log,
            format,
            filter,
            since,
            limit,
            out,
        } => {
            use std::fs;
            use std::io::{BufRead, BufReader};
            if !log.exists() {
                eprintln!("[gate] access log missing: {}", log.display());
                std::process::exit(2);
            }
            let since_bound = match since.as_ref() {
                Some(s) => match parse_since(s) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        eprintln!("[gate] {e}");
                        std::process::exit(2);
                    }
                },
                None => None,
            };
            let f = fs::File::open(&log)?;
            let mut rows: Vec<serde_json::Value> = Vec::new();
            let mut raw_lines: Vec<String> = Vec::new();
            for line in BufReader::new(f).lines().flatten() {
                if let Some(ref filt) = filter {
                    if !line.contains(filt.as_str()) {
                        continue;
                    }
                }
                if let Some(bound) = since_bound {
                    match access_line_ts(&line) {
                        Some(ts) if ts >= bound => {}
                        _ => continue,
                    }
                }
                raw_lines.push(line.clone());
                rows.push(parse_access_line(&line));
            }
            // keep last `limit` matches (newest at end of file)
            if rows.len() > limit {
                let skip = rows.len() - limit;
                rows = rows.split_off(skip);
                raw_lines = raw_lines.split_off(skip);
            }
            let text = if format.eq_ignore_ascii_case("csv") {
                let mut s = String::from(
                    "ts,decision,method,path,reason,status,route,user,ip\n",
                );
                for r in &rows {
                    s.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        r.get("ts").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("decision").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("method").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("route").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("user").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                    ));
                }
                s
            } else if format.eq_ignore_ascii_case("text") {
                raw_lines.join("\n") + if raw_lines.is_empty() { "" } else { "\n" }
            } else {
                serde_json::to_string_pretty(&serde_json::json!({
                    "log": log.display().to_string(),
                    "since": since,
                    "filter": filter,
                    "count": rows.len(),
                    "lines": rows,
                }))?
            };
            if let Some(path) = out {
                if let Some(p) = path.parent() {
                    fs::create_dir_all(p)?;
                }
                fs::write(&path, &text)?;
                println!(
                    "{}",
                    format!(
                        "[gate] exported {} access line(s) → {}",
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
        Commands::Check { min_score, json } => {
            let fw = create_firewall_engine();
            let posture = compute_posture_score(&fw).await?;
            let pass = posture.passes(min_score);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "score": posture.score,
                        "max_score": posture.max_score,
                        "min_score": min_score,
                        "pass": pass,
                        "checks": posture.checks,
                    }))?
                );
            } else {
                println!(
                    "posture_score={} max={} min={} pass={}",
                    posture.score, posture.max_score, min_score, pass
                );
                for c in &posture.checks {
                    println!(
                        "  [{}] {} {}",
                        if c.pass { "PASS" } else { "FAIL" },
                        c.id,
                        c.detail
                    );
                }
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
        Commands::Mtls { command } => match command {
            MtlsCmd::Init {
                dir,
                client_cn,
                force,
            } => {
                tls::generate_mtls_pki(&dir, &client_cn, force)?;
            }
            MtlsCmd::Status { dir, json } => {
                let p = tls::MtlsPaths::in_dir(&dir);
                let files = [
                    ("ca", p.ca_cert.clone()),
                    ("server", p.server_cert.clone()),
                    ("server_key", p.server_key.clone()),
                    ("client", p.client_cert.clone()),
                    ("client_key", p.client_key.clone()),
                ];
                let rows: Vec<_> = files
                    .iter()
                    .map(|(label, path)| {
                        serde_json::json!({
                            "label": label,
                            "path": path.display().to_string(),
                            "present": path.exists(),
                        })
                    })
                    .collect();
                let ready = rows.iter().all(|r| r.get("present").and_then(|v| v.as_bool()).unwrap_or(false));
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "dir": dir.display().to_string(),
                            "ready": ready,
                            "files": rows,
                        }))?
                    );
                } else {
                    println!("[gate] mTLS dir {}", dir.display());
                    for (label, path) in &files {
                        println!(
                            "  {label:<10} {} {}",
                            if path.exists() {
                                "OK".green()
                            } else {
                                "missing".red()
                            },
                            path.display()
                        );
                    }
                }
            }
            MtlsCmd::Probe {
                url,
                dir,
                also_plain,
            } => {
                let p = tls::MtlsPaths::in_dir(&dir);
                if !p.client_cert.exists() || !p.client_key.exists() {
                    eprintln!("[gate] missing client certs — run: cyberztna mtls init --dir {}", dir.display());
                    std::process::exit(2);
                }
                let mut pem = std::fs::read(&p.client_cert)?;
                pem.extend(std::fs::read(&p.client_key)?);
                let identity = reqwest::Identity::from_pem(&pem)?;
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .identity(identity)
                    .danger_accept_invalid_certs(true)
                    .build()?;
                match client.get(&url).send().await {
                    Ok(res) => {
                        println!(
                            "[gate] mTLS probe OK status={} url={url}",
                            res.status()
                        );
                    }
                    Err(e) => {
                        eprintln!("[gate] mTLS probe FAIL: {e}");
                        std::process::exit(3);
                    }
                }
                if also_plain {
                    let plain = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .danger_accept_invalid_certs(true)
                        .build()?;
                    match plain.get(&url).send().await {
                        Ok(res) => {
                            println!(
                                "[gate] plain TLS (no client cert) status={} (unexpected if mTLS required)",
                                res.status()
                            );
                        }
                        Err(e) => {
                            println!(
                                "[gate] plain TLS without client cert failed as expected: {e}"
                            );
                        }
                    }
                }
            }
        },
        Commands::Jwt { command } => match command {
            JwtCmd::Keygen { dir, kid, force } => {
                jwt::write_rs256_lab(&dir, &kid, force)?;
            }
            JwtCmd::FetchJwks { url, out } => {
                let v = jwt::fetch_jwks_url(&url, Some(&out)).await?;
                let n = match &v {
                    jwt::JwtVerifier::Rs256JwkSet { keys } => keys.len(),
                    _ => 1,
                };
                println!(
                    "[gate] fetched JWKS from {url} -> {} (keys~{n})",
                    out.display()
                );
            }
            JwtCmd::OidcDiscover {
                issuer,
                fetch_jwks,
                jwks_out,
            } => {
                let disc = jwt::discover_oidc(&issuer).await?;
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      OIDC discovery                                   "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Issuer     : {}", disc.issuer);
                println!(" JWKS URI   : {}", disc.jwks_uri);
                if let Some(ref a) = disc.authorization_endpoint {
                    println!(" Authorize  : {a}");
                }
                if let Some(ref t) = disc.token_endpoint {
                    println!(" Token      : {t}");
                }
                if let Some(ref algs) = disc.id_token_signing_alg_values_supported {
                    println!(" ID algs    : {}", algs.join(", "));
                }
                if fetch_jwks {
                    let v = jwt::fetch_jwks_url(&disc.jwks_uri, Some(&jwks_out)).await?;
                    let n = match &v {
                        jwt::JwtVerifier::Rs256JwkSet { keys } => keys.len(),
                        _ => 1,
                    };
                    println!(
                        "[gate] JWKS cached -> {} (keys~{n})",
                        jwks_out.display()
                    );
                }
                println!(
                    " Serve hint : cyberztna serve --oidc-issuer {} ...",
                    disc.issuer
                );
            }
            JwtCmd::Mint {
                user,
                secret,
                rsa_key,
                kid,
                ttl_hours,
                posture,
                issuer,
                json,
            } => {
                let (token, alg) = if let Some(key_path) = rsa_key {
                    let pem = std::fs::read_to_string(&key_path)?;
                    // Prefer explicit --kid, else sibling jwks.json kid, else omit kid
                    let kid = kid.or_else(|| {
                        key_path.parent().and_then(|dir| {
                            let jwks_path = dir.join("jwks.json");
                            std::fs::read_to_string(jwks_path)
                                .ok()
                                .and_then(|t| serde_json::from_str::<jwt::JwksDoc>(&t).ok())
                                .and_then(|j| j.keys.first().cloned())
                                .and_then(|k| {
                                    k.get("kid")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string())
                                })
                        })
                    });
                    (
                        jwt::mint_rs256(&pem, kid.as_deref(), &user, ttl_hours, posture, &issuer)?,
                        "RS256",
                    )
                } else if let Some(secret) = secret {
                    (
                        jwt::mint(&secret, &user, ttl_hours, posture, &issuer)?,
                        "HS256",
                    )
                } else {
                    eprintln!("[gate] jwt mint needs --secret or --rsa-key");
                    std::process::exit(2);
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "user": user,
                            "issuer": issuer,
                            "alg": alg,
                            "ttl_hours": ttl_hours,
                            "posture": posture,
                            "token": token,
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        "=========================================================".cyan()
                    );
                    println!(
                        "{}",
                        format!("      Gate JWT minted ({alg} / OIDC-lite)")
                            .bold()
                            .green()
                    );
                    println!(
                        "{}",
                        "=========================================================".cyan()
                    );
                    println!(" User    : {}", user.bold());
                    if let Some(p) = posture {
                        println!(" Posture : {p}");
                    }
                    println!(" Issuer  : {issuer}");
                    println!(" Alg     : {alg}");
                    println!(" Token   : {}", token.yellow().bold());
                    println!(" Header  : Authorization: Bearer <token>");
                }
                emit(
                    &cli.event_log,
                    EventAction::Allowed,
                    Severity::Info,
                    format!("jwt mint user={user} alg={alg}"),
                    &[
                        ("user", serde_json::json!(user)),
                        ("issuer", serde_json::json!(issuer)),
                        ("alg", serde_json::json!(alg)),
                    ],
                );
            }
            JwtCmd::Verify {
                token,
                secret,
                jwks,
                iss,
                oidc_issuer,
                json,
            } => {
                let result = if let Some(issuer) = oidc_issuer {
                    let (v, canon) = jwt::oidc_verifier_from_issuer(&issuer, None).await?;
                    let expected = iss.as_deref().unwrap_or(canon.as_str());
                    jwt::verify_with_iss(&v, &token, Some(expected))
                } else if let Some(path) = jwks {
                    let v = jwt::rs256_verifier_from_path(&path)?;
                    jwt::verify_with_iss(&v, &token, iss.as_deref())
                } else if let Some(secret) = secret {
                    jwt::verify_with_iss(
                        &jwt::JwtVerifier::Hs256(secret),
                        &token,
                        iss.as_deref(),
                    )
                } else {
                    eprintln!("[gate] jwt verify needs --secret, --jwks, or --oidc-issuer");
                    std::process::exit(2);
                };
                match result {
                    Ok(c) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "valid": true,
                                    "claims": c,
                                }))?
                            );
                        } else {
                            println!(
                                "OK sub={} exp={} posture={:?} iss={:?}",
                                c.sub, c.exp, c.posture, c.iss
                            );
                        }
                    }
                    Err(e) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "valid": false,
                                    "error": e,
                                }))?
                            );
                        } else {
                            eprintln!("INVALID: {e}");
                        }
                        std::process::exit(3);
                    }
                }
            }
        },
        Commands::Oauth { command } => match command {
            OauthCmd::Device {
                issuer,
                client_id,
                timeout_secs,
            } => {
                let base = issuer.trim_end_matches('/');
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()?;
                let start = client
                    .post(format!("{base}/oauth/device_authorization"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(format!("client_id={client_id}&scope=openid"))
                    .send()
                    .await?;
                if !start.status().is_success() {
                    eprintln!(
                        "[gate] device_authorization failed: {} {}",
                        start.status(),
                        start.text().await.unwrap_or_default()
                    );
                    std::process::exit(1);
                }
                let body: serde_json::Value = start.json().await?;
                let device_code = body["device_code"].as_str().unwrap_or("").to_string();
                let user_code = body["user_code"].as_str().unwrap_or("").to_string();
                let verify_uri = body["verification_uri"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let interval = body["interval"].as_u64().unwrap_or(2).max(1);
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      OAuth device login                               "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" User code : {}", user_code.yellow().bold());
                println!(" Open      : {verify_uri}");
                println!(" Or run    : cyberztna oauth approve {user_code} --issuer {base}");
                println!(" Polling token endpoint...");
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                loop {
                    if std::time::Instant::now() > deadline {
                        eprintln!("[gate] device login timed out");
                        std::process::exit(1);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    let tok = client
                        .post(format!("{base}/oauth/token"))
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(format!(
                            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={client_id}"
                        ))
                        .send()
                        .await?;
                    let status = tok.status();
                    let text = tok.text().await.unwrap_or_default();
                    if status.is_success() {
                        let v: serde_json::Value =
                            serde_json::from_str(&text).unwrap_or(serde_json::json!({}));
                        let access = v["access_token"].as_str().unwrap_or("");
                        println!(
                            "{}",
                            format!("[gate] access_token issued (sub={:?})", v.get("sub"))
                                .green()
                                .bold()
                        );
                        println!("{access}");
                        println!(" Header : Authorization: Bearer <token>");
                        break;
                    }
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        let err = v["error"].as_str().unwrap_or("");
                        if err == "authorization_pending" {
                            eprint!(".");
                            continue;
                        }
                        eprintln!("\n[gate] token error: {text}");
                        std::process::exit(1);
                    }
                    eprintln!("\n[gate] token HTTP {status}: {text}");
                    std::process::exit(1);
                }
            }
            OauthCmd::Approve {
                user_code,
                user,
                issuer,
            } => {
                let base = issuer.trim_end_matches('/');
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(15))
                    .build()?;
                let res = client
                    .post(format!("{base}/oauth/device_approve"))
                    .json(&serde_json::json!({
                        "user_code": user_code,
                        "user": user,
                    }))
                    .send()
                    .await?;
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                if status.is_success() {
                    println!(
                        "{}",
                        format!("[gate] approved user_code={user_code} user={user}")
                            .green()
                            .bold()
                    );
                } else {
                    eprintln!("[gate] approve failed {status}: {body}");
                    std::process::exit(1);
                }
            }
            OauthCmd::Code {
                issuer,
                client_id,
                user,
                redirect_uri,
                state,
                url_only,
                code,
            } => {
                let base = issuer.trim_end_matches('/');
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()?;
                let auth_code = if let Some(c) = code {
                    c
                } else {
                    let auth_url = format!(
                        "{base}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid%20profile&user={}&auto_approve=1",
                        urlencoding_form(&client_id),
                        urlencoding_form(&redirect_uri),
                        urlencoding_form(&state),
                        urlencoding_form(&user),
                    );
                    println!(" Authorize URL : {auth_url}");
                    if url_only {
                        return Ok(());
                    }
                    let res = client.get(&auth_url).send().await?;
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    if !status.is_success() {
                        eprintln!("[gate] authorize failed {status}: {text}");
                        std::process::exit(1);
                    }
                    let v: serde_json::Value =
                        serde_json::from_str(&text).unwrap_or(serde_json::json!({}));
                    let c = v["code"].as_str().unwrap_or("").to_string();
                    if c.is_empty() {
                        eprintln!("[gate] no code in authorize response: {text}");
                        std::process::exit(1);
                    }
                    println!(" Code         : {}", c.yellow());
                    c
                };
                let tok = client
                    .post(format!("{base}/oauth/token"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(format!(
                        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}",
                        urlencoding_form(&auth_code),
                        urlencoding_form(&client_id),
                        urlencoding_form(&redirect_uri),
                    ))
                    .send()
                    .await?;
                let status = tok.status();
                let text = tok.text().await.unwrap_or_default();
                if !status.is_success() {
                    eprintln!("[gate] token exchange failed {status}: {text}");
                    std::process::exit(1);
                }
                let v: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or(serde_json::json!({}));
                let access = v["access_token"].as_str().unwrap_or("");
                println!(
                    "{}",
                    format!(
                        "[gate] authorization_code OK sub={:?}",
                        v.get("sub")
                    )
                    .green()
                    .bold()
                );
                println!("{access}");
                println!(" Header : Authorization: Bearer <token>");
            }
        },
        Commands::Serve {
            listen,
            min_score,
            upstream,
            tls,
            tls_cert,
            tls_key,
            mtls_ca,
            access_log,
            no_access_log,
            require_session,
            sessions,
            jwt_secret,
            jwt_jwks,
            jwt_jwks_url,
            jwt_jwks_cache,
            oidc_issuer,
            oidc_validate_iss,
            no_oidc_validate_iss,
            allow_ips,
            rate_limit,
            enforce_session_posture,
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
            if !allow_ips.is_empty() {
                cfg.allow_ips = allow_ips;
            }
            if rate_limit > 0 {
                cfg.rate_limit_per_minute = rate_limit;
            }
            if enforce_session_posture {
                cfg.enforce_session_posture = true;
            }
            // CLI --require-session wins; else honor policy-written config flag
            let require_session = require_session || cfg.require_session;
            if cfg.routes.is_empty() {
                eprintln!("[gate] no routes configured — run cyberztna init or pass --upstream");
                std::process::exit(2);
            }
            let use_tls = tls || mtls_ca.is_some();
            if mtls_ca.is_some() && !use_tls {
                eprintln!("[gate] --mtls-ca requires TLS");
                std::process::exit(2);
            }
            let scheme = if use_tls { "https" } else { "http" };
            println!(
                "[gate] starting on {}://{} min_score={} routes={} tls={} mtls={}",
                scheme,
                cfg.listen,
                cfg.min_score,
                cfg.routes.len(),
                use_tls,
                mtls_ca.is_some()
            );
            for r in &cfg.routes {
                println!("  {} {} -> {}", r.name, r.path_prefix, r.upstream);
            }
            emit(
                &cli.event_log,
                EventAction::Observed,
                Severity::Info,
                format!(
                    "gate serve listen={} tls={} mtls={}",
                    cfg.listen,
                    use_tls,
                    mtls_ca.is_some()
                ),
                &[
                    ("listen", serde_json::json!(cfg.listen)),
                    ("min_score", serde_json::json!(cfg.min_score)),
                    ("tls", serde_json::json!(use_tls)),
                    ("mtls", serde_json::json!(mtls_ca.is_some())),
                    (
                        "rate_limit",
                        serde_json::json!(cfg.rate_limit_per_minute),
                    ),
                    (
                        "allow_ips",
                        serde_json::json!(cfg.allow_ips.len()),
                    ),
                    (
                        "jwt",
                        serde_json::json!(
                            jwt_secret.is_some()
                                || jwt_jwks.is_some()
                                || jwt_jwks_url.is_some()
                                || oidc_issuer.is_some()
                        ),
                    ),
                    ("oidc", serde_json::json!(oidc_issuer.is_some())),
                ],
            );
            let (tls_cert, tls_key) = if let Some(ref ca) = mtls_ca {
                // Prefer lab PKI server certs next to CA when defaults missing
                let ca_path = ca.clone();
                let dir = ca_path.parent().unwrap_or(Path::new(".aegis"));
                let lab = tls::MtlsPaths::in_dir(dir);
                let cert = if tls_cert.exists() {
                    tls_cert
                } else if lab.server_cert.exists() {
                    lab.server_cert
                } else {
                    tls_cert
                };
                let key = if tls_key.exists() {
                    tls_key
                } else if lab.server_key.exists() {
                    lab.server_key
                } else {
                    tls_key
                };
                (cert, key)
            } else {
                (tls_cert, tls_key)
            };
            let tls_files = if use_tls {
                Some(proxy::TlsFiles {
                    cert: tls_cert,
                    key: tls_key,
                    mtls_ca,
                })
            } else {
                None
            };
            let access = if no_access_log {
                None
            } else {
                Some(access_log)
            };
            if let Some(ref p) = access {
                println!("[gate] access log      : {}", p.display());
            }
            if require_session {
                println!(
                    "[gate] require session  : {} (header X-Aegis-Session)",
                    sessions.display()
                );
            }
            let validate_iss = oidc_validate_iss && !no_oidc_validate_iss;
            let (jwt_verifier, jwt_expected_iss) = if let Some(issuer) = oidc_issuer {
                println!("[gate] OIDC issuer     : {issuer}");
                let (v, canon) =
                    jwt::oidc_verifier_from_issuer(&issuer, Some(&jwt_jwks_cache)).await?;
                println!("[gate] OIDC JWKS cache : {}", jwt_jwks_cache.display());
                println!("[gate] OIDC iss check  : {}", validate_iss);
                let expected = if validate_iss {
                    Some(canon)
                } else {
                    None
                };
                (Some(v), expected)
            } else if let Some(url) = jwt_jwks_url {
                println!("[gate] JWT JWKS URL    : {url}");
                println!("[gate] JWT JWKS cache  : {}", jwt_jwks_cache.display());
                (
                    Some(jwt::fetch_jwks_url(&url, Some(&jwt_jwks_cache)).await?),
                    None,
                )
            } else if let Some(path) = jwt_jwks {
                let v = jwt::rs256_verifier_from_path(&path)?;
                println!("[gate] JWT RS256/JWKS  : {}", path.display());
                (Some(v), None)
            } else if let Some(ref s) = jwt_secret {
                println!(
                    "[gate] JWT HS256        : enabled (secret len={})",
                    s.len()
                );
                (Some(jwt::JwtVerifier::Hs256(s.clone())), None)
            } else {
                (None, None)
            };
            if cfg.enforce_session_posture {
                println!(
                    "[gate] session posture  : enforce mint score >= {}",
                    cfg.min_score
                );
            }
            if !cfg.allow_ips.is_empty() {
                println!(
                    "[gate] allow IPs        : {}",
                    cfg.allow_ips.join(", ")
                );
            }
            if cfg.rate_limit_per_minute > 0 {
                println!(
                    "[gate] rate limit       : {}/min per IP",
                    cfg.rate_limit_per_minute
                );
            }
            let sessions_path = if require_session {
                Some(sessions)
            } else {
                // still load sessions if JWT not sole auth and path exists? only when required
                None
            };
            proxy::run(
                cfg,
                cli.event_log,
                tls_files,
                access,
                proxy::AuthOptions {
                    require_session,
                    sessions_path,
                    jwt_verifier,
                    jwt_expected_iss,
                },
            )
            .await?;
        }
        Commands::Connect { app, json } => {
            let cfg = load_config(&cli.config).unwrap_or_else(|_| default_config());
            if let Some(r) = cfg.routes.iter().find(|r| r.name == app) {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "app": app,
                            "path_prefix": r.path_prefix,
                            "upstream": r.upstream,
                            "listen": cfg.listen,
                            "access_url": format!("http://{}/", cfg.listen),
                            "min_score": cfg.min_score,
                        }))?
                    );
                } else {
                    println!("App route '{app}':");
                    println!("  prefix   : {}", r.path_prefix);
                    println!("  upstream : {}", r.upstream);
                    println!("  access   : http://{}/  (via cyberztna serve)", cfg.listen);
                    println!("  gate     : posture score >= {}", cfg.min_score);
                }
            } else {
                if json {
                    let known: Vec<_> = cfg.routes.iter().map(|r| &r.name).collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": format!("unknown app '{app}'"),
                            "known": known,
                        }))?
                    );
                } else {
                    eprintln!("[gate] unknown app '{app}'. Known:");
                    for r in &cfg.routes {
                        eprintln!("  - {}", r.name);
                    }
                }
                std::process::exit(1);
            }
        }
        Commands::Audit { limit, json } => {
            if !cli.event_log.exists() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "event_log": cli.event_log.display().to_string(),
                            "present": false,
                            "count": 0,
                            "events": [],
                        }))?
                    );
                } else {
                    println!("[gate] no event log yet");
                }
                return Ok(());
            }
            let store = EventStore::open(&cli.event_log)?;
            let events = store.recent(limit * 5)?;
            let mut hits = Vec::new();
            for e in events.into_iter().rev() {
                if e.product != ProductId::Gate {
                    continue;
                }
                hits.push(e);
                if hits.len() >= limit {
                    break;
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "event_log": cli.event_log.display().to_string(),
                        "present": true,
                        "limit": limit,
                        "count": hits.len(),
                        "events": hits,
                    }))?
                );
            } else if hits.is_empty() {
                println!("[gate] no Gate events in log");
            } else {
                for e in &hits {
                    println!(
                        "[{}] {:?} {} ",
                        e.ts.to_rfc3339(),
                        e.action,
                        e.message
                    );
                }
            }
        }
    }

    Ok(())
}
