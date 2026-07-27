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
    Status,
    /// Write a starter route config
    Init,
    /// List configured routes
    Routes,
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
    },
    /// Connect shorthand: print how to reach an app route
    Connect { app: String },
    /// Show recent Gate events from the suite event log
    Audit {
        #[arg(long, default_value_t = 20)]
        limit: usize,
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
                "posture+session+JWT/OIDC discovery, TLS/mTLS, allowlist, rate-limit".green()
            );
            println!(
                " Not implemented   : {}",
                "full OAuth authorization code flow, multi-POP SASE".red()
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
        Commands::Mtls { command } => match command {
            MtlsCmd::Init {
                dir,
                client_cn,
                force,
            } => {
                tls::generate_mtls_pki(&dir, &client_cn, force)?;
            }
            MtlsCmd::Status { dir } => {
                let p = tls::MtlsPaths::in_dir(&dir);
                println!("[gate] mTLS dir {}", dir.display());
                for (label, path) in [
                    ("ca", &p.ca_cert),
                    ("server", &p.server_cert),
                    ("server-key", &p.server_key),
                    ("client", &p.client_cert),
                    ("client-key", &p.client_key),
                ] {
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
                        println!(
                            "OK sub={} exp={} posture={:?} iss={:?}",
                            c.sub, c.exp, c.posture, c.iss
                        );
                    }
                    Err(e) => {
                        eprintln!("INVALID: {e}");
                        std::process::exit(3);
                    }
                }
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
