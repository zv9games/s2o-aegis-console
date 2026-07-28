//! S2O CyberMesh — WireGuard keys, conf generation, optional system wg status.

mod peers;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use colored::*;
use peers::{MeshPeer, PeerRegistry};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "cybermesh")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "0.4.0")]
#[command(about = "S2O CyberMesh: WireGuard keygen + config orchestration", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Validate keys/conf/peers registry (no tunnel create)
    Doctor {
        #[arg(long, default_value = ".aegis/wg0.conf")]
        conf: PathBuf,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        peers_file: PathBuf,
        #[arg(long, default_value = ".aegis/wg-private.key")]
        private_key_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print system `wg show` if available (does not create tunnels)
    Show,
    /// TCP connect probe to peer endpoints (userspace reachability; not WG handshake)
    Probe {
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        peers_file: PathBuf,
        /// Single host:port (skips registry when set)
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value_t = 3)]
        timeout_secs: u64,
        #[arg(long)]
        json: bool,
    },
    /// Attempt `wg-quick up` on a conf (requires admin + wg-quick)
    Up {
        #[arg(long, default_value = ".aegis/wg0.conf")]
        conf: PathBuf,
    },
    /// Attempt `wg-quick down`
    Down {
        #[arg(long, default_value = ".aegis/wg0.conf")]
        conf: PathBuf,
    },
    /// Peer registry + live system peers
    Peers {
        #[command(subcommand)]
        command: PeersCmd,
    },
    /// Real X25519 WireGuard-compatible keypair (base64)
    Genkey {
        #[arg(long)]
        write_private: Option<String>,
        #[arg(long)]
        write_public: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Derive public key from a base64 private key
    Pubkey {
        private_b64: String,
        #[arg(long)]
        json: bool,
    },
    /// Write a WireGuard interface conf (for system wg-quick / import)
    Config {
        /// Output path
        #[arg(long, default_value = ".aegis/wg0.conf")]
        output: PathBuf,
        /// Interface address (CIDR)
        #[arg(long, default_value = "10.220.0.2/32")]
        address: String,
        /// Listen port (optional)
        #[arg(long)]
        listen_port: Option<u16>,
        /// DNS servers comma-separated (optional)
        #[arg(long)]
        dns: Option<String>,
        /// Path to private key file, or generate new
        #[arg(long)]
        private_key_file: Option<PathBuf>,
        /// Peer public key (base64) — single peer mode
        #[arg(long)]
        peer_public: Option<String>,
        /// Peer endpoint host:port
        #[arg(long)]
        peer_endpoint: Option<String>,
        /// AllowedIPs for single peer
        #[arg(long, default_value = "10.220.0.0/24")]
        allowed_ips: String,
        /// PersistentKeepalive seconds
        #[arg(long, default_value_t = 25)]
        keepalive: u16,
        /// Include all peers from registry file
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        peers_file: PathBuf,
        /// Skip peers registry (only CLI single peer flags)
        #[arg(long)]
        no_peers_file: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PeersCmd {
    /// List peers from registry file
    List {
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Export peers registry (json/csv)
    Export {
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        /// json | csv
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Add or update a peer in the registry
    Add {
        name: String,
        public_key: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value = "10.220.0.0/24")]
        allowed_ips: String,
        #[arg(long, default_value_t = 25)]
        keepalive: u16,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Remove a peer by name
    Remove {
        name: String,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show one peer by name
    Show {
        name: String,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Update fields on an existing peer (endpoint / allowed-ips / keepalive)
    Set {
        name: String,
        #[arg(long)]
        endpoint: Option<String>,
        /// Clear endpoint
        #[arg(long)]
        clear_endpoint: bool,
        #[arg(long)]
        allowed_ips: Option<String>,
        #[arg(long)]
        keepalive: Option<u16>,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
    },
    /// Live peers from system `wg` (if installed)
    Live,
    /// POST local public key to aegisd mesh directory
    Publish {
        /// Path to public key file or base64 string
        public_key: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value = "10.220.0.0/24")]
        allowed_ips: String,
        #[arg(long, default_value = "http://127.0.0.1:9090/mesh/peers")]
        url: String,
    },
    /// Pull remote peer directory from aegisd into local registry
    Pull {
        #[arg(long, default_value = "http://127.0.0.1:9090/mesh/peers")]
        url: String,
        #[arg(long, default_value = ".aegis/mesh-peers.json")]
        file: PathBuf,
        /// Merge with existing (default replace)
        #[arg(long)]
        merge: bool,
    },
}

fn wg_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    (B64.encode(secret.to_bytes()), B64.encode(public.as_bytes()))
}

fn wg_pubkey_from_private(private_b64: &str) -> Result<String, String> {
    let bytes = B64
        .decode(private_b64.trim())
        .map_err(|e| format!("base64 decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("private key must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(B64.encode(public.as_bytes()))
}

/// TCP connect probe result for one endpoint.
#[derive(Debug, Clone, serde::Serialize)]
struct ProbeResult {
    name: String,
    endpoint: String,
    ok: bool,
    latency_ms: Option<u64>,
    detail: String,
}

async fn tcp_probe(endpoint: &str, timeout_secs: u64) -> ProbeResult {
    let start = std::time::Instant::now();
    let to = std::time::Duration::from_secs(timeout_secs.max(1));
    match tokio::time::timeout(to, tokio::net::TcpStream::connect(endpoint)).await {
        Ok(Ok(_stream)) => ProbeResult {
            name: String::new(),
            endpoint: endpoint.to_string(),
            ok: true,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            detail: "tcp connect ok".into(),
        },
        Ok(Err(e)) => ProbeResult {
            name: String::new(),
            endpoint: endpoint.to_string(),
            ok: false,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            detail: format!("connect error: {e}"),
        },
        Err(_) => ProbeResult {
            name: String::new(),
            endpoint: endpoint.to_string(),
            ok: false,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            detail: format!("timeout after {timeout_secs}s"),
        },
    }
}

fn find_wg() -> Option<&'static str> {
    for bin in ["wg", "wg.exe"] {
        if Command::new(bin)
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(bin);
        }
    }
    None
}

fn find_wg_quick() -> Option<&'static str> {
    for bin in ["wg-quick", "wg-quick.exe"] {
        if Command::new(bin)
            .arg("--help")
            .output()
            .map(|o| o.status.success() || o.status.code().is_some())
            .unwrap_or(false)
        {
            // help often exits non-zero; existence via which-like: try running
            return Some(bin);
        }
    }
    // presence by path probe is weak; try spawn
    if Command::new("wg-quick").arg("help").output().is_ok() {
        return Some("wg-quick");
    }
    None
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    Ok(())
}

fn build_conf(
    private_key: &str,
    address: &str,
    listen_port: Option<u16>,
    dns: Option<&str>,
    peer_public: Option<&str>,
    peer_endpoint: Option<&str>,
    allowed_ips: &str,
    keepalive: u16,
    registry: Option<&PeerRegistry>,
) -> String {
    let mut conf = String::new();
    conf.push_str("# Generated by S2O CyberMesh - review before wg-quick up\n");
    conf.push_str("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {private_key}\n"));
    conf.push_str(&format!("Address = {address}\n"));
    if let Some(port) = listen_port {
        conf.push_str(&format!("ListenPort = {port}\n"));
    }
    if let Some(dns) = dns {
        conf.push_str(&format!("DNS = {dns}\n"));
    }
    conf.push('\n');
    let mut wrote_peer = false;
    if let Some(reg) = registry {
        if !reg.peers.is_empty() {
            conf.push_str(&reg.render_peer_sections());
            wrote_peer = true;
        }
    }
    if let Some(pk) = peer_public {
        conf.push_str("\n[Peer]\n");
        conf.push_str("# cli-single\n");
        conf.push_str(&format!("PublicKey = {pk}\n"));
        conf.push_str(&format!("AllowedIPs = {allowed_ips}\n"));
        if let Some(ep) = peer_endpoint {
            conf.push_str(&format!("Endpoint = {ep}\n"));
        }
        conf.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
        wrote_peer = true;
    }
    if !wrote_peer {
        conf.push_str("# [Peer] section omitted — cybermesh peers add  or  --peer-public\n");
    }
    conf
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { json } => {
            let wg = find_wg();
            let conf_path = PathBuf::from(".aegis/wg0.conf");
            let peers = PathBuf::from(".aegis/mesh-peers.json");
            let peer_count = if peers.exists() {
                Some(PeerRegistry::load(&peers).peers.len())
            } else {
                None
            };
            let mut tunnel_status = if wg.is_some() {
                "unknown".to_string()
            } else {
                "no_wg_tool".to_string()
            };
            let mut tunnel_lines: Vec<String> = Vec::new();
            if let Some(bin) = wg.as_deref() {
                if let Ok(out) = Command::new(bin).arg("show").output() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if text.trim().is_empty() {
                        tunnel_status = "no_interfaces".into();
                    } else {
                        tunnel_status = "interfaces_reported".into();
                        tunnel_lines = text.lines().take(12).map(|s| s.to_string()).collect();
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "product": "cybermesh",
                        "wg_tool": wg,
                        "conf": conf_path.display().to_string(),
                        "conf_present": conf_path.exists(),
                        "peers_file": peers.display().to_string(),
                        "peers_present": peers.exists(),
                        "peer_count": peer_count,
                        "tunnel_status": tunnel_status,
                        "tunnel_preview": tunnel_lines,
                        "implemented": "X25519 keys, multi-peer registry, conf writer, doctor, probe, wg show/wg-quick",
                        "not_implemented": "embedded boringtun userspace stack",
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "        S2O CyberMesh (Phase 3)                          "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    " system wg tool    : {}",
                    if let Some(bin) = wg.as_deref() {
                        format!("found ({bin})").green().to_string()
                    } else {
                        "not found (optional)".yellow().to_string()
                    }
                );
                println!(
                    " conf template     : {} ({})",
                    conf_path.display(),
                    if conf_path.exists() {
                        "present".green().to_string()
                    } else {
                        "missing — cybermesh config".yellow().to_string()
                    }
                );
                match tunnel_status.as_str() {
                    "no_interfaces" => println!(
                        " Tunnel status     : {}",
                        "no interfaces (wg show empty)".yellow()
                    ),
                    "interfaces_reported" => {
                        println!(
                            " Tunnel status     : {}",
                            "interfaces reported by wg show".green().bold()
                        );
                        for line in &tunnel_lines {
                            println!("   {line}");
                        }
                    }
                    _ => println!(
                        " Tunnel status     : {}",
                        "unknown (install WireGuard tools to activate)".yellow()
                    ),
                }
                println!(
                    " peers registry    : {} ({})",
                    peers.display(),
                    match peer_count {
                        Some(n) => format!("{n} peers").green().to_string(),
                        None => "missing".yellow().to_string(),
                    }
                );
                println!(
                    " Implemented       : {}",
                    "X25519 keys, multi-peer registry, conf writer, doctor, probe, wg show/wg-quick"
                        .green()
                );
                println!(
                    " Not implemented   : {}",
                    "embedded boringtun userspace stack".red()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
        }
        Commands::Doctor {
            conf,
            peers_file,
            private_key_file,
            json,
        } => {
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut notes: Vec<serde_json::Value> = Vec::new();
            let mut check = |label: &str, good: bool, detail: &str| {
                let soft = !good && detail.starts_with("WARN");
                notes.push(serde_json::json!({
                    "label": label,
                    "ok": good,
                    "warn": soft,
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
                    "      S2O CyberMesh doctor                               "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }

            // X25519 / key material
            if private_key_file.exists() {
                match fs::read_to_string(&private_key_file) {
                    Ok(pk) => {
                        let pk = pk.trim();
                        match wg_pubkey_from_private(pk) {
                            Ok(pubk) => check(
                                "private key",
                                true,
                                &format!(
                                    "{} → pub {}",
                                    private_key_file.display(),
                                    &pubk[..16.min(pubk.len())]
                                ),
                            ),
                            Err(e) => check("private key", false, &format!("decode error: {e}")),
                        }
                    }
                    Err(e) => check("private key", false, &e.to_string()),
                }
            } else {
                check(
                    "private key",
                    false,
                    &format!(
                        "WARN missing {} — run: cybermesh genkey --write-private …",
                        private_key_file.display()
                    ),
                );
            }

            // conf file
            if conf.exists() {
                match fs::read_to_string(&conf) {
                    Ok(text) => {
                        let has_iface = text.contains("[Interface]") && text.contains("PrivateKey");
                        let peers = text.matches("[Peer]").count();
                        check(
                            "conf file",
                            has_iface,
                            &format!(
                                "{} interface={} peers={}",
                                conf.display(),
                                has_iface,
                                peers
                            ),
                        );
                        if has_iface && peers == 0 {
                            check(
                                "conf peers",
                                false,
                                "WARN no [Peer] sections — peers add or --peer-public",
                            );
                        }
                    }
                    Err(e) => check("conf file", false, &e.to_string()),
                }
            } else {
                check(
                    "conf file",
                    false,
                    &format!("WARN missing {} — run cybermesh config", conf.display()),
                );
            }

            // peers registry
            if peers_file.exists() {
                let reg = PeerRegistry::load(&peers_file);
                check(
                    "peers registry",
                    true,
                    &format!("{} ({} peer(s))", peers_file.display(), reg.peers.len()),
                );
                for p in &reg.peers {
                    let pk_ok = B64
                        .decode(p.public_key.trim())
                        .map(|b| b.len() == 32)
                        .unwrap_or(false);
                    check(
                        &format!("peer {}", p.name),
                        pk_ok,
                        if pk_ok {
                            p.endpoint.as_deref().unwrap_or("no endpoint")
                        } else {
                            "invalid public key base64"
                        },
                    );
                }
            } else {
                check(
                    "peers registry",
                    false,
                    &format!("WARN missing {}", peers_file.display()),
                );
            }

            // tools
            match find_wg() {
                Some(bin) => check("wg tool", true, bin),
                None => check("wg tool", false, "WARN wg not on PATH (optional)"),
            }
            match find_wg_quick() {
                Some(bin) => check("wg-quick", true, bin),
                None => check(
                    "wg-quick",
                    false,
                    "WARN not found — import conf via WireGuard UI",
                ),
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "checks": notes,
                        "not_embedded": "boringtun userspace stack (later)",
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                println!(" Summary: ok={ok} warn={warn} fail={fail}");
                println!(
                    " Not embedded: {}",
                    "boringtun userspace stack (later)".yellow()
                );
            }
            if fail > 0 {
                std::process::exit(2);
            }
        }
        Commands::Probe {
            peers_file,
            endpoint,
            timeout_secs,
            json,
        } => {
            let mut targets: Vec<(String, String)> = Vec::new();
            if let Some(ep) = endpoint {
                targets.push(("cli".into(), ep));
            } else {
                let reg = PeerRegistry::load(&peers_file);
                if reg.peers.is_empty() {
                    eprintln!(
                        "[mesh] no peers in {} — add with cybermesh peers add, or --endpoint host:port",
                        peers_file.display()
                    );
                    std::process::exit(2);
                }
                for p in &reg.peers {
                    match &p.endpoint {
                        Some(ep) if !ep.trim().is_empty() => {
                            targets.push((p.name.clone(), ep.clone()));
                        }
                        _ => {
                            if !json {
                                println!(
                                    "  {} {} — {}",
                                    "SKIP".yellow().bold(),
                                    p.name,
                                    "no endpoint"
                                );
                            }
                        }
                    }
                }
                if targets.is_empty() {
                    eprintln!("[mesh] no peer endpoints to probe");
                    std::process::exit(2);
                }
            }

            let mut results = Vec::new();
            for (name, ep) in &targets {
                let mut r = tcp_probe(ep, timeout_secs).await;
                r.name = name.clone();
                results.push(r);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "      S2O CyberMesh probe (TCP)                          "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    " {}",
                    "Note: TCP connect only — does not validate WireGuard handshake.".yellow()
                );
                let mut ok_n = 0u32;
                let mut fail_n = 0u32;
                for r in &results {
                    if r.ok {
                        ok_n += 1;
                        println!(
                            "  {} {} @ {} — {} ({}ms)",
                            "OK".green().bold(),
                            r.name,
                            r.endpoint,
                            r.detail,
                            r.latency_ms.unwrap_or(0)
                        );
                    } else {
                        fail_n += 1;
                        println!(
                            "  {} {} @ {} — {} ({}ms)",
                            "FAIL".red().bold(),
                            r.name,
                            r.endpoint,
                            r.detail,
                            r.latency_ms.unwrap_or(0)
                        );
                    }
                }
                println!(" Summary: {ok_n} ok, {fail_n} fail (timeout={timeout_secs}s)");
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
            }
            if results.iter().any(|r| !r.ok) {
                std::process::exit(3);
            }
        }
        Commands::Show => {
            let Some(bin) = find_wg() else {
                eprintln!("[cybermesh] `wg` not found on PATH");
                std::process::exit(2);
            };
            let status = Command::new(bin).arg("show").status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Commands::Up { conf } => {
            if !conf.exists() {
                eprintln!(
                    "[cybermesh] conf missing: {} — run cybermesh config",
                    conf.display()
                );
                std::process::exit(1);
            }
            // Prefer wg-quick; on Windows WireGuard may use different tooling
            let iface = conf
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("wg0");
            if let Some(wq) = find_wg_quick() {
                println!("[cybermesh] running {wq} up {} ...", conf.display());
                let st = Command::new(wq).arg("up").arg(&conf).status()?;
                std::process::exit(st.code().unwrap_or(1));
            }
            eprintln!("[cybermesh] wg-quick not found.");
            eprintln!("Import {} with system WireGuard UI, or install wireguard-tools.", conf.display());
            eprintln!("Interface name hint: {iface}");
            std::process::exit(2);
        }
        Commands::Down { conf } => {
            if let Some(wq) = find_wg_quick() {
                let st = Command::new(wq).arg("down").arg(&conf).status()?;
                std::process::exit(st.code().unwrap_or(1));
            }
            eprintln!("[cybermesh] wg-quick not found — tear down via system WireGuard tools.");
            std::process::exit(2);
        }
        Commands::Peers { command } => match command {
            PeersCmd::List { file, json } => {
                let reg = PeerRegistry::load(&file);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": file.display().to_string(),
                            "version": reg.version,
                            "count": reg.peers.len(),
                            "peers": reg.peers,
                        }))?
                    );
                } else if reg.peers.is_empty() {
                    println!("[cybermesh] no peers in {} — peers add …", file.display());
                } else {
                    for p in &reg.peers {
                        println!(
                            "{:<16} pk={} endpoint={} allowed={}",
                            p.name,
                            &p.public_key[..p.public_key.len().min(16)],
                            p.endpoint.as_deref().unwrap_or("-"),
                            p.allowed_ips
                        );
                    }
                    println!("--- {} peer(s) in {}", reg.peers.len(), file.display());
                }
            }
            PeersCmd::Export { file, format, out } => {
                let reg = PeerRegistry::load(&file);
                let text = if format.eq_ignore_ascii_case("csv") {
                    let mut s =
                        String::from("name,public_key,endpoint,allowed_ips,keepalive\n");
                    for p in &reg.peers {
                        s.push_str(&format!(
                            "{},{},{},{},{}\n",
                            p.name,
                            p.public_key,
                            p.endpoint.as_deref().unwrap_or(""),
                            p.allowed_ips,
                            p.keepalive
                        ));
                    }
                    s
                } else {
                    serde_json::to_string_pretty(&serde_json::json!({
                        "path": file.display().to_string(),
                        "version": reg.version,
                        "count": reg.peers.len(),
                        "peers": reg.peers,
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
                            "[cybermesh] exported {} peer(s) → {}",
                            reg.peers.len(),
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
            PeersCmd::Add {
                name,
                public_key,
                endpoint,
                allowed_ips,
                keepalive,
                file,
                json,
            } => {
                let mut reg = PeerRegistry::load(&file);
                let existed = reg.peers.iter().any(|p| p.name == name);
                let peer = MeshPeer {
                    name: name.clone(),
                    public_key: public_key.clone(),
                    endpoint: endpoint.clone(),
                    allowed_ips: allowed_ips.clone(),
                    keepalive,
                    notes: None,
                };
                reg.add(peer.clone());
                reg.save(&file)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "updated": existed,
                            "added": !existed,
                            "path": file.display().to_string(),
                            "peer": peer,
                            "count": reg.peers.len(),
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!("[cybermesh] peer '{name}' saved -> {}", file.display())
                            .green()
                            .bold()
                    );
                }
            }
            PeersCmd::Remove { name, file, json } => {
                let mut reg = PeerRegistry::load(&file);
                if reg.remove(&name) {
                    reg.save(&file)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": true,
                                "removed": name,
                                "remaining": reg.peers.len(),
                                "path": file.display().to_string(),
                            }))?
                        );
                    } else {
                        println!("[cybermesh] removed peer '{name}'");
                    }
                } else {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": "peer not found",
                                "name": name,
                            }))?
                        );
                    } else {
                        eprintln!("[cybermesh] peer not found: {name}");
                    }
                    std::process::exit(1);
                }
            }
            PeersCmd::Show { name, file, json } => {
                let reg = PeerRegistry::load(&file);
                let Some(p) = reg.peers.iter().find(|p| p.name.eq_ignore_ascii_case(&name))
                else {
                    eprintln!("[cybermesh] peer not found: {name}");
                    std::process::exit(1);
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": file.display().to_string(),
                            "peer": p,
                        }))?
                    );
                } else {
                    println!("[cybermesh] peer '{}'", p.name);
                    println!("  public_key  : {}", p.public_key);
                    println!(
                        "  endpoint    : {}",
                        p.endpoint.as_deref().unwrap_or("-")
                    );
                    println!("  allowed_ips : {}", p.allowed_ips);
                    println!("  keepalive   : {}", p.keepalive);
                    if let Some(ref n) = p.notes {
                        println!("  notes       : {n}");
                    }
                }
            }
            PeersCmd::Set {
                name,
                endpoint,
                clear_endpoint,
                allowed_ips,
                keepalive,
                file,
            } => {
                let mut reg = PeerRegistry::load(&file);
                let Some(p) = reg
                    .peers
                    .iter_mut()
                    .find(|p| p.name.eq_ignore_ascii_case(&name))
                else {
                    eprintln!("[cybermesh] peer not found: {name}");
                    std::process::exit(1);
                };
                let mut changed = Vec::new();
                if clear_endpoint {
                    p.endpoint = None;
                    changed.push("endpoint=cleared".into());
                } else if let Some(ep) = endpoint {
                    p.endpoint = Some(ep.clone());
                    changed.push(format!("endpoint={ep}"));
                }
                if let Some(a) = allowed_ips {
                    p.allowed_ips = a.clone();
                    changed.push(format!("allowed_ips={a}"));
                }
                if let Some(k) = keepalive {
                    p.keepalive = k;
                    changed.push(format!("keepalive={k}"));
                }
                if changed.is_empty() {
                    eprintln!(
                        "[cybermesh] peers set: pass --endpoint, --clear-endpoint, --allowed-ips, and/or --keepalive"
                    );
                    std::process::exit(2);
                }
                let shown = p.name.clone();
                reg.save(&file)?;
                println!(
                    "{}",
                    format!(
                        "[cybermesh] peer '{shown}' updated ({}) → {}",
                        changed.join(", "),
                        file.display()
                    )
                    .green()
                    .bold()
                );
            }
            PeersCmd::Live => {
                if let Some(bin) = find_wg() {
                    let out = Command::new(bin).args(["show", "all", "peers"]).output();
                    match out {
                        Ok(o) if o.status.success() => {
                            let t = String::from_utf8_lossy(&o.stdout);
                            if t.trim().is_empty() {
                                println!("[cybermesh] no peers reported by wg");
                            } else {
                                print!("{t}");
                            }
                        }
                        _ => {
                            let _ = Command::new(bin).arg("show").status();
                        }
                    }
                } else {
                    println!("[cybermesh] wg not found — install WireGuard tools for live peers.");
                }
            }
            PeersCmd::Publish {
                public_key,
                name,
                endpoint,
                allowed_ips,
                url,
            } => {
                let pk = if Path::new(&public_key).exists() {
                    fs::read_to_string(&public_key)?.trim().to_string()
                } else {
                    public_key
                };
                let host = std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "mesh-node".into());
                let peer = MeshPeer {
                    name: name.unwrap_or(host),
                    public_key: pk,
                    endpoint,
                    allowed_ips,
                    keepalive: 25,
                    notes: None,
                };
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(15))
                    .build()?;
                let res = client.post(&url).json(&peer).send().await?;
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                println!("[cybermesh] publish {url} -> {status}");
                println!("{body}");
                if !status.is_success() {
                    std::process::exit(1);
                }
            }
            PeersCmd::Pull { url, file, merge } => {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(15))
                    .build()?;
                let res = client.get(&url).send().await?;
                if !res.status().is_success() {
                    eprintln!("[cybermesh] pull failed: {}", res.status());
                    std::process::exit(1);
                }
                let remote: PeerRegistry = res.json().await?;
                let reg = if merge {
                    let mut local = PeerRegistry::load(&file);
                    for p in remote.peers {
                        local.add(p);
                    }
                    local
                } else {
                    remote
                };
                reg.save(&file)?;
                println!(
                    "[cybermesh] pulled {} peer(s) -> {}",
                    reg.peers.len(),
                    file.display()
                );
            }
        },
        Commands::Genkey {
            write_private,
            write_public,
            json,
        } => {
            let (privkey, pubkey) = wg_keypair();
            if let Some(ref path) = write_private {
                ensure_parent(Path::new(path))?;
                fs::write(path, format!("{privkey}\n"))?;
            }
            if let Some(ref path) = write_public {
                ensure_parent(Path::new(path))?;
                fs::write(path, format!("{pubkey}\n"))?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "private": privkey,
                        "public": pubkey,
                        "write_private": write_private,
                        "write_public": write_public,
                    }))?
                );
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "  WireGuard X25519 keypair                               "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Private : {}", privkey.yellow());
                println!(" Public  : {}", pubkey.green());
                if let Some(path) = write_private {
                    println!(" Wrote private → {path}");
                }
                if let Some(path) = write_public {
                    println!(" Wrote public  → {path}");
                }
            }
        }
        Commands::Pubkey { private_b64, json } => match wg_pubkey_from_private(&private_b64) {
            Ok(p) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "public": p,
                        }))?
                    );
                } else {
                    println!("{p}");
                }
            }
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": e.to_string(),
                        }))?
                    );
                } else {
                    eprintln!("[cybermesh] {e}");
                }
                std::process::exit(1);
            }
        },
        Commands::Config {
            output,
            address,
            listen_port,
            dns,
            private_key_file,
            peer_public,
            peer_endpoint,
            allowed_ips,
            keepalive,
            peers_file,
            no_peers_file,
            json,
        } => {
            let mut generated_key_paths: Option<(String, String)> = None;
            let private_key = if let Some(pkf) = private_key_file {
                fs::read_to_string(&pkf)?.trim().to_string()
            } else {
                let (sk, pk) = wg_keypair();
                let key_path = output.with_extension("key");
                ensure_parent(&key_path)?;
                fs::write(&key_path, format!("{sk}\n"))?;
                let pub_path = output.with_extension("pub");
                fs::write(&pub_path, format!("{pk}\n"))?;
                generated_key_paths =
                    Some((key_path.display().to_string(), pub_path.display().to_string()));
                if !json {
                    println!("[cybermesh] generated keys:");
                    println!("  private → {}", key_path.display());
                    println!("  public  → {}", pub_path.display());
                }
                sk
            };
            // validate
            if let Err(e) = wg_pubkey_from_private(&private_key) {
                eprintln!("[cybermesh] invalid private key: {e}");
                std::process::exit(1);
            }
            let peer_count = if no_peers_file {
                0
            } else {
                PeerRegistry::load(&peers_file).peers.len()
            };
            let registry = if no_peers_file {
                None
            } else {
                let r = PeerRegistry::load(&peers_file);
                if !r.peers.is_empty() && !json {
                    println!(
                        "[cybermesh] including {} peer(s) from {}",
                        r.peers.len(),
                        peers_file.display()
                    );
                }
                Some(r)
            };
            let conf = build_conf(
                &private_key,
                &address,
                listen_port,
                dns.as_deref(),
                peer_public.as_deref(),
                peer_endpoint.as_deref(),
                &allowed_ips,
                keepalive,
                registry.as_ref(),
            );
            ensure_parent(&output)?;
            fs::write(&output, &conf)?;
            // restrict perms on unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&output, fs::Permissions::from_mode(0o600));
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "output": output.display().to_string(),
                        "address": address,
                        "listen_port": listen_port,
                        "dns": dns,
                        "peer_count": peer_count,
                        "peers_file": if no_peers_file { None } else { Some(peers_file.display().to_string()) },
                        "bytes": conf.len(),
                        "generated_keys": generated_key_paths.map(|(priv_p, pub_p)| serde_json::json!({
                            "private": priv_p,
                            "public": pub_p,
                        })),
                    }))?
                );
            } else {
                println!(
                    "{}",
                    format!("[cybermesh] wrote {}", output.display())
                        .green()
                        .bold()
                );
                println!("Review the conf, then:");
                println!("  cybermesh up --conf {}", output.display());
                println!("  # or import into WireGuard for Windows");
            }
        }
    }

    Ok(())
}
