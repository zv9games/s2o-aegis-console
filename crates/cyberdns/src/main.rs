use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::UdpSocket;

const DEFAULT_BLOCKLIST_PATH: &str = ".aegis/dns_blocklist.txt";

#[derive(Parser)]
#[command(name = "cyberdns")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.1.0")]
#[command(about = "S2O CyberDNS Guard: Encrypted DNS-over-HTTPS (DoH) Resolver & Category Web Filter", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberDNS engine status, active DoH resolver, and blocklist metrics
    Status,
    /// Resolve a domain name securely over encrypted DNS-over-HTTPS (DoH)
    Resolve {
        /// The target domain name to resolve
        domain: String,
    },
    /// Add a domain to the local threat blocklist
    Block {
        /// Target domain name to block
        domain: String,
    },
    /// Remove a domain from the local threat blocklist
    Unblock {
        /// Target domain name to unblock
        domain: String,
    },
    /// List all domains currently in the threat blocklist
    ListBlocked,
    /// Start the local S2O CyberDNS Guard UDP forwarding proxy server
    Serve {
        /// Local listen address (default: 127.0.0.1:5353)
        #[arg(short, long, default_value = "127.0.0.1:5353")]
        listen: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(default)]
    data: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DohResponse {
    #[serde(default)]
    Status: u32,
    Answer: Option<Vec<DohAnswer>>,
}

fn load_blocklist() -> HashSet<String> {
    let mut set = HashSet::new();
    let path = PathBuf::from(DEFAULT_BLOCKLIST_PATH);
    if let Ok(file) = File::open(&path) {
        let reader = BufReader::new(file);
        for line in reader.lines().filter_map(|l| l.ok()) {
            let trimmed = line.trim().to_lowercase();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                set.insert(trimmed);
            }
        }
    }
    // Seed standard telemetry & ads if empty
    if set.is_empty() {
        set.insert("telemetry.microsoft.com".to_string());
        set.insert("v10.events.data.microsoft.com".to_string());
        set.insert("doubleclick.net".to_string());
        set.insert("adservice.google.com".to_string());
    }
    set
}

fn save_blocklist(set: &HashSet<String>) -> std::io::Result<()> {
    let path = PathBuf::from(DEFAULT_BLOCKLIST_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;

    for domain in set {
        writeln!(file, "{}", domain)?;
    }
    Ok(())
}

fn extract_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let mut idx = 12;
    let mut labels = Vec::new();

    while idx < buf.len() {
        let len = buf[idx] as usize;
        if len == 0 {
            break;
        }
        idx += 1;
        if idx + len > buf.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&buf[idx..idx + len]) {
            labels.push(label.to_lowercase());
        }
        idx += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

async fn query_doh(domain: &str) -> Result<Option<String>, reqwest::Error> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", domain);
    let client = reqwest::Client::new();
    let res = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await?;

    if res.status().is_success() {
        let doh: DohResponse = res.json().await?;
        if let Some(answers) = doh.Answer {
            for ans in answers {
                if ans.record_type == 1 { // A record
                    return Ok(Some(ans.data));
                }
            }
        }
    }
    Ok(None)
}

fn build_dns_response(req: &[u8], ip: Option<[u8; 4]>) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let mut resp = Vec::with_capacity(req.len() + 16);
    // Header
    resp.push(req[0]);
    resp.push(req[1]);
    resp.push(0x81); // Standard query response, No error
    resp.push(if ip.is_some() { 0x80 } else { 0x83 }); // 0x83 = NXDOMAIN
    resp.push(req[4]); // QDCOUNT
    resp.push(req[5]);
    resp.push(0x00); // ANCOUNT
    resp.push(if ip.is_some() { 0x01 } else { 0x00 });
    resp.push(0x00); // NSCOUNT
    resp.push(0x00);
    resp.push(0x00); // ARCOUNT
    resp.push(0x00);

    // Copy Question section
    let mut q_end = 12;
    while q_end < req.len() && req[q_end] != 0 {
        q_end += (req[q_end] as usize) + 1;
    }
    q_end += 5; // null byte + QTYPE (2) + QCLASS (2)
    if q_end <= req.len() {
        resp.extend_from_slice(&req[12..q_end]);
    }

    // Answer section if resolved
    if let Some(ip_bytes) = ip {
        resp.push(0xc0); // pointer to domain name in header
        resp.push(0x0c);
        resp.push(0x00); // TYPE A
        resp.push(0x01);
        resp.push(0x00); // CLASS IN
        resp.push(0x01);
        resp.push(0x00); // TTL (60s)
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x3c);
        resp.push(0x00); // RDLENGTH (4 bytes)
        resp.push(0x04);
        resp.extend_from_slice(&ip_bytes);
    }

    resp
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let blocklist = load_blocklist();
            println!("{}", "=========================================================".cyan());
            println!("{}", "        SPLIT2OPS CYBERDNS GUARD & SINKHOLE              ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Primary Resolver  : {}", "https://cloudflare-dns.com/dns-query (DoH)".yellow());
            println!(" Secondary Engine  : {}", "Local UDP DNS Forwarder".green());
            println!(" Threat Blocklist  : {}", format!("{} active domains sinkholed", blocklist.len()).bold());
            println!(" Storage File      : {}", DEFAULT_BLOCKLIST_PATH);
            println!("{}", "=========================================================".cyan());
        }
        Commands::Resolve { domain } => {
            let blocklist = load_blocklist();
            let d_lower = domain.to_lowercase();
            if blocklist.contains(&d_lower) {
                println!("{}", "---------------------------------------------------------".cyan());
                println!(" Target Domain : {}", domain.bold());
                println!(" Guard Verdict : {}", "BLOCKED (Threat Sinkhole)".red().bold());
                println!(" Resolved IP   : {}", "0.0.0.0".red());
                println!("{}", "---------------------------------------------------------".cyan());
                return Ok(());
            }

            println!("{}", format!("[cyberdns] resolving '{}' via Encrypted DoH...", domain).cyan());
            let url = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", domain);
            let client = reqwest::Client::new();
            let res = client
                .get(&url)
                .header("accept", "application/dns-json")
                .send()
                .await?;

            if res.status().is_success() {
                let doh: DohResponse = res.json().await?;
                println!("{}", "---------------------------------------------------------".cyan());
                if let Some(answers) = doh.Answer {
                    for ans in answers {
                        println!(" Domain Record : {}", ans.name.bold());
                        println!(" Type Code     : {}", ans.record_type);
                        println!(" Resolved IP   : {}", ans.data.green().bold());
                        println!("{}", "---------------------------------------------------------".cyan());
                    }
                } else {
                    println!("{}", "NXDOMAIN: No DNS records found for this target.".yellow());
                }
            } else {
                println!("{}", format!("DoH HTTP Error: {}", res.status()).red());
            }
        }
        Commands::Block { domain } => {
            let mut blocklist = load_blocklist();
            let d_lower = domain.to_lowercase();
            if blocklist.insert(d_lower.clone()) {
                save_blocklist(&blocklist)?;
                println!("{}", format!("[cyberdns] OK: '{}' added to threat sinkhole blocklist.", d_lower).green().bold());
            } else {
                println!("{}", format!("[cyberdns] '{}' is already in the blocklist.", d_lower).yellow());
            }
        }
        Commands::Unblock { domain } => {
            let mut blocklist = load_blocklist();
            let d_lower = domain.to_lowercase();
            if blocklist.remove(&d_lower) {
                save_blocklist(&blocklist)?;
                println!("{}", format!("[cyberdns] OK: '{}' removed from threat sinkhole blocklist.", d_lower).green().bold());
            } else {
                println!("{}", format!("[cyberdns] '{}' was not found in the blocklist.", d_lower).yellow());
            }
        }
        Commands::ListBlocked => {
            let blocklist = load_blocklist();
            println!("{}", "=========================================================".cyan());
            println!("{}", "           CyberDNS Guard — Threat Sinkhole              ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Total sinkholed domains: {}", blocklist.len());
            for (idx, dom) in blocklist.iter().enumerate() {
                println!("{}. {}", idx + 1, dom.red().bold());
            }
            println!("{}", "=========================================================".cyan());
        }
        Commands::Serve { listen } => {
            let addr: SocketAddr = listen.parse()?;
            let socket = UdpSocket::bind(addr).await?;
            println!("{}", "=========================================================".cyan());
            println!("{}", "    SPLIT2OPS CYBERDNS PROXY & SINKHOLE SERVICE ACTIVE   ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Listening on UDP : {}", addr);
            println!(" Upstream DoH     : Cloudflare DNS (1.1.1.1 encrypted)");
            println!(" Sinkhole IP      : 0.0.0.0");
            println!("{}", "---------------------------------------------------------".cyan());

            let mut buf = [0u8; 1024];

            loop {
                let (len, src) = socket.recv_from(&mut buf).await?;
                let req_bytes = &buf[..len];
                let blocklist = load_blocklist();

                if let Some(qname) = extract_qname(req_bytes) {
                    let is_blocked = blocklist.contains(&qname.to_lowercase());
                    if is_blocked {
                        println!("{} {} -> 0.0.0.0 (Sinkhole)", "[CYBERDNS-BLOCK]".red().bold(), qname);
                        let resp = build_dns_response(req_bytes, Some([0, 0, 0, 0]));
                        let _ = socket.send_to(&resp, src).await;
                    } else {
                        match query_doh(&qname).await {
                            Ok(Some(ip_str)) => {
                                if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
                                    println!("{} {} -> {}", "[CYBERDNS-RESOLVE]".green().bold(), qname, ip_str);
                                    let resp = build_dns_response(req_bytes, Some(ipv4.octets()));
                                    let _ = socket.send_to(&resp, src).await;
                                }
                            }
                            _ => {
                                let resp = build_dns_response(req_bytes, None);
                                let _ = socket.send_to(&resp, src).await;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
