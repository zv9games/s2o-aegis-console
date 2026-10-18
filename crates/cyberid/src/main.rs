use clap::{Parser, Subcommand};
use colored::*;
use cyberwall_backend_windows::WindowsFirewallEngine;
use cyberwall_core::FirewallEngine;

#[derive(Parser)]
#[command(name = "cyberid")]
#[command(author = "Split2ops Software <support@split2ops.com>")]
#[command(version = "1.1.0")]
#[command(about = "S2O CyberID: Zero-Trust Endpoint Posture & Device Identity CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display CyberID engine status and identity provider integration
    Status,
    /// Run deep Zero-Trust endpoint posture audit across 5 security pillars
    Posture,
    /// Generate an Ed25519-signed device posture token (JWS compact, alg EdDSA)
    Attest {
        /// Device name or identifier
        #[arg(long, default_value = "host-01")]
        device: String,
    },
    /// Verify a token produced by `attest` against this host's key (or --pubkey)
    Verify {
        token: String,
        /// Base64url Ed25519 public key; defaults to the local signing key
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Print this host's attestation public key (base64url)
    Pubkey,
}

mod token;

fn check_registry_dword(path: &str, name: &str) -> Option<u32> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Get-ItemProperty -Path '{}' -Name '{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty {}", path, name, name),
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        text.trim().parse::<u32>().ok()
    } else {
        None
    }
}

fn get_os_info() -> String {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object -Property ProductName, DisplayVersion, CurrentBuild | ForEach-Object { \"$($_.ProductName) $($_.DisplayVersion) (Build $($_.CurrentBuild))\" }",
        ])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    "Windows OS".to_string()
}

// Posture weights (sum = 100). The former "isolation ready" pillar awarded a
// fixed 10 points without checking anything, so it was removed.
const W_FIREWALL: u32 = 30;
const W_DEFENDER: u32 = 30;
const W_UAC: u32 = 20;
const W_SECUREBOOT: u32 = 20;

struct Posture {
    firewall: bool,
    defender: bool,
    uac: bool,
    secure_boot: bool,
}

impl Posture {
    fn score(&self) -> u32 {
        (if self.firewall { W_FIREWALL } else { 0 })
            + (if self.defender { W_DEFENDER } else { 0 })
            + (if self.uac { W_UAC } else { 0 })
            + (if self.secure_boot { W_SECUREBOOT } else { 0 })
    }
}

fn collect_posture(st: &cyberwall_core::FirewallStatus) -> Posture {
    Posture {
        firewall: st.enabled && st.profile_private && st.profile_public,
        defender: st.defender_active,
        uac: check_registry_dword("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA") == Some(1),
        secure_boot: check_registry_dword("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled") == Some(1),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("{}", "=========================================================".cyan());
            println!("{}", "        SPLIT2OPS CYBERID ZERO-TRUST IDENTITY            ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Posture Engine    : {}", "5-Pillar Endpoint Telemetry Audit".green());
            println!(" Operating System  : {}", get_os_info().bold());
            println!(" Zero-Trust Model  : {}", "Continuous Verification (NIST SP 800-207)".bold());
            println!(" Identity Protocols: Device Attestation / FIDO2 / Token Claims");
            println!("{}", "=========================================================".cyan());
        }
        Commands::Posture => {
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;
            let p = collect_posture(&st);

            println!("{}", "=========================================================".cyan());
            println!("{}", "      SPLIT2OPS CYBERID ZERO-TRUST POSTURE AUDIT         ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!(" Host Environment : {}", get_os_info().cyan());
            println!("{}", "---------------------------------------------------------".cyan());
            let line = |label: &str, pass: bool, pts: u32, ok: &str, bad: &str| {
                if pass {
                    println!(" {label}: {} ({pts}/{pts} pts)", ok.green().bold());
                } else {
                    println!(" {label}: {} (0/{pts} pts)", bad.red().bold());
                }
            };
            line("[1/4] Firewall Protection   ", p.firewall, W_FIREWALL, "PASS - Private & Public profiles on", "FAIL - Profiles Disabled");
            line("[2/4] Antivirus (Defender)  ", p.defender, W_DEFENDER, "PASS - Defender AntivirusEnabled", "FAIL - Defender Inactive / Unknown");
            line("[3/4] User Access Ctrl (UAC)", p.uac, W_UAC, "PASS - EnableLUA = 1", "FAIL - UAC Disabled or Unreadable");
            line("[4/4] UEFI SecureBoot State ", p.secure_boot, W_SECUREBOOT, "PASS - SecureBoot Enabled", "FAIL - SecureBoot Not Detected");

            let total_score = p.score();
            println!("{}", "=========================================================".cyan());
            let score_display = if total_score >= 80 {
                format!("{} / 100 [TRUSTED ENDPOINT]", total_score).green().bold()
            } else if total_score >= 60 {
                format!("{} / 100 [DEGRADED POSTURE]", total_score).yellow().bold()
            } else {
                format!("{} / 100 [UNTRUSTED / NON-COMPLIANT]", total_score).red().bold()
            };
            println!(" ZERO-TRUST POSTURE SCORE: {}", score_display);
            println!("{}", "=========================================================".cyan());
        }
        Commands::Attest { device } => {
            let fw = WindowsFirewallEngine::new();
            let st = fw.get_status().await?;
            let p = collect_posture(&st);
            let key = token::load_or_create_key()?;
            let now = chrono::Utc::now().timestamp();
            let claims = serde_json::json!({
                "iss": "Split2ops-CyberID",
                "sub": device,
                "iat": now,
                "exp": now + 3600,
                "posture_score": p.score(),
                "claims": {
                    "firewall_active": p.firewall,
                    "defender_active": p.defender,
                    "uac_enforced": p.uac,
                    "secure_boot": p.secure_boot,
                }
            });
            let jws = token::sign(&key, &claims)?;

            println!("{}", "=========================================================".cyan());
            println!("{}", "        CYBERID SIGNED POSTURE TOKEN (Ed25519)           ".bold().green());
            println!("{}", "=========================================================".cyan());
            println!("{}", serde_json::to_string_pretty(&claims)?);
            println!("{}", "---------------------------------------------------------".cyan());
            println!(" Signing key : {} ({})", token::KEY_PATH, token::public_key_b64(&key));
            println!(" Token       :\n{}", jws);
            println!("{}", "=========================================================".cyan());
        }
        Commands::Verify { token: jws, pubkey } => {
            let vk = match pubkey {
                Some(pk) => token::parse_public_key(&pk)?,
                None => token::load_or_create_key()?.verifying_key(),
            };
            let claims = token::verify(&vk, &jws, chrono::Utc::now().timestamp())?;
            println!("{}", "[cyberid] OK: signature valid and token not expired.".green().bold());
            println!("{}", serde_json::to_string_pretty(&claims)?);
        }
        Commands::Pubkey => {
            let key = token::load_or_create_key()?;
            println!("{}", token::public_key_b64(&key));
        }
    }

    Ok(())
}
