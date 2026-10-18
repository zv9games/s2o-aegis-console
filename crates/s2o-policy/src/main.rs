//! `aegis-policy`: offline admin tool to create keys, approve and verify bundles.

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use s2o_policy::{verify, AdminRoster, SignedBundle};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis-policy",
    version,
    about = "Offline signing tool for S2O Aegis policy bundles"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an admin Ed25519 key (32-byte seed file) and print its public key
    Keygen { out: PathBuf },
    /// Add an approval to a signed-bundle JSON file (creates approvals list if missing)
    Approve {
        bundle: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        key_id: String,
    },
    /// Verify a signed bundle against a roster
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        roster: PathBuf,
        #[arg(long, default_value_t = 0)]
        last_version: u64,
    },
}

fn load_key(p: &PathBuf) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let seed: [u8; 32] = std::fs::read(p)?
        .try_into()
        .map_err(|_| "key file must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            if out.exists() {
                return Err(format!("{} exists", out.display()).into());
            }
            let k = SigningKey::generate(&mut rand::rngs::OsRng);
            std::fs::write(&out, k.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("{}", s2o_policy::public_key_b64(&k));
        }
        Cmd::Approve {
            bundle,
            key,
            key_id,
        } => {
            let mut sb: SignedBundle = serde_json::from_slice(&std::fs::read(&bundle)?)?;
            sb.approve(&key_id, &load_key(&key)?);
            std::fs::write(&bundle, serde_json::to_vec_pretty(&sb)?)?;
            println!("approved by {key_id}; {} approval(s)", sb.approvals.len());
        }
        Cmd::Verify {
            bundle,
            roster,
            last_version,
        } => {
            let sb: SignedBundle = serde_json::from_slice(&std::fs::read(&bundle)?)?;
            let r: AdminRoster = serde_json::from_slice(&std::fs::read(&roster)?)?;
            let v = verify(&sb, &r, last_version)?;
            println!(
                "OK: {} key(s), {} admin(s)",
                v.valid_keys.len(),
                v.distinct_admins
            );
            if let Some(w) = v.warning {
                eprintln!("WARNING: {w}");
            }
        }
    }
    Ok(())
}
