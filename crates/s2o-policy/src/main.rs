//! `aegis-policy`: offline admin tool. Keys are passphrase-encrypted files;
//! keep them off the fleet server. The passphrase is read from the terminal,
//! or from AEGIS_ADMIN_PASSPHRASE for scripted use.

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use s2o_policy::keyfile::KeyFile;
use s2o_policy::signer::PolicySigner;
use s2o_policy::{verify, ActionClass, AdminKeyEntry, AdminRoster, PolicyBundle, SignedBundle};
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
    /// Generate an encrypted admin key file and print its roster entry
    Keygen {
        out: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        admin: String,
    },
    /// Create an unsigned bundle file
    New {
        out: PathBuf,
        #[arg(long)]
        version: u64,
        #[arg(long, value_parser = parse_class)]
        action: ActionClass,
        /// JSON body
        #[arg(long)]
        body: String,
    },
    /// Add an approval to a bundle file using an encrypted key file
    Approve {
        bundle: PathBuf,
        #[arg(long)]
        key: PathBuf,
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

fn parse_class(s: &str) -> Result<ActionClass, String> {
    serde_json::from_value(serde_json::Value::String(s.into())).map_err(|_| {
        "unknown action; one of: normal, isolate_host, run_script, uninstall, change_roster, change_firewall, change_require_tpm, rotate_ca".to_string()
    })
}

fn passphrase(confirm: bool) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(p) = std::env::var("AEGIS_ADMIN_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Admin key passphrase: ")?;
    if confirm && rpassword::prompt_password("Repeat passphrase: ")? != p {
        return Err("passphrases do not match".into());
    }
    Ok(p)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Keygen { out, key_id, admin } => {
            if out.exists() {
                return Err(format!("{} exists", out.display()).into());
            }
            let k = SigningKey::generate(&mut rand::rngs::OsRng);
            let kf = KeyFile::encrypt(&key_id, &k, &passphrase(true)?)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&kf)?)?;
            let entry = AdminKeyEntry {
                key_id,
                admin,
                public_key: kf.public_key.clone(),
            };
            println!("{}", serde_json::to_string_pretty(&entry)?);
            eprintln!(
                "Add the entry above to the roster. Keep {} off the fleet server.",
                out.display()
            );
        }
        Cmd::New {
            out,
            version,
            action,
            body,
        } => {
            let sb = SignedBundle::new(PolicyBundle {
                version,
                action,
                issued_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs() as i64,
                targets: vec![],
                body: serde_json::from_str(&body)?,
            });
            std::fs::write(&out, serde_json::to_vec_pretty(&sb)?)?;
        }
        Cmd::Approve { bundle, key } => {
            let mut sb: SignedBundle = serde_json::from_slice(&std::fs::read(&bundle)?)?;
            let kf: KeyFile = serde_json::from_slice(&std::fs::read(&key)?)?;
            let signer = kf.decrypt(&passphrase(false)?)?;
            sb.approve_with(&signer);
            std::fs::write(&bundle, serde_json::to_vec_pretty(&sb)?)?;
            println!(
                "approved by {}; {} approval(s)",
                signer.key_id(),
                sb.approvals.len()
            );
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
