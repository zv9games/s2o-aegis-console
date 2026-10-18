//! `aegis-audit verify <log.jsonl> [--head head.json --pubkey <b64url>]`

use base64::Engine;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis-audit",
    version,
    about = "Verify S2O Aegis hash-chained audit logs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify chain integrity (and optionally a signed head to detect truncation)
    Verify {
        log: PathBuf,
        #[arg(long, requires = "pubkey")]
        head: Option<PathBuf>,
        /// Pinned base64url Ed25519 key that signs heads
        #[arg(long)]
        pubkey: Option<String>,
    },
}

fn main() {
    let Cmd::Verify { log, head, pubkey } = Cli::parse().cmd;
    let res = (|| -> Result<usize, Box<dyn std::error::Error>> {
        let entries = s2o_audit::read_file(&log)?;
        match (head, pubkey) {
            (Some(h), Some(pk)) => {
                let head: s2o_audit::SignedHead = serde_json::from_slice(&std::fs::read(h)?)?;
                let raw: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(pk.trim())?
                    .try_into()
                    .map_err(|_| "pubkey must be 32 bytes")?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
                s2o_audit::verify_against_head(&entries, &head, &vk)?;
            }
            _ => s2o_audit::verify_entries(&entries)?,
        }
        Ok(entries.len())
    })();
    match res {
        Ok(n) => println!("OK: {n} entries, chain intact"),
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}
