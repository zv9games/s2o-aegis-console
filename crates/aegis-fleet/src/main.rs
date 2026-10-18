//! `aegis-fleet`: self-hosted fleet server (embedded SQLite).

use aegis_fleet::{ca::FleetCa, server::FleetServer, store::Store};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "aegis-fleet",
    version,
    about = "S2O Aegis self-hosted fleet server (enrollment + mTLS heartbeat)"
)]
struct Cli {
    /// Data directory (CA, server cert, fleet.db). Keep it private.
    #[arg(long, default_value = ".aegis-fleet")]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the fleet CA and server certificate
    Init {
        /// DNS names / IPs agents will use to reach this server
        #[arg(long, required = true)]
        name: Vec<String>,
    },
    /// Create a one-time enrollment token
    Token {
        /// Token lifetime in hours (default 24, single use)
        #[arg(long, default_value_t = 24)]
        ttl_hours: i64,
    },
    /// Show or change fleet settings
    Settings {
        /// Require hardware-backed (TPM) agent keys for new enrollments
        #[arg(long)]
        require_tpm: Option<bool>,
    },
    /// Run the server
    Serve {
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: String,
        /// Client certificate lifetime in hours
        #[arg(long, default_value_t = 24)]
        cert_ttl_hours: i64,
        /// Offline grace period in days (renew with an expired cert)
        #[arg(long, default_value_t = 7)]
        grace_days: i64,
    },
    /// List enrolled agents
    Agents,
    /// Revoke an agent (its heartbeats are rejected)
    Revoke { agent_id: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let dir = cli.dir;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    match cli.cmd {
        Cmd::Init { name } => {
            if dir.join("ca.key").exists() {
                return Err(format!("{} already initialised", dir.display()).into());
            }
            let ca = FleetCa::generate(&name[0])?;
            ca.save(&dir)?;
            let (cert, key) = ca.issue_server_cert(&name)?;
            std::fs::write(dir.join("server.pem"), cert)?;
            std::fs::write(dir.join("server.key"), &key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    dir.join("server.key"),
                    std::fs::Permissions::from_mode(0o600),
                )?;
            }
            Store::open(&dir.join("fleet.db"))?;
            println!("Initialised {}", dir.display());
            println!("CA fingerprint (SHA-256): {}", ca.fingerprint());
            println!(
                "Distribute {} to agents with their enrollment token.",
                dir.join("ca.pem").display()
            );
        }
        Cmd::Token { ttl_hours } => {
            let store = Store::open(&dir.join("fleet.db"))?;
            let t = store.create_token(now, ttl_hours * 3600)?;
            let ca = FleetCa::load(&dir)?;
            println!("token: {t}");
            println!("expires in {ttl_hours} h, single use");
            println!("ca fingerprint: {}", ca.fingerprint());
        }
        Cmd::Settings { require_tpm } => {
            let store = Store::open(&dir.join("fleet.db"))?;
            if let Some(v) = require_tpm {
                store.set_setting("require_hardware_keys", if v { "true" } else { "false" })?;
            }
            println!("require_tpm: {}", store.require_hardware_keys()?);
        }
        Cmd::Serve {
            listen,
            cert_ttl_hours,
            grace_days,
        } => {
            let ca = Arc::new(FleetCa::load(&dir)?);
            let store = Arc::new(Store::open(&dir.join("fleet.db"))?);
            let srv = Arc::new(FleetServer::new(
                ca,
                store,
                &std::fs::read_to_string(dir.join("server.pem"))?,
                &std::fs::read_to_string(dir.join("server.key"))?,
                aegis_fleet::policy::FleetPolicy {
                    cert_ttl: time::Duration::hours(cert_ttl_hours),
                    renew_after: time::Duration::hours(cert_ttl_hours) / 2,
                    offline_grace: time::Duration::days(grace_days),
                    ..Default::default()
                },
            )?);
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            println!("aegis-fleet listening on {listen} (mTLS)");
            srv.serve(listener).await?;
        }
        Cmd::Agents => {
            let store = Store::open(&dir.join("fleet.db"))?;
            let agents = store.list_agents()?;
            let software = agents.iter().filter(|a| !a.hardware_backed).count();
            println!("{}", serde_json::to_string_pretty(&agents)?);
            if software > 0 {
                eprintln!("WARNING: {software} agent(s) use software keys (not TPM-backed)");
            }
        }
        Cmd::Revoke { agent_id } => {
            let store = Store::open(&dir.join("fleet.db"))?;
            if store.revoke(&agent_id)? {
                println!("revoked {agent_id}");
            } else {
                return Err(format!("no such agent {agent_id}").into());
            }
        }
    }
    Ok(())
}
