//! `aegisd enroll` / `aegisd agent`: fleet agent built on `aegis_fleet::runtime`.

use aegis_fleet::keystore::{AgentKeyStore, SoftwareKeyStore};
use aegis_fleet::policy::FleetPolicy;
use aegis_fleet::runtime::{enroll_new, AgentState, EnrollParams, TickOutcome};
use cyberwall_core::FirewallEngine;
use std::path::{Path, PathBuf};

pub type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn default_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\S2O\Aegis\agent")
    } else {
        PathBuf::from("/var/lib/aegis-agent")
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub struct EnrollArgs {
    pub dir: PathBuf,
    pub server: String,
    pub server_name: String,
    pub ca: PathBuf,
    pub ca_fingerprint: String,
    pub token: String,
    pub roster: PathBuf,
}

pub async fn enroll(a: EnrollArgs) -> Res<()> {
    let state_path = a.dir.join("state.json");
    if state_path.exists() {
        return Err(format!("{} exists; already enrolled", state_path.display()).into());
    }
    std::fs::create_dir_all(&a.dir)?;
    let keys = SoftwareKeyStore::load_or_create(&a.dir.join("agent.key"))?;
    let cid = s2o_attest::load_or_create_key_at(&a.dir.join("cyberid.key"))?;
    let ca_pem = std::fs::read_to_string(&a.ca)?;
    let roster: s2o_policy::AdminRoster =
        serde_json::from_str(&std::fs::read_to_string(&a.roster)?)?;
    let host = crate::hostname();
    let st = enroll_new(
        EnrollParams {
            server_addr: &a.server,
            server_name: &a.server_name,
            ca_pem: &ca_pem,
            ca_fingerprint: &a.ca_fingerprint,
            token: &a.token,
            hostname: &host,
            cyberid_public_key: &s2o_attest::public_key_b64(&cid),
            roster,
        },
        &keys,
        now(),
    )
    .await?;
    st.save(&state_path)?;
    println!(
        "enrolled as {} (cert valid until {})",
        st.agent_id, st.not_after_unix
    );
    if !keys.is_hardware_backed() {
        eprintln!("WARNING: agent key is a software key (TPM-backed keys not implemented yet)");
    }
    Ok(())
}

async fn posture() -> serde_json::Value {
    let fw = cyberwall_backend_windows::WindowsFirewallEngine::new();
    match fw.get_status().await {
        Ok(s) => serde_json::json!({
            "firewall_enabled": s.enabled,
            "profile_private": s.profile_private,
            "profile_public": s.profile_public,
            "profile_domain": s.profile_domain,
            "defender_active": s.defender_active,
        }),
        Err(e) => serde_json::json!({"probe_error": e.to_string()}),
    }
}

/// Run the agent loop until `stop` resolves (or forever with `once = false`).
pub async fn run(dir: &Path, once: bool, stop: tokio::sync::watch::Receiver<bool>) -> Res<()> {
    let state_path = dir.join("state.json");
    let mut st = AgentState::load(&state_path)?;
    let keys = SoftwareKeyStore::load_or_create(&dir.join("agent.key"))?;
    let cid = s2o_attest::load_or_create_key_at(&dir.join("cyberid.key"))?;
    let policy = FleetPolicy::default();
    let mut stop = stop;
    loop {
        let p = posture().await;
        let token = s2o_attest::sign(
            &cid,
            &serde_json::json!({"sub": st.agent_id, "exp": now() + 300, "posture": p}),
        )?;
        #[cfg(windows)]
        let fw: Option<&dyn aegis_fleet::fw::AegisFirewall> =
            Some(&aegis_fleet::fw::windows::WindowsAegisFirewall);
        // Linux: firewall enforcement is not implemented (never flush nft).
        #[cfg(not(windows))]
        let fw: Option<&dyn aegis_fleet::fw::AegisFirewall> = None;
        match st.tick_with(&keys, &policy, p, &token, now(), fw).await {
            Ok(TickOutcome::Ok { renewed, results }) => {
                if renewed {
                    println!("[aegisd] certificate renewed");
                }
                for r in results {
                    println!(
                        "[aegisd] policy v{}: {:?} {}",
                        r.version, r.status, r.detail
                    );
                }
            }
            Ok(TickOutcome::Offline { error }) => {
                eprintln!("[aegisd] fleet server unreachable (within grace): {error}")
            }
            Ok(TickOutcome::ReenrollRequired) => {
                st.save(&state_path)?;
                return Err("certificate expired beyond offline grace; re-enroll this host".into());
            }
            Err(e) => eprintln!("[aegisd] heartbeat error: {e}"),
        }
        st.save(&state_path)?;
        if once {
            return Ok(());
        }
        let wait = std::time::Duration::from_secs(st.next_wake_secs(now()));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.changed() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}
