//! Windows Service Control Manager entry for aegisd (T1 packaging).
//!
//! SCM launches: `aegisd.exe --run-as-service [start args…]`
//! Interactive use remains: `aegisd start …`

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

pub const SERVICE_NAME: &str = "S2OAegisd";

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Last-resort log next to the binary when possible
        let _ = std::fs::write(
            std::env::temp_dir().join("s2o-aegisd-service-error.txt"),
            format!("{e:?}"),
        );
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let (event_log, health_bind, no_health, fleet, fleet_policy, mesh_peers, jwks) =
        service_start_config();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let stop = async move {
        // Bridge blocking SCM channel into async
        loop {
            match shutdown_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    };

    let run = crate::run_daemon(
        event_log,
        health_bind,
        no_health,
        true,
        fleet,
        fleet_policy,
        mesh_peers,
        jwks,
    );
    rt.block_on(async {
        tokio::select! {
            r = run => { let _ = r; }
            _ = stop => {}
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Parse start-like flags from the process command line after `--run-as-service`.
fn service_start_config() -> (PathBuf, String, bool, PathBuf, PathBuf, PathBuf, PathBuf) {
    let args: Vec<String> = std::env::args().collect();
    let mut event_log = default_event_log();
    let mut health_bind = "127.0.0.1:9090".to_string();
    let mut no_health = false;
    let mut fleet = default_fleet_path();
    let mut fleet_policy = default_fleet_policy_path();
    let mut mesh_peers = default_mesh_peers_path();
    let mut jwks = default_jwks_path();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--event-log" => {
                if let Some(v) = args.get(i + 1) {
                    event_log = PathBuf::from(v);
                    i += 1;
                }
            }
            "--health-bind" => {
                if let Some(v) = args.get(i + 1) {
                    health_bind = v.clone();
                    i += 1;
                }
            }
            "--fleet" => {
                if let Some(v) = args.get(i + 1) {
                    fleet = PathBuf::from(v);
                    i += 1;
                }
            }
            "--fleet-policy" => {
                if let Some(v) = args.get(i + 1) {
                    fleet_policy = PathBuf::from(v);
                    i += 1;
                }
            }
            "--mesh-peers" => {
                if let Some(v) = args.get(i + 1) {
                    mesh_peers = PathBuf::from(v);
                    i += 1;
                }
            }
            "--jwks" => {
                if let Some(v) = args.get(i + 1) {
                    jwks = PathBuf::from(v);
                    i += 1;
                }
            }
            "--no-health" => no_health = true,
            _ => {}
        }
        i += 1;
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_EVENT_LOG") {
        if !v.is_empty() {
            event_log = PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_HEALTH_BIND") {
        if !v.is_empty() {
            health_bind = v;
        }
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_FLEET") {
        if !v.is_empty() {
            fleet = PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_FLEET_POLICY") {
        if !v.is_empty() {
            fleet_policy = PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_MESH_PEERS") {
        if !v.is_empty() {
            mesh_peers = PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("S2O_AEGIS_JWKS") {
        if !v.is_empty() {
            jwks = PathBuf::from(v);
        }
    }
    (
        event_log,
        health_bind,
        no_health,
        fleet,
        fleet_policy,
        mesh_peers,
        jwks,
    )
}

fn default_event_log() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base)
            .join("S2O")
            .join("Aegis")
            .join("data")
            .join("events.jsonl");
    }
    PathBuf::from(r"C:\ProgramData\S2O\Aegis\events.jsonl")
}

fn default_fleet_path() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base)
            .join("S2O")
            .join("Aegis")
            .join("data")
            .join("fleet.json");
    }
    PathBuf::from(r"C:\ProgramData\S2O\Aegis\fleet.json")
}

fn default_fleet_policy_path() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base)
            .join("S2O")
            .join("Aegis")
            .join("data")
            .join("fleet-policy.json");
    }
    PathBuf::from(r"C:\ProgramData\S2O\Aegis\fleet-policy.json")
}

fn default_mesh_peers_path() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base)
            .join("S2O")
            .join("Aegis")
            .join("data")
            .join("mesh-peers.json");
    }
    PathBuf::from(r"C:\ProgramData\S2O\Aegis\mesh-peers.json")
}

fn default_jwks_path() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base)
            .join("S2O")
            .join("Aegis")
            .join("data")
            .join("jwt")
            .join("jwks.json");
    }
    PathBuf::from(r"C:\ProgramData\S2O\Aegis\jwt\jwks.json")
}
