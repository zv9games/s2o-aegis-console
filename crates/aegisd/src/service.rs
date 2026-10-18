//! Windows service integration (install/uninstall/run under the SCM).
//! Compiled on Windows only; verified by CI build, not on a real host yet.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "S2OAegisAgent";

pub fn install(dir: PathBuf) -> windows_service::Result<()> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe = std::env::current_exe().map_err(windows_service::Error::Winapi)?;
    let info = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from("S2O Aegis Agent"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
            OsString::from("--dir"),
            dir.into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    svc.set_description("S2O Aegis fleet agent (mTLS heartbeat, signed policy)")?;
    Ok(())
}

pub fn uninstall() -> windows_service::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    svc.delete()
}

static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run(dir: PathBuf) -> windows_service::Result<()> {
    let _ = DIR.set(dir);
    service_dispatcher::start(NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else {
        return;
    };
    let status = |state, accept, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let _ = h.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ));
    let dir = DIR
        .get()
        .cloned()
        .unwrap_or_else(crate::agent_cmd::default_dir);
    let code = match tokio::runtime::Runtime::new() {
        Ok(rt) => match rt.block_on(crate::agent_cmd::run(&dir, false, rx)) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(_) => 1,
    };
    let _ = h.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
    ));
}
