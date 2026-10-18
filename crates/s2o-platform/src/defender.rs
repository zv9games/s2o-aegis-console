//! Microsoft Defender queries via PowerShell / MpCmdRun.
#![cfg_attr(not(windows), allow(unused_imports))]

use crate::{cmd, windows_only, PlatformError, PlatformResult};
use std::path::PathBuf;

/// True when Defender reports AntivirusEnabled. False on error or non-Windows.
pub fn is_defender_active() -> bool {
    #[cfg(windows)]
    {
        cmd::powershell("(Get-MpComputerStatus).AntivirusEnabled")
            .map(|s| s.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    false
}

/// Locate MpCmdRun.exe (newest platform folder first, then Program Files).
pub fn find_mp_cmd_run() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let mut candidates = Vec::new();
    if let Ok(pd) = std::env::var("ProgramData") {
        let platform = PathBuf::from(pd).join(r"Microsoft\Windows Defender\Platform");
        if let Ok(rd) = std::fs::read_dir(&platform) {
            let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            dirs.sort();
            dirs.reverse();
            candidates.extend(dirs.into_iter().map(|d| d.join("MpCmdRun.exe")));
        }
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        candidates.push(PathBuf::from(pf).join(r"Windows Defender\MpCmdRun.exe"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn mpcmdrun(args: &[&str]) -> PlatformResult<()> {
    if !cfg!(windows) {
        return windows_only("MpCmdRun");
    }
    let exe = find_mp_cmd_run()
        .ok_or_else(|| PlatformError::Command("MpCmdRun.exe not found".into()))?;
    cmd::run(&exe.to_string_lossy(), args).map(|_| ())
}

/// Defender quick scan (ScanType 1). Blocks until the scan finishes.
pub fn run_scan_native() -> PlatformResult<()> {
    mpcmdrun(&["-Scan", "-ScanType", "1"])
}

pub fn update_defender_native() -> PlatformResult<()> {
    mpcmdrun(&["-SignatureUpdate"])
}
