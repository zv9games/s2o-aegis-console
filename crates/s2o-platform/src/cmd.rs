#![allow(dead_code)]
use crate::{PlatformError, PlatformResult};
use std::process::Command;

/// Run a command (hidden console window on Windows) and return stdout.
pub(crate) fn run(program: &str, args: &[&str]) -> PlatformResult<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd
        .output()
        .map_err(|e| PlatformError::Command(format!("{program}: {e}")))?;
    if !out.status.success() {
        return Err(PlatformError::Command(format!(
            "{program} exited with {}: {} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub(crate) fn powershell(script: &str) -> PlatformResult<String> {
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

/// ConvertTo-Json emits a bare object for a single item; normalise to a list.
pub(crate) fn json_list(text: &str) -> PlatformResult<Vec<serde_json::Value>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| PlatformError::Parse(e.to_string()))?;
    Ok(match v {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    })
}
