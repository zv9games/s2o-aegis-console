//! System resolver takeover (T0/T1-lite) — point OS DNS at local proxy.
//!
//! Windows: `netsh interface ip set dns` with backup/restore.
//! Linux: writes resolv.conf note / optional override with backup (honest limits).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackup {
    pub version: String,
    pub saved_at: String,
    pub os: String,
    pub servers: Vec<String>,
    #[serde(default)]
    pub interfaces: Vec<IfaceBackup>,
    #[serde(default)]
    pub resolv_conf: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceBackup {
    pub name: String,
    pub servers: Vec<String>,
}

#[allow(dead_code)]
pub fn default_backup_path() -> PathBuf {
    PathBuf::from(".aegis/dns-system-backup.json")
}

/// List likely IPv4 interface names (Windows).
pub fn list_windows_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(o) = Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
    {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().skip(3) {
            // Admin State  State  Type  Interface Name
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // last field(s) may be multi-word name
                let name = parts[3..].join(" ");
                if !name.is_empty() {
                    out.push(name);
                }
            }
        }
    }
    out
}

fn parse_windows_dns_for_iface(name: &str) -> Vec<String> {
    let mut servers = Vec::new();
    if let Ok(o) = Command::new("netsh")
        .args(["interface", "ip", "show", "dnsservers", &format!("name={name}")])
        .output()
    {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            let t = line.trim();
            // lines like "   1.1.1.1" or "Statically Configured DNS Servers: 8.8.8.8"
            if let Some(rest) = t.strip_prefix("Statically Configured DNS Servers:") {
                let s = rest.trim();
                if !s.is_empty() && s != "None" {
                    servers.push(s.to_string());
                }
                continue;
            }
            if t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                // IP-looking token
                let ip = t.split_whitespace().next().unwrap_or("");
                if ip.parse::<std::net::Ipv4Addr>().is_ok()
                    || ip.parse::<std::net::Ipv6Addr>().is_ok()
                {
                    servers.push(ip.to_string());
                }
            }
        }
    }
    servers
}

pub fn show_current() -> Result<String, String> {
    if cfg!(windows) {
        let mut report = String::new();
        let ifaces = list_windows_interfaces();
        if ifaces.is_empty() {
            // fallback dump
            if let Ok(o) = Command::new("netsh")
                .args(["interface", "ip", "show", "dnsservers"])
                .output()
            {
                return Ok(String::from_utf8_lossy(&o.stdout).to_string());
            }
            return Err("could not query DNS servers".into());
        }
        for name in ifaces {
            let servers = parse_windows_dns_for_iface(&name);
            report.push_str(&format!(
                "Interface: {name}\n  DNS: {}\n",
                if servers.is_empty() {
                    "(none/dhcp)".into()
                } else {
                    servers.join(", ")
                }
            ));
        }
        Ok(report)
    } else {
        let path = Path::new("/etc/resolv.conf");
        if path.exists() {
            fs::read_to_string(path).map_err(|e| e.to_string())
        } else {
            Err("no /etc/resolv.conf".into())
        }
    }
}

/// Structured OS DNS snapshot for machine-readable consumers.
pub fn show_current_structured() -> Result<serde_json::Value, String> {
    if cfg!(windows) {
        let ifaces = list_windows_interfaces();
        if ifaces.is_empty() {
            let raw = if let Ok(o) = Command::new("netsh")
                .args(["interface", "ip", "show", "dnsservers"])
                .output()
            {
                String::from_utf8_lossy(&o.stdout).to_string()
            } else {
                String::new()
            };
            return Ok(serde_json::json!({
                "os": "windows",
                "interfaces": [],
                "raw": raw,
            }));
        }
        let rows: Vec<_> = ifaces
            .into_iter()
            .map(|name| {
                let servers = parse_windows_dns_for_iface(&name);
                serde_json::json!({
                    "name": name,
                    "servers": servers,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "os": "windows",
            "interfaces": rows,
        }))
    } else {
        let path = Path::new("/etc/resolv.conf");
        if !path.exists() {
            return Err("no /etc/resolv.conf".into());
        }
        let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut servers = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("nameserver") {
                let s = rest.trim();
                if !s.is_empty() {
                    servers.push(s.to_string());
                }
            }
        }
        Ok(serde_json::json!({
            "os": "unix",
            "resolv_conf": path.display().to_string(),
            "servers": servers,
            "raw": text,
        }))
    }
}

pub fn backup_current(path: &Path) -> Result<DnsBackup, String> {
    let mut backup = DnsBackup {
        version: "0.1.0".into(),
        saved_at: chrono::Utc::now().to_rfc3339(),
        os: if cfg!(windows) {
            "windows".into()
        } else {
            "unix".into()
        },
        servers: Vec::new(),
        interfaces: Vec::new(),
        resolv_conf: None,
    };
    if cfg!(windows) {
        for name in list_windows_interfaces() {
            let servers = parse_windows_dns_for_iface(&name);
            for s in &servers {
                if !backup.servers.contains(s) {
                    backup.servers.push(s.clone());
                }
            }
            backup.interfaces.push(IfaceBackup { name, servers });
        }
    } else {
        let resolv = Path::new("/etc/resolv.conf");
        if resolv.exists() {
            let text = fs::read_to_string(resolv).map_err(|e| e.to_string())?;
            for line in text.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("nameserver ") {
                    let s = rest.trim().to_string();
                    if !s.is_empty() {
                        backup.servers.push(s);
                    }
                }
            }
            backup.resolv_conf = Some(text);
        }
    }
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(backup)
}

/// Point system DNS at `server` (e.g. 127.0.0.1). Saves backup first.
pub fn set_system_dns(
    server: &str,
    interface: Option<&str>,
    backup_path: &Path,
) -> Result<String, String> {
    let _ = backup_current(backup_path)?;
    if cfg!(windows) {
        let ifaces: Vec<String> = if let Some(i) = interface {
            vec![i.to_string()]
        } else {
            // Prefer Connected interfaces
            let all = list_windows_interfaces();
            if all.is_empty() {
                return Err("no interfaces found".into());
            }
            all
        };
        let mut applied = Vec::new();
        for name in ifaces {
            let st = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dnsservers",
                    &format!("name={name}"),
                    "static",
                    server,
                    "primary",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if st.status.success() {
                applied.push(name);
            } else {
                let err = String::from_utf8_lossy(&st.stderr);
                // continue other ifaces
                if !err.trim().is_empty() {
                    eprintln!("[cyberdns] netsh {name}: {err}");
                }
            }
        }
        if applied.is_empty() {
            return Err(
                "netsh failed for all interfaces (try elevated shell / --interface)".into(),
            );
        }
        Ok(format!(
            "set DNS={server} on {} interface(s); backup {}",
            applied.len(),
            backup_path.display()
        ))
    } else {
        // Linux: only touch resolv.conf if writable; otherwise print instructions
        let resolv = Path::new("/etc/resolv.conf");
        let content = format!(
            "# Managed by S2O CyberDNS system-dns — restore via cyberdns system-dns restore\nnameserver {server}\n"
        );
        match fs::write(resolv, &content) {
            Ok(()) => Ok(format!(
                "wrote nameserver {server} to /etc/resolv.conf; backup {}",
                backup_path.display()
            )),
            Err(e) => Err(format!(
                "cannot write /etc/resolv.conf ({e}). Run as root, or configure NetworkManager/systemd-resolved to {server}"
            )),
        }
    }
}

pub fn restore_system_dns(backup_path: &Path) -> Result<String, String> {
    if !backup_path.exists() {
        return Err(format!("no backup at {}", backup_path.display()));
    }
    let text = fs::read_to_string(backup_path).map_err(|e| e.to_string())?;
    let backup: DnsBackup = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if cfg!(windows) {
        if backup.interfaces.is_empty() {
            // dhcp all known
            for name in list_windows_interfaces() {
                let _ = Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "dnsservers",
                        &format!("name={name}"),
                        "dhcp",
                    ])
                    .status();
            }
            return Ok("restored DNS to DHCP on interfaces (no per-iface backup)".into());
        }
        let mut n = 0;
        for iface in &backup.interfaces {
            if iface.servers.is_empty() {
                let _ = Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "dnsservers",
                        &format!("name={}", iface.name),
                        "dhcp",
                    ])
                    .status();
                n += 1;
                continue;
            }
            // first server primary, rest index=
            let primary = &iface.servers[0];
            let st = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dnsservers",
                    &format!("name={}", iface.name),
                    "static",
                    primary,
                    "primary",
                ])
                .status()
                .map_err(|e| e.to_string())?;
            if st.success() {
                n += 1;
            }
            for (i, s) in iface.servers.iter().skip(1).enumerate() {
                let _ = Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "add",
                        "dnsservers",
                        &format!("name={}", iface.name),
                        s,
                        &format!("index={}", i + 2),
                    ])
                    .status();
            }
        }
        Ok(format!("restored DNS on {n} interface(s) from backup"))
    } else if let Some(ref conf) = backup.resolv_conf {
        fs::write("/etc/resolv.conf", conf).map_err(|e| e.to_string())?;
        Ok("restored /etc/resolv.conf from backup".into())
    } else {
        Err("backup has no resolv.conf payload".into())
    }
}
