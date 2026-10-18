//! Active TCP socket enumeration.
//!
//! * Windows: parses `netstat -ano -p TCP` / `-p TCPv6` (owner PID included).
//! * Linux: parses `/proc/net/tcp{,6}` and maps socket inodes to PIDs via
//!   `/proc/<pid>/fd` (PIDs owned by other users need root).
//! * Elsewhere: returns an empty list; see [`telemetry_source`].

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Owning process id, 0 when unknown.
    pub pid: u32,
    /// Normalised state, e.g. "ESTABLISHED", "LISTEN", "TIME_WAIT".
    pub state: String,
}

/// Human-readable description of where connection data comes from.
pub fn telemetry_source() -> &'static str {
    if cfg!(windows) {
        "netstat -ano (TCP/TCPv6, owner PID)"
    } else if cfg!(target_os = "linux") {
        "/proc/net/tcp{,6} + /proc/<pid>/fd inode mapping"
    } else {
        "unavailable on this OS"
    }
}

pub fn get_active_tcp_connections() -> Vec<ActiveConnection> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        for proto in ["TCP", "TCPv6"] {
            if let Ok(text) = crate::cmd::run("netstat", &["-ano", "-p", proto]) {
                out.extend(parse_netstat(&text));
            }
        }
        out
    }
    #[cfg(target_os = "linux")]
    {
        linux::connections()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Vec::new()
    }
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let idx = s.rfind(':')?;
    let port = s[idx + 1..].parse().ok()?;
    let host = s[..idx].trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port))
}

/// Parse Windows `netstat -ano` output.
pub fn parse_netstat(text: &str) -> Vec<ActiveConnection> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 5 || !f[0].starts_with("TCP") {
                return None;
            }
            let (la, lp) = split_host_port(f[1])?;
            let (ra, rp) = split_host_port(f[2])?;
            let state = match f[3] {
                "LISTENING" => "LISTEN".to_string(),
                s => s.to_string(),
            };
            Some(ActiveConnection {
                local_addr: la,
                local_port: lp,
                remote_addr: ra,
                remote_port: rp,
                pid: f[4].parse().unwrap_or(0),
                state,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::ActiveConnection;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const STATES: [&str; 12] = [
        "UNKNOWN",
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING",
    ];

    fn inode_pid_map() -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return map;
        };
        for p in procs.flatten() {
            let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    let l = link.to_string_lossy();
                    if let Some(n) = l.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                        if let Ok(inode) = n.parse() {
                            map.insert(inode, pid);
                        }
                    }
                }
            }
        }
        map
    }

    pub(super) fn parse_addr(hex: &str) -> Option<(String, u16)> {
        let (a, p) = hex.split_once(':')?;
        let port = u16::from_str_radix(p, 16).ok()?;
        let addr = match a.len() {
            8 => Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.swap_bytes()).to_string(),
            32 => {
                let mut bytes = [0u8; 16];
                for w in 0..4 {
                    let word = u32::from_str_radix(&a[w * 8..w * 8 + 8], 16).ok()?;
                    bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                Ipv6Addr::from(bytes).to_string()
            }
            _ => return None,
        };
        Some((addr, port))
    }

    pub(super) fn connections() -> Vec<ActiveConnection> {
        let pids = inode_pid_map();
        let mut out = Vec::new();
        for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let (Some((la, lp)), Some((ra, rp))) = (parse_addr(f[1]), parse_addr(f[2])) else {
                    continue;
                };
                let st = usize::from_str_radix(f[3], 16).unwrap_or(0);
                let inode: u64 = f[9].parse().unwrap_or(0);
                out.push(ActiveConnection {
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    pid: pids.get(&inode).copied().unwrap_or(0),
                    state: STATES.get(st).unwrap_or(&"UNKNOWN").to_string(),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netstat_lines() {
        let text = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1032\n  TCP    [::1]:49670            [::1]:49671            ESTABLISHED     4412\n";
        let c = parse_netstat(text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].local_port, 135);
        assert_eq!(c[0].state, "LISTEN");
        assert_eq!(c[0].pid, 1032);
        assert_eq!(c[1].local_addr, "::1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_addr() {
        assert_eq!(
            linux::parse_addr("0100007F:0050"),
            Some(("127.0.0.1".to_string(), 80))
        );
    }
}
