use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRoute {
    pub name: String,
    /// Path prefix on the gate listener (e.g. `/app` or `/`)
    pub path_prefix: String,
    /// Upstream base URL (e.g. `http://127.0.0.1:8080`)
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    pub listen: String,
    pub min_score: u32,
    pub routes: Vec<GateRoute>,
    /// When non-empty, only these IPs / CIDRs may connect (exact IPv4/IPv6 or a.b.c.d/nn)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_ips: Vec<String>,
    /// Max requests per client IP per rolling minute; 0 = disabled
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rate_limit_per_minute: u32,
    /// When true with sessions, reject sessions whose mint posture < min_score
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enforce_session_posture: bool,
    /// Preferred auth flag from policy pack (CLI --require-session still wins at runtime)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_session: bool,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

pub fn default_config() -> GateConfig {
    GateConfig {
        listen: "127.0.0.1:18443".into(),
        min_score: 50,
        routes: vec![GateRoute {
            name: "demo".into(),
            path_prefix: "/".into(),
            upstream: "https://example.com".into(),
        }],
        allow_ips: vec![],
        rate_limit_per_minute: 0,
        enforce_session_posture: false,
        require_session: false,
    }
}

pub fn load_config(path: &Path) -> Result<GateConfig, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_config(path: &Path, cfg: &GateConfig) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

impl GateConfig {
    pub fn match_route(&self, path: &str) -> Option<&GateRoute> {
        let mut best: Option<&GateRoute> = None;
        let mut best_len = 0usize;
        for r in &self.routes {
            let prefix = if r.path_prefix.is_empty() {
                "/"
            } else {
                r.path_prefix.as_str()
            };
            if path == prefix || path.starts_with(prefix) || (prefix == "/" && path.starts_with('/'))
            {
                let len = prefix.len();
                if len >= best_len {
                    best_len = len;
                    best = Some(r);
                }
            }
        }
        best
    }

    /// Empty allow_ips = allow all. Supports exact IP or IPv4/IPv6 CIDR (std-only).
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        if self.allow_ips.is_empty() {
            return true;
        }
        self.allow_ips.iter().any(|entry| cidr_or_ip_matches(entry, ip))
    }
}

fn cidr_or_ip_matches(entry: &str, ip: IpAddr) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    if let Some((net, bits)) = entry.split_once('/') {
        let Ok(net_ip) = IpAddr::from_str(net.trim()) else {
            return false;
        };
        let Ok(prefix) = bits.trim().parse::<u8>() else {
            return false;
        };
        return ip_in_cidr(ip, net_ip, prefix);
    }
    IpAddr::from_str(entry).map(|a| a == ip).unwrap_or(false)
}

fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix > 128 {
                return false;
            }
            let a = u128::from(a);
            let n = u128::from(n);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (a & mask) == (n & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allow_all_when_empty() {
        let cfg = default_config();
        assert!(cfg.ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn allow_exact_and_cidr() {
        let mut cfg = default_config();
        cfg.allow_ips = vec!["10.0.0.5".into(), "192.168.0.0/16".into()];
        assert!(cfg.ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!cfg.ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
        assert!(cfg.ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9))));
        assert!(!cfg.ip_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }
}
