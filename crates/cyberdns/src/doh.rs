//! Encrypted DNS (DoH JSON) with multi-resolver fallback.

use serde::Deserialize;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Default resolvers: Cloudflare primary, Google JSON DoH secondary.
/// Note: Google's JSON API path is `/resolve` (not `/dns-query`).
pub const DEFAULT_DOH_ENDPOINTS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(default)]
    data: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DohResponse {
    Answer: Option<Vec<DohAnswer>>,
}

/// Query A records via DoH JSON, trying endpoints in order until one succeeds.
/// Returns (ips, resolver_url_used).
pub async fn resolve_a(
    domain: &str,
    endpoints: &[String],
) -> Result<(Vec<Ipv4Addr>, String), String> {
    let eps: Vec<String> = if endpoints.is_empty() {
        DEFAULT_DOH_ENDPOINTS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        endpoints.to_vec()
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let mut last_err = String::from("no DoH endpoints");
    for base in &eps {
        let base = base.trim_end_matches('/');
        let url = format!("{base}?name={domain}&type=A");
        match client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
        {
            Ok(res) if res.status().is_success() => {
                match res.json::<DohResponse>().await {
                    Ok(doh) => {
                        let mut out = Vec::new();
                        if let Some(answers) = doh.Answer {
                            for a in answers {
                                if a.record_type == 1 {
                                    if let Ok(ip) = a.data.parse::<Ipv4Addr>() {
                                        out.push(ip);
                                    }
                                }
                            }
                        }
                        return Ok((out, base.to_string()));
                    }
                    Err(e) => last_err = format!("{base}: json {e}"),
                }
            }
            Ok(res) => last_err = format!("{base}: HTTP {}", res.status()),
            Err(e) => last_err = format!("{base}: {e}"),
        }
    }
    Err(last_err)
}

/// Same as resolve_a but returns dotted IP strings (CLI resolve path).
pub async fn resolve_a_strings(
    domain: &str,
    endpoints: &[String],
) -> Result<(Vec<String>, String), String> {
    let (ips, used) = resolve_a(domain, endpoints).await?;
    Ok((ips.into_iter().map(|ip| ip.to_string()).collect(), used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_endpoints_present() {
        assert!(DEFAULT_DOH_ENDPOINTS.len() >= 2);
        assert!(DEFAULT_DOH_ENDPOINTS[0].contains("cloudflare"));
        assert!(DEFAULT_DOH_ENDPOINTS[1].contains("google"));
        assert!(DEFAULT_DOH_ENDPOINTS[1].contains("resolve"));
    }
}
