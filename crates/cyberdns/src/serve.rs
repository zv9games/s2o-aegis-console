//! Local UDP DNS proxy: blocklist → NXDOMAIN, else DoH A records (multi-resolver).

use crate::blocklist::{is_allowed, is_blocked, load_blocklist, normalize_domain};
use crate::doh;
use simple_dns::rdata::{RData, A};
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, QTYPE, RCODE, TYPE};
use s2o_ioc::{IocKind, IocStore};
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Live counters for the UDP DNS proxy.
#[derive(Default)]
pub struct ProxyStats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub allowed: AtomicU64,
    pub allowlisted: AtomicU64,
    pub doh_ok: AtomicU64,
    pub doh_fail: AtomicU64,
    pub doh_fallback: AtomicU64,
    pub other_qtype: AtomicU64,
    pub encode_err: AtomicU64,
}

impl ProxyStats {
    pub fn snapshot_line(&self) -> String {
        format!(
            "queries={} blocked={} allowlisted={} allowed={} doh_ok={} doh_fail={} doh_fallback={} other_qtype={} encode_err={}",
            self.queries.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.allowlisted.load(Ordering::Relaxed),
            self.allowed.load(Ordering::Relaxed),
            self.doh_ok.load(Ordering::Relaxed),
            self.doh_fail.load(Ordering::Relaxed),
            self.doh_fallback.load(Ordering::Relaxed),
            self.other_qtype.load(Ordering::Relaxed),
            self.encode_err.load(Ordering::Relaxed),
        )
    }
}

fn load_deny_set(blocklist_path: &Path, ioc_path: &Path) -> BTreeSet<String> {
    let mut set = load_blocklist(blocklist_path).unwrap_or_default();
    if let Ok(ioc) = IocStore::load(ioc_path) {
        for e in ioc.entries {
            if e.kind == IocKind::Domain {
                set.insert(e.value);
            }
        }
    }
    set
}

fn load_allow_set(allowlist_path: &Path) -> BTreeSet<String> {
    crate::blocklist::load_allowlist(allowlist_path).unwrap_or_default()
}

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit_dns(
    event_log: &Path,
    action: EventAction,
    severity: Severity,
    message: &str,
    domain: &str,
    resolver: Option<&str>,
) {
    if let Ok(store) = EventStore::open(event_log) {
        let mut ev = AegisEvent::new(
            host_id(),
            ProductId::CyberDns,
            EventKind::Dns,
            action,
            severity,
            message,
        )
        .with_attr("domain", serde_json::json!(domain))
        .with_attr("source", serde_json::json!("proxy"))
        .with_ioc(Ioc::Domain(normalize_domain(domain)));
        if let Some(r) = resolver {
            ev = ev.with_attr("doh_resolver", serde_json::json!(r));
        }
        let _ = store.append(&ev);
    }
}

fn qname_to_string(name: &Name<'_>) -> String {
    name.to_string().trim_end_matches('.').to_ascii_lowercase()
}

fn copy_questions(query: &Packet<'_>) -> Vec<Question<'static>> {
    query
        .questions
        .iter()
        .map(|q| q.clone().into_owned())
        .collect()
}

fn build_with_rcode(
    query: &Packet<'_>,
    rcode: RCODE,
    answers: &[(String, Ipv4Addr)],
) -> Result<Vec<u8>, String> {
    let mut packet = Packet::new_reply(query.id());
    packet.set_flags(
        PacketFlag::RESPONSE | PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE,
    );
    *packet.rcode_mut() = rcode;
    packet.questions = copy_questions(query);

    if matches!(rcode, RCODE::NoError) {
        for (name, ip) in answers {
            let n = Name::new_unchecked(name).into_owned();
            packet.answers.push(simple_dns::ResourceRecord::new(
                n,
                CLASS::IN,
                60,
                RData::A(A {
                    address: u32::from(*ip),
                }),
            ));
        }
    }

    packet
        .build_bytes_vec()
        .map_err(|e| format!("encode dns: {e:?}"))
}

pub async fn run_proxy(
    listen: &str,
    blocklist_path: &Path,
    allowlist_path: &Path,
    ioc_path: &Path,
    event_log: &Path,
    stats_interval_secs: u64,
    doh_endpoints: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let set = Arc::new(RwLock::new(load_deny_set(blocklist_path, ioc_path)));
    let allow = Arc::new(RwLock::new(load_allow_set(allowlist_path)));
    let stats = Arc::new(ProxyStats::default());
    let blocklist_path = blocklist_path.to_path_buf();
    let allowlist_path = allowlist_path.to_path_buf();
    let ioc_path = ioc_path.to_path_buf();
    let event_log = event_log.to_path_buf();

    let sock = UdpSocket::bind(listen).await?;
    let doh_eps = if doh_endpoints.is_empty() {
        doh::DEFAULT_DOH_ENDPOINTS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    } else {
        doh_endpoints
    };
    println!(
        "[cyberdns] UDP proxy listening on {listen} (allowlist>blocklist+IOC, DoH multi-resolver)"
    );
    println!("[cyberdns] DoH chain: {}", doh_eps.join(" → "));
    println!("[cyberdns] test: nslookup -port=53553 example.com 127.0.0.1");
    if stats_interval_secs > 0 {
        println!("[cyberdns] stats every {stats_interval_secs}s");
    }
    println!("[cyberdns] Ctrl+C to stop");

    let set_reload = set.clone();
    let allow_reload = allow.clone();
    let bl = blocklist_path.clone();
    let al = allowlist_path.clone();
    let ioc = ioc_path.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            *set_reload.write().await = load_deny_set(&bl, &ioc);
            *allow_reload.write().await = load_allow_set(&al);
        }
    });

    if stats_interval_secs > 0 {
        let st = stats.clone();
        let secs = stats_interval_secs;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(secs));
            loop {
                tick.tick().await;
                eprintln!("[cyberdns] stats {}", st.snapshot_line());
            }
        });
    }

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();
        let packet = match Packet::parse(&data) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if packet.questions.is_empty() {
            continue;
        }
        stats.queries.fetch_add(1, Ordering::Relaxed);
        let q = &packet.questions[0];
        let domain = qname_to_string(&q.qname);
        let qtype = q.qtype;

        let on_allow = {
            let guard = allow.read().await;
            is_allowed(&guard, &domain)
        };
        let blocked = if on_allow {
            false
        } else {
            let guard = set.read().await;
            is_blocked(&guard, &domain)
        };

        let reply_bytes = if blocked {
            stats.blocked.fetch_add(1, Ordering::Relaxed);
            emit_dns(
                &event_log,
                EventAction::Blocked,
                Severity::High,
                &format!("proxy blocked: {domain}"),
                &domain,
                None,
            );
            match build_with_rcode(&packet, RCODE::NameError, &[]) {
                Ok(b) => b,
                Err(e) => {
                    stats.encode_err.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[cyberdns] encode nxdomain: {e}");
                    continue;
                }
            }
        } else if matches!(qtype, QTYPE::TYPE(TYPE::A)) {
            if on_allow {
                stats.allowlisted.fetch_add(1, Ordering::Relaxed);
            }
            match doh::resolve_a(&domain, &doh_eps).await {
                Ok((ips, used)) => {
                    stats.doh_ok.fetch_add(1, Ordering::Relaxed);
                    stats.allowed.fetch_add(1, Ordering::Relaxed);
                    if doh_eps.len() > 1 && used != doh_eps[0] {
                        stats.doh_fallback.fetch_add(1, Ordering::Relaxed);
                    }
                    emit_dns(
                        &event_log,
                        EventAction::Allowed,
                        Severity::Info,
                        &format!("proxy resolve: {domain}"),
                        &domain,
                        Some(&used),
                    );
                    let ans: Vec<(String, Ipv4Addr)> = ips
                        .into_iter()
                        .map(|ip| (format!("{domain}."), ip))
                        .collect();
                    match build_with_rcode(&packet, RCODE::NoError, &ans) {
                        Ok(b) => b,
                        Err(e) => {
                            stats.encode_err.fetch_add(1, Ordering::Relaxed);
                            eprintln!("[cyberdns] encode answer: {e}");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    stats.doh_fail.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[cyberdns] DoH fail {domain}: {e}");
                    match build_with_rcode(&packet, RCODE::ServerFailure, &[]) {
                        Ok(b) => b,
                        Err(_) => {
                            stats.encode_err.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
            }
        } else {
            // AAAA / other: empty NOERROR (no data)
            stats.other_qtype.fetch_add(1, Ordering::Relaxed);
            match build_with_rcode(&packet, RCODE::NoError, &[]) {
                Ok(b) => b,
                Err(_) => {
                    stats.encode_err.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        };

        if let Err(e) = sock.send_to(&reply_bytes, peer).await {
            eprintln!("[cyberdns] send_to {peer}: {e}");
        }
    }
}
