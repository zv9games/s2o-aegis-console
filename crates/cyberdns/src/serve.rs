//! Local UDP DNS proxy: blocklist → NXDOMAIN, else DoH A records.

use crate::blocklist::{is_blocked, load_blocklist, normalize_domain};
use serde::Deserialize;
use simple_dns::rdata::{RData, A};
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, QTYPE, RCODE, TYPE};
use s2o_ioc::{IocKind, IocStore};
use s2o_schema::{AegisEvent, EventAction, EventKind, Ioc, ProductId, Severity};
use s2o_store::EventStore;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

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

fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn emit_dns(event_log: &Path, action: EventAction, severity: Severity, message: &str, domain: &str) {
    if let Ok(store) = EventStore::open(event_log) {
        let ev = AegisEvent::new(
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
        let _ = store.append(&ev);
    }
}

async fn doh_a(domain: &str) -> Result<Vec<Ipv4Addr>, String> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type=A");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("DoH HTTP {}", res.status()));
    }
    let doh: DohResponse = res.json().await.map_err(|e| e.to_string())?;
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
    Ok(out)
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
    ioc_path: &Path,
    event_log: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let set = Arc::new(RwLock::new(load_deny_set(blocklist_path, ioc_path)));
    let blocklist_path = blocklist_path.to_path_buf();
    let ioc_path = ioc_path.to_path_buf();
    let event_log = event_log.to_path_buf();

    let sock = UdpSocket::bind(listen).await?;
    println!(
        "[cyberdns] UDP proxy listening on {listen} (blocklist+IOC, DoH=cloudflare)"
    );
    println!("[cyberdns] test: nslookup -port=53553 example.com 127.0.0.1");
    println!("[cyberdns] Ctrl+C to stop");

    let set_reload = set.clone();
    let bl = blocklist_path.clone();
    let ioc = ioc_path.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            *set_reload.write().await = load_deny_set(&bl, &ioc);
        }
    });

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
        let q = &packet.questions[0];
        let domain = qname_to_string(&q.qname);
        let qtype = q.qtype;

        let blocked = {
            let guard = set.read().await;
            is_blocked(&guard, &domain)
        };

        let reply_bytes = if blocked {
            emit_dns(
                &event_log,
                EventAction::Blocked,
                Severity::High,
                &format!("proxy blocked: {domain}"),
                &domain,
            );
            match build_with_rcode(&packet, RCODE::NameError, &[]) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[cyberdns] encode nxdomain: {e}");
                    continue;
                }
            }
        } else if matches!(qtype, QTYPE::TYPE(TYPE::A)) {
            match doh_a(&domain).await {
                Ok(ips) => {
                    emit_dns(
                        &event_log,
                        EventAction::Allowed,
                        Severity::Info,
                        &format!("proxy resolve: {domain}"),
                        &domain,
                    );
                    let ans: Vec<(String, Ipv4Addr)> = ips
                        .into_iter()
                        .map(|ip| (format!("{domain}."), ip))
                        .collect();
                    match build_with_rcode(&packet, RCODE::NoError, &ans) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("[cyberdns] encode answer: {e}");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[cyberdns] DoH fail {domain}: {e}");
                    match build_with_rcode(&packet, RCODE::ServerFailure, &[]) {
                        Ok(b) => b,
                        Err(_) => continue,
                    }
                }
            }
        } else {
            // AAAA / other: empty NOERROR (no data)
            match build_with_rcode(&packet, RCODE::NoError, &[]) {
                Ok(b) => b,
                Err(_) => continue,
            }
        };

        if let Err(e) = sock.send_to(&reply_bytes, peer).await {
            eprintln!("[cyberdns] send_to {peer}: {e}");
        }
    }
}
