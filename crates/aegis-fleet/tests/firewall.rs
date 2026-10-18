//! ChangeFirewall enforcement with a mock backend: apply / confirm /
//! rollback / apply-failure / foreign-rule protection / quorum.

use aegis_fleet::fw::{AegisFirewall, FwRule, PREFIX};
use aegis_fleet::proto::PolicyStatus;
use aegis_fleet::runtime::{AgentState, CaPin};
use ed25519_dalek::SigningKey;
use s2o_policy::{ActionClass, AdminKeyEntry, AdminRoster, PolicyBundle, SignedBundle};
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
struct MockFw {
    rules: Mutex<BTreeMap<String, Option<FwRule>>>,
    fail_on: Option<String>,
    log: Mutex<Vec<String>>,
}

impl MockFw {
    fn with_foreign() -> Self {
        let m = MockFw::default();
        for n in [
            "Core Networking - DHCP (UDP-In)",
            "Remote Desktop",
            "aegis-lowercase-not-ours",
        ] {
            m.rules.lock().unwrap().insert(n.into(), None);
        }
        m
    }
    fn names(&self) -> Vec<String> {
        self.rules.lock().unwrap().keys().cloned().collect()
    }
    fn owned(&self) -> Vec<String> {
        self.names()
            .into_iter()
            .filter(|n| n.starts_with(PREFIX))
            .collect()
    }
    fn foreign(&self) -> Vec<String> {
        self.names()
            .into_iter()
            .filter(|n| !n.starts_with(PREFIX))
            .collect()
    }
}

impl AegisFirewall for MockFw {
    fn list_names(&self) -> Result<Vec<String>, String> {
        Ok(self.names())
    }
    fn add(&self, r: &FwRule) -> Result<(), String> {
        if self.fail_on.as_deref() == Some(r.name.as_str()) {
            return Err("simulated failure".into());
        }
        self.log
            .lock()
            .unwrap()
            .push(format!("add {}", r.os_name()));
        self.rules
            .lock()
            .unwrap()
            .insert(r.os_name(), Some(r.clone()));
        Ok(())
    }
    fn delete(&self, n: &str) -> Result<(), String> {
        assert!(
            n.starts_with(PREFIX),
            "enforcer tried to delete foreign rule {n}"
        );
        self.log.lock().unwrap().push(format!("delete {n}"));
        self.rules.lock().unwrap().remove(n);
        Ok(())
    }
}

fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

struct Adm(SigningKey, SigningKey, AdminRoster);
fn adm() -> Adm {
    let (a, b) = (key(), key());
    let r = AdminRoster::new(vec![
        AdminKeyEntry {
            key_id: "a".into(),
            admin: "alice".into(),
            public_key: s2o_policy::public_key_b64(&a),
        },
        AdminKeyEntry {
            key_id: "b".into(),
            admin: "bob".into(),
            public_key: s2o_policy::public_key_b64(&b),
        },
    ]);
    Adm(a, b, r)
}

fn state(r: &AdminRoster) -> AgentState {
    AgentState {
        agent_id: "agent-x".into(),
        cert_pem: String::new(),
        not_after_unix: 0,
        server_addr: String::new(),
        server_name: String::new(),
        pins: vec![CaPin {
            pem: "X".into(),
            valid_until: None,
        }],
        roster: r.clone(),
        last_policy_version: 0,
        last_contact: 0,
        heartbeat_secs: 60,
        pending_results: vec![],
        audit_head: None,
        fw_applied: vec![],
        fw_pending: None,
    }
}

fn rule(name: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "direction": "in", "action": "block", "protocol": "tcp", "local_ports": "4444"})
}

fn fw_bundle(a: &Adm, v: u64, rules: Vec<serde_json::Value>, approvals: usize) -> SignedBundle {
    let mut sb = SignedBundle::new(PolicyBundle {
        version: v,
        action: ActionClass::ChangeFirewall,
        issued_at: 0,
        targets: vec![],
        body: serde_json::json!({"rules": rules, "confirm_secs": 300}),
    });
    sb.approve("a", &a.0);
    if approvals > 1 {
        sb.approve("b", &a.1);
    }
    sb
}

const T0: i64 = 1_000_000;

#[test]
fn apply_then_confirm() {
    let a = adm();
    let fw = MockFw::with_foreign();
    let foreign = fw.foreign();
    let mut st = state(&a.2);
    let r = st.apply_bundles_with(
        &[fw_bundle(&a, 1, vec![rule("block-4444")], 2)],
        T0,
        Some(&fw),
    );
    assert_eq!(r[0].status, PolicyStatus::Applied, "{r:?}");
    assert_eq!(fw.owned(), vec![format!("{PREFIX}block-4444")]);
    assert_eq!(fw.foreign(), foreign);
    assert!(st.fw_pending.is_some());
    // Heartbeat succeeds a minute later.
    let c = st.confirm_firewall(T0 + 60).unwrap();
    assert_eq!(c.status, PolicyStatus::Applied);
    assert!(st.fw_pending.is_none());
    assert_eq!(st.fw_applied.len(), 1);
    // Deadline check is now a no-op.
    assert!(st.check_firewall_deadline(Some(&fw), T0 + 10_000).is_none());
    assert_eq!(fw.owned().len(), 1);
}

#[test]
fn no_confirmation_rolls_back_to_snapshot() {
    let a = adm();
    let fw = MockFw::with_foreign();
    let foreign = fw.foreign();
    let mut st = state(&a.2);
    st.apply_bundles_with(&[fw_bundle(&a, 1, vec![rule("keep")], 2)], T0, Some(&fw));
    st.confirm_firewall(T0 + 30).unwrap();
    // v2 replaces the set but is never confirmed.
    st.apply_bundles_with(
        &[fw_bundle(&a, 2, vec![rule("new-a"), rule("new-b")], 2)],
        T0 + 100,
        Some(&fw),
    );
    assert_eq!(fw.owned().len(), 2);
    assert!(
        st.check_firewall_deadline(Some(&fw), T0 + 200).is_none(),
        "not yet due"
    );
    assert!(st.next_wake_secs(T0 + 200) <= 60);
    let r = st.check_firewall_deadline(Some(&fw), T0 + 400).unwrap();
    assert_eq!(r.status, PolicyStatus::RolledBack);
    assert_eq!(r.version, 2);
    assert_eq!(fw.owned(), vec![format!("{PREFIX}keep")]);
    assert_eq!(fw.foreign(), foreign);
    assert!(st.fw_pending.is_none());
    assert_eq!(
        st.last_policy_version, 2,
        "a rolled-back bundle is not replayed"
    );
}

#[test]
fn apply_failure_restores_immediately() {
    let a = adm();
    let fw = MockFw {
        fail_on: Some("bad".into()),
        ..MockFw::with_foreign()
    };
    let mut st = state(&a.2);
    st.apply_bundles_with(&[fw_bundle(&a, 1, vec![rule("good")], 2)], T0, Some(&fw));
    st.confirm_firewall(T0 + 1).unwrap();
    let r = st.apply_bundles_with(
        &[fw_bundle(&a, 2, vec![rule("x"), rule("bad")], 2)],
        T0 + 10,
        Some(&fw),
    );
    assert_eq!(r[0].status, PolicyStatus::RolledBack, "{r:?}");
    assert_eq!(fw.owned(), vec![format!("{PREFIX}good")]);
    assert!(st.fw_pending.is_none());
}

#[test]
fn foreign_rules_and_injection_are_refused() {
    let a = adm();
    let fw = MockFw::with_foreign();
    let foreign = fw.foreign();
    let mut st = state(&a.2);
    for bad in [
        serde_json::json!({"name": "x name=Remote Desktop", "direction": "in", "action": "allow"}),
        serde_json::json!({"name": "ok", "direction": "in", "action": "allow", "protocol": "tcp", "local_ports": "80 dir=out"}),
        serde_json::json!({"name": "ok", "direction": "in", "action": "allow", "remote_addresses": "1.2.3.4\" program=c:\\x"}),
        serde_json::json!({"name": "ok", "direction": "in", "action": "allow", "application": "C:\\evil.exe"}),
        serde_json::json!({"name": "ok", "direction": "in", "action": "allow", "local_ports": "80"}),
    ] {
        let v = st.last_policy_version + 1;
        let r = st.apply_bundles_with(&[fw_bundle(&a, v, vec![bad.clone()], 2)], T0, Some(&fw));
        assert_eq!(r[0].status, PolicyStatus::Rejected, "{bad}: {r:?}");
    }
    assert_eq!(fw.foreign(), foreign);
    assert!(fw.owned().is_empty());
    assert!(fw.log.lock().unwrap().is_empty(), "nothing touched");
}

#[test]
fn needs_quorum_and_backend() {
    let a = adm();
    let fw = MockFw::with_foreign();
    let mut st = state(&a.2);
    let r = st.apply_bundles_with(&[fw_bundle(&a, 1, vec![rule("x")], 1)], T0, Some(&fw));
    assert_eq!(r[0].status, PolicyStatus::Rejected);
    assert!(fw.owned().is_empty());
    let r = st.apply_bundles_with(&[fw_bundle(&a, 1, vec![rule("x")], 2)], T0, None);
    assert_eq!(r[0].status, PolicyStatus::NotImplemented);
}
