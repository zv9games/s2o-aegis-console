//! D6: CA rotation needs a 2-approval signed bundle, is distributed to
//! agents via heartbeat, and both CAs stay pinned for a 30-day overlap.

use aegis_fleet::agent::{enroll, FleetEndpoint};
use aegis_fleet::ca::FleetCa;
use aegis_fleet::keystore::SoftwareKeyStore;
use aegis_fleet::policy::FleetPolicy;
use aegis_fleet::proto::PolicyStatus;
use aegis_fleet::runtime::{AgentState, CaPin, TickOutcome};
use aegis_fleet::server::FleetServer;
use aegis_fleet::store::Store;
use ed25519_dalek::SigningKey;
use s2o_policy::{ActionClass, AdminKeyEntry, AdminRoster, PolicyBundle, SignedBundle};
use std::sync::Arc;
use time::OffsetDateTime;

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

struct Admins {
    a: SigningKey,
    b: SigningKey,
    roster: AdminRoster,
}

fn admins() -> Admins {
    let (a, b) = (key(), key());
    let roster = AdminRoster::new(vec![
        AdminKeyEntry {
            key_id: "alice-1".into(),
            admin: "alice".into(),
            public_key: s2o_policy::public_key_b64(&a),
        },
        AdminKeyEntry {
            key_id: "bob-1".into(),
            admin: "bob".into(),
            public_key: s2o_policy::public_key_b64(&b),
        },
    ]);
    Admins { a, b, roster }
}

fn bundle(version: u64, action: ActionClass, body: serde_json::Value) -> SignedBundle {
    SignedBundle::new(PolicyBundle {
        version,
        action,
        issued_at: now(),
        targets: vec![],
        body,
    })
}

struct Fx {
    srv: Arc<FleetServer>,
    store: Arc<Store>,
    old: Arc<FleetCa>,
    next: Arc<FleetCa>,
    adm: Admins,
    ep: FleetEndpoint,
}

async fn start() -> Fx {
    let old = Arc::new(FleetCa::generate("old-ca").unwrap());
    let next = Arc::new(FleetCa::generate("new-ca").unwrap());
    let store = Arc::new(Store::in_memory().unwrap());
    let adm = admins();
    let (cert, k) = old.issue_server_cert(&["fleet.test".to_string()]).unwrap();
    let srv = Arc::new(
        FleetServer::new(
            old.clone(),
            store.clone(),
            &cert,
            &k,
            FleetPolicy::default(),
        )
        .unwrap()
        .with_roster(adm.roster.clone())
        .with_next_ca(next.clone()),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(srv.clone().serve(l));
    let ep = FleetEndpoint {
        addr,
        server_name: "fleet.test".into(),
        ca_pem: old.cert_pem().to_string(),
    };
    Fx {
        srv,
        store,
        old,
        next,
        adm,
        ep,
    }
}

async fn enrolled_agent(fx: &Fx) -> (AgentState, SoftwareKeyStore, SigningKey) {
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = key();
    let t = fx.store.create_token(now(), 3600).unwrap();
    let e = enroll(&fx.ep, &keys, &t, "host", &s2o_attest::public_key_b64(&cid))
        .await
        .unwrap();
    let st = AgentState {
        agent_id: e.agent_id,
        cert_pem: e.cert_pem,
        not_after_unix: e.not_after_unix,
        server_addr: fx.ep.addr.clone(),
        server_name: fx.ep.server_name.clone(),
        pins: vec![CaPin {
            pem: fx.old.cert_pem().to_string(),
            valid_until: None,
        }],
        roster: fx.adm.roster.clone(),
        last_policy_version: 0,
        last_contact: now(),
        heartbeat_secs: 60,
        pending_results: vec![],
        audit_head: None,
    };
    (st, keys, cid)
}

fn tok(k: &SigningKey) -> String {
    s2o_attest::sign(k, &serde_json::json!({"sub":"host","exp": now()+60})).unwrap()
}

fn issuer_cn(cert_pem: &str) -> String {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let c = pem.parse_x509().unwrap();
    c.issuer().to_string()
}

fn rotate_body(fx: &Fx) -> serde_json::Value {
    serde_json::json!({"new_ca_pem": fx.next.cert_pem(), "overlap_days": 30})
}

#[tokio::test]
async fn rotation_requires_two_approvals() {
    let fx = start().await;
    let mut one = bundle(1, ActionClass::RotateCa, rotate_body(&fx));
    one.approve("alice-1", &fx.adm.a);
    assert!(fx.srv.submit_bundle(&one).is_err());
    assert_eq!(fx.srv.trusted_cas().len(), 1);
}

#[tokio::test]
async fn rotation_must_match_prepared_ca() {
    let fx = start().await;
    let other = FleetCa::generate("rogue").unwrap();
    let mut b = bundle(
        1,
        ActionClass::RotateCa,
        serde_json::json!({"new_ca_pem": other.cert_pem()}),
    );
    b.approve("alice-1", &fx.adm.a);
    b.approve("bob-1", &fx.adm.b);
    assert!(fx.srv.submit_bundle(&b).is_err());
}

#[tokio::test]
async fn rotation_end_to_end_with_overlap() {
    let fx = start().await;
    let (mut st, keys, cid) = enrolled_agent(&fx).await;
    assert!(issuer_cn(&st.cert_pem).contains("old-ca"));

    let mut b = bundle(1, ActionClass::RotateCa, rotate_body(&fx));
    b.approve("alice-1", &fx.adm.a);
    b.approve("bob-1", &fx.adm.b);
    fx.srv.submit_bundle(&b).unwrap();
    assert_eq!(fx.srv.trusted_cas().len(), 2);

    // Agent with an old-CA cert still works and receives the bundle.
    let t0 = now();
    let out = st
        .tick(
            &keys,
            &FleetPolicy::default(),
            serde_json::json!({}),
            &tok(&cid),
            t0,
        )
        .await
        .unwrap();
    match out {
        TickOutcome::Ok { results, .. } => assert_eq!(results[0].status, PolicyStatus::Applied),
        o => panic!("{o:?}"),
    }
    assert_eq!(st.pins.len(), 2);
    let until = st.pins[0].valid_until.unwrap();
    assert!((until - (t0 + 30 * 86_400)).abs() < 5);
    assert_eq!(st.last_policy_version, 1);

    // Renewal now issues from the new CA, and that cert is accepted.
    let e = aegis_fleet::agent::renew(&st.endpoint(), &keys, &st.agent_id, Some(&st.cert_pem))
        .await
        .unwrap();
    assert!(issuer_cn(&e.cert_pem).contains("new-ca"));
    st.cert_pem = e.cert_pem;
    let out = st
        .tick(
            &keys,
            &FleetPolicy::default(),
            serde_json::json!({}),
            &tok(&cid),
            now(),
        )
        .await
        .unwrap();
    assert!(matches!(out, TickOutcome::Ok { .. }), "{out:?}");

    // After the overlap the old pin is dropped.
    st.prune_pins(t0 + 31 * 86_400);
    assert_eq!(st.pins.len(), 1);
    assert_eq!(st.pins[0].pem, fx.next.cert_pem());
}

#[test]
fn agent_rejects_forged_or_underapproved_rotation() {
    let adm = admins();
    let mut st = AgentState {
        agent_id: "a".into(),
        cert_pem: String::new(),
        not_after_unix: 0,
        server_addr: String::new(),
        server_name: String::new(),
        pins: vec![CaPin {
            pem: "OLD".into(),
            valid_until: None,
        }],
        roster: adm.roster.clone(),
        last_policy_version: 0,
        last_contact: 0,
        heartbeat_secs: 60,
        pending_results: vec![],
        audit_head: None,
    };
    let body = serde_json::json!({"new_ca_pem": "EVIL"});
    let mut one = bundle(1, ActionClass::RotateCa, body.clone());
    one.approve("alice-1", &adm.a);
    let mut forged = bundle(2, ActionClass::RotateCa, body);
    forged.approve("alice-1", &adm.a);
    forged.approve("bob-1", &key()); // wrong key for bob-1
    let r = st.apply_bundles(&[one, forged], now());
    assert!(r.iter().all(|r| r.status == PolicyStatus::Rejected));
    assert_eq!(st.pins.len(), 1);
    assert_eq!(st.last_policy_version, 0);
}

#[tokio::test]
async fn full_rotation_lifecycle_with_retirement() {
    let fx = start().await;
    let pol = FleetPolicy::default();
    let (mut a1, k1, c1) = enrolled_agent(&fx).await;
    let (mut a2, k2, c2) = enrolled_agent(&fx).await;
    let old_fp = fx.old.fingerprint();
    let new_fp = fx.next.fingerprint();

    // 1. Rotate (2 approvals).
    let mut rot = bundle(1, ActionClass::RotateCa, rotate_body(&fx));
    rot.approve("alice-1", &fx.adm.a);
    rot.approve("bob-1", &fx.adm.b);
    fx.srv.submit_bundle(&rot).unwrap();

    // 2. Agent 1 gets the pin, acks it on the next heartbeat, renews from new CA.
    a1.tick(&k1, &pol, serde_json::json!({}), &tok(&c1), now())
        .await
        .unwrap();
    let e = aegis_fleet::agent::renew(&a1.endpoint(), &k1, &a1.agent_id, Some(&a1.cert_pem))
        .await
        .unwrap();
    a1.cert_pem = e.cert_pem;
    a1.tick(&k1, &pol, serde_json::json!({}), &tok(&c1), now())
        .await
        .unwrap();
    assert!(!fx
        .store
        .agents_missing_pin(&new_fp)
        .unwrap()
        .contains(&a1.agent_id));
    assert!(fx
        .store
        .agents_missing_pin(&new_fp)
        .unwrap()
        .contains(&a2.agent_id));

    let retire = |v: u64, force: bool, approvers: usize| {
        let mut b = bundle(
            v,
            ActionClass::RetireCa,
            serde_json::json!({"old_ca_fingerprint": old_fp, "force": force}),
        );
        b.approve("alice-1", &fx.adm.a);
        if approvers > 1 {
            b.approve("bob-1", &fx.adm.b);
        }
        b
    };

    // 3. Refused while the server cert is still from the old CA.
    let err = fx
        .srv
        .submit_bundle(&retire(2, false, 2))
        .unwrap_err()
        .to_string();
    assert!(err.contains("server certificate"), "{err}");

    // 4. Reissue server cert from next CA.
    let (cert, key) = fx
        .next
        .issue_server_cert(&["fleet.test".to_string()])
        .unwrap();
    fx.srv.reload_server_cert(&cert, &key).unwrap();

    // 5. Refused while agent 2 has not acked; force needs quorum too.
    let err = fx
        .srv
        .submit_bundle(&retire(2, false, 2))
        .unwrap_err()
        .to_string();
    assert!(err.contains("not acked"), "{err}");
    assert!(fx.srv.submit_bundle(&retire(2, true, 1)).is_err());
    fx.srv.submit_bundle(&retire(2, true, 2)).unwrap();
    assert_eq!(fx.srv.trusted_cas(), vec![fx.next.cert_pem().to_string()]);

    // 6. Agent 1 drops the old pin on the signed retire bundle.
    let out = a1
        .tick(&k1, &pol, serde_json::json!({}), &tok(&c1), now())
        .await
        .unwrap();
    match out {
        TickOutcome::Ok { results, .. } => {
            assert_eq!(results[0].version, 2);
            assert_eq!(results[0].status, PolicyStatus::Applied, "{results:?}");
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(a1.pins.len(), 1);
    assert_eq!(aegis_fleet::ca::pem_fingerprint(&a1.pins[0].pem), new_fp);
    a1.tick(&k1, &pol, serde_json::json!({}), &tok(&c1), now())
        .await
        .unwrap();
    assert!(matches!(
        a1.tick(&k1, &pol, serde_json::json!({}), &tok(&c1), now())
            .await
            .unwrap(),
        TickOutcome::Ok { .. }
    ));

    // 7. Agent 2 (old-CA cert, old pin only) is now locked out: needs re-enrollment.
    let out = a2
        .tick(&k2, &pol, serde_json::json!({}), &tok(&c2), now())
        .await
        .unwrap();
    assert!(matches!(out, TickOutcome::Offline { .. }), "{out:?}");
}
