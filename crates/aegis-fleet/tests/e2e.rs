//! In-process end-to-end over loopback mTLS:
//! enroll -> heartbeat -> signed bundles applied/reported -> audit verify,
//! plus a forged bundle served by a compromised server DB.

use aegis_fleet::ca::FleetCa;
use aegis_fleet::keystore::SoftwareKeyStore;
use aegis_fleet::policy::FleetPolicy;
use aegis_fleet::proto::PolicyStatus;
use aegis_fleet::runtime::{enroll_new, EnrollParams, TickOutcome};
use aegis_fleet::server::FleetServer;
use aegis_fleet::store::Store;
use ed25519_dalek::SigningKey;
use s2o_policy::{ActionClass, AdminKeyEntry, AdminRoster, PolicyBundle, SignedBundle};
use std::sync::Arc;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}
fn bundle(v: u64, action: ActionClass, body: serde_json::Value) -> SignedBundle {
    SignedBundle::new(PolicyBundle {
        version: v,
        action,
        issued_at: now(),
        targets: vec![],
        body,
    })
}

#[tokio::test]
async fn enroll_heartbeat_policy_audit() {
    let dir = std::env::temp_dir().join(format!("aegis-e2e-{}-{}", std::process::id(), now()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit_path = dir.join("audit.log");
    let audit_key = key();

    let (alice, bob) = (key(), key());
    let roster = AdminRoster::new(vec![
        AdminKeyEntry {
            key_id: "alice-1".into(),
            admin: "alice".into(),
            public_key: s2o_policy::public_key_b64(&alice),
        },
        AdminKeyEntry {
            key_id: "bob-1".into(),
            admin: "bob".into(),
            public_key: s2o_policy::public_key_b64(&bob),
        },
    ]);

    let ca = Arc::new(FleetCa::generate("e2e").unwrap());
    let store = Arc::new(Store::in_memory().unwrap());
    let (cert, k) = ca.issue_server_cert(&["fleet.test".to_string()]).unwrap();
    let srv = Arc::new(
        FleetServer::new(ca.clone(), store.clone(), &cert, &k, FleetPolicy::default())
            .unwrap()
            .with_roster(roster.clone())
            .with_audit(
                s2o_audit::AuditLog::open(&audit_path).unwrap(),
                audit_key.clone(),
            ),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(srv.clone().serve(l));

    // Enroll (wrong fingerprint refused first).
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = key();
    let token = store.create_token(now(), 3600).unwrap();
    let cid_pk = s2o_attest::public_key_b64(&cid);
    macro_rules! params {
        ($fp:expr) => {
            EnrollParams {
                server_addr: &addr,
                server_name: "fleet.test",
                ca_pem: ca.cert_pem(),
                ca_fingerprint: $fp,
                token: &token,
                hostname: "win-01",
                cyberid_public_key: &cid_pk,
                roster: roster.clone(),
            }
        };
    }
    let bad = "00".repeat(32);
    assert!(enroll_new(params!(&bad), &keys, now()).await.is_err());
    let mut st = enroll_new(params!(&ca.fingerprint()), &keys, now())
        .await
        .unwrap();

    let tok = || {
        s2o_attest::sign(
            &cid,
            &serde_json::json!({"sub": "win-01", "exp": now() + 60}),
        )
        .unwrap()
    };
    let pol = FleetPolicy::default();

    // Heartbeat with no bundles.
    let out = st
        .tick(&keys, &pol, serde_json::json!({"fw": true}), &tok(), now())
        .await
        .unwrap();
    assert_eq!(
        out,
        TickOutcome::Ok {
            renewed: false,
            results: vec![]
        }
    );

    // Admins publish: v1 normal (1 approval), v2 isolate-host (2 approvals).
    let mut b1 = bundle(
        1,
        ActionClass::Normal,
        serde_json::json!({"heartbeat_secs": 30}),
    );
    b1.approve("alice-1", &alice);
    srv.submit_bundle(&b1).unwrap();
    let mut b2 = bundle(2, ActionClass::IsolateHost, serde_json::json!({}));
    b2.approve("alice-1", &alice);
    assert!(
        srv.submit_bundle(&b2).is_err(),
        "risky class needs 2 approvals"
    );
    b2.approve("bob-1", &bob);
    srv.submit_bundle(&b2).unwrap();

    let out = st
        .tick(&keys, &pol, serde_json::json!({}), &tok(), now())
        .await
        .unwrap();
    let TickOutcome::Ok { results, .. } = out else {
        panic!("{out:?}")
    };
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].status, PolicyStatus::Applied);
    assert_eq!(results[1].status, PolicyStatus::NotImplemented);
    assert_eq!(st.heartbeat_secs, 30);
    assert_eq!(st.last_policy_version, 2);

    // Compromised server DB serves a forged risky bundle; the agent refuses it.
    let mut forged = bundle(
        3,
        ActionClass::RunScript,
        serde_json::json!({"cmd": "evil"}),
    );
    forged.approve("alice-1", &alice);
    forged.approve("bob-1", &key());
    store
        .add_bundle(
            3,
            "run_script",
            &serde_json::to_string(&forged).unwrap(),
            now(),
        )
        .unwrap();
    let out = st
        .tick(&keys, &pol, serde_json::json!({}), &tok(), now())
        .await
        .unwrap();
    let TickOutcome::Ok { results, .. } = out else {
        panic!("{out:?}")
    };
    assert_eq!(results[0].status, PolicyStatus::Rejected);
    assert_eq!(st.last_policy_version, 2);

    // One more heartbeat delivers the pending results.
    st.tick(&keys, &pol, serde_json::json!({}), &tok(), now())
        .await
        .unwrap();
    let reported = store.policy_results().unwrap();
    let statuses: Vec<_> = reported.iter().map(|r| (r.1, r.2.as_str())).collect();
    assert!(statuses.contains(&(1, "applied")));
    assert!(statuses.contains(&(2, "not_implemented")));
    assert!(statuses.contains(&(3, "rejected")));

    // Audit: chain verifies against the signed head the agent holds.
    let head = st.audit_head.clone().expect("agent received audit head");
    let entries = s2o_audit::verify_file(&audit_path).unwrap();
    s2o_audit::verify_against_head(&entries, &head, &audit_key.verifying_key()).unwrap();
    let actions: Vec<_> = entries.iter().map(|e| e.action.as_str()).collect();
    for a in ["agent.enroll", "policy.submit", "policy.result"] {
        assert!(actions.contains(&a), "missing {a} in {actions:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
