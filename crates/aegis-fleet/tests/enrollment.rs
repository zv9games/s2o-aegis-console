use aegis_fleet::agent::{enroll, heartbeat, FleetEndpoint};
use aegis_fleet::ca::FleetCa;
use aegis_fleet::keystore::{AgentKeyStore, SoftwareKeyStore};
use aegis_fleet::proto::Response;
use aegis_fleet::server::FleetServer;
use aegis_fleet::store::Store;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

struct Fixture {
    ep: FleetEndpoint,
    ca: Arc<FleetCa>,
    store: Arc<Store>,
}

async fn start() -> Fixture {
    let ca = Arc::new(FleetCa::generate("test").unwrap());
    let store = Arc::new(Store::in_memory().unwrap());
    let (cert, key) = ca.issue_server_cert(&["fleet.test".to_string()]).unwrap();
    let srv = Arc::new(
        FleetServer::new(ca.clone(), store.clone(), &cert, &key, Duration::hours(1)).unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(srv.serve(listener));
    Fixture {
        ep: FleetEndpoint {
            addr,
            server_name: "fleet.test".into(),
            ca_pem: ca.cert_pem().to_string(),
        },
        ca,
        store,
    }
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn cyberid_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
}

fn posture_token(k: &ed25519_dalek::SigningKey, exp: i64) -> String {
    s2o_attest::sign(
        k,
        &serde_json::json!({"sub": "host", "exp": exp, "posture_score": 80}),
    )
    .unwrap()
}

#[tokio::test]
async fn enrollment_happy_path_and_heartbeat() {
    let f = start().await;
    let token = f.store.create_token(now(), 3600).unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = cyberid_key();
    let e = enroll(
        &f.ep,
        &keys,
        &token,
        "host-a",
        &s2o_attest::public_key_b64(&cid),
    )
    .await
    .unwrap();
    assert!(e.agent_id.starts_with("agent-"));

    let r = heartbeat(
        &f.ep,
        &keys,
        &e.cert_pem,
        serde_json::json!({"fw": true}),
        &posture_token(&cid, now() + 60),
    )
    .await
    .unwrap();
    match r {
        Response::HeartbeatAck { agent_id, .. } => assert_eq!(agent_id, e.agent_id),
        other => panic!("unexpected {other:?}"),
    }
    let agents = f.store.list_agents().unwrap();
    assert_eq!(agents.len(), 1);
    assert!(!agents[0].hardware_backed);
    assert!(agents[0].last_seen.is_some());
}

#[tokio::test]
async fn replayed_token_is_rejected() {
    let f = start().await;
    let token = f.store.create_token(now(), 3600).unwrap();
    let cid = s2o_attest::public_key_b64(&cyberid_key());
    let k1 = SoftwareKeyStore::ephemeral().unwrap();
    enroll(&f.ep, &k1, &token, "a", &cid).await.unwrap();
    let k2 = SoftwareKeyStore::ephemeral().unwrap();
    let err = enroll(&f.ep, &k2, &token, "b", &cid)
        .await
        .err()
        .expect("replay must fail");
    assert!(err.to_string().contains("already used"), "{err}");
    assert_eq!(f.store.list_agents().unwrap().len(), 1);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let f = start().await;
    let token = f.store.create_token(now() - 7200, 3600).unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let err = enroll(
        &f.ep,
        &keys,
        &token,
        "a",
        &s2o_attest::public_key_b64(&cyberid_key()),
    )
    .await
    .err()
    .unwrap();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[tokio::test]
async fn expired_client_cert_is_rejected() {
    let f = start().await;
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = cyberid_key();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(keys.key_pair())
        .unwrap()
        .pem()
        .unwrap();
    let t = OffsetDateTime::now_utc();
    let (cert, _) =
        f.ca.issue_client_cert_with_validity(
            &csr,
            "agent-expired",
            t - Duration::hours(3),
            t - Duration::hours(1),
        )
        .unwrap();
    f.store
        .add_agent(
            "agent-expired",
            "h",
            &s2o_attest::public_key_b64(&cid),
            false,
            now(),
            now(),
        )
        .unwrap();
    let r = heartbeat(
        &f.ep,
        &keys,
        &cert,
        serde_json::json!({}),
        &posture_token(&cid, now() + 60),
    )
    .await;
    assert!(
        r.is_err(),
        "expired cert must fail the TLS handshake, got {r:?}"
    );
}

#[tokio::test]
async fn client_cert_from_wrong_ca_is_rejected() {
    let f = start().await;
    let rogue = FleetCa::generate("rogue").unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = cyberid_key();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(keys.key_pair())
        .unwrap()
        .pem()
        .unwrap();
    let (cert, _) = rogue
        .issue_client_cert(&csr, "agent-rogue", Duration::hours(1))
        .unwrap();
    f.store
        .add_agent(
            "agent-rogue",
            "h",
            &s2o_attest::public_key_b64(&cid),
            false,
            now(),
            now(),
        )
        .unwrap();
    let r = heartbeat(
        &f.ep,
        &keys,
        &cert,
        serde_json::json!({}),
        &posture_token(&cid, now() + 60),
    )
    .await;
    assert!(
        r.is_err(),
        "cert from another CA must be rejected, got {r:?}"
    );
}

#[tokio::test]
async fn agent_pinning_wrong_ca_refuses_server() {
    let f = start().await;
    let other = FleetCa::generate("other").unwrap();
    let ep = FleetEndpoint {
        ca_pem: other.cert_pem().to_string(),
        ..f.ep.clone()
    };
    let token = f.store.create_token(now(), 3600).unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let r = enroll(
        &ep,
        &keys,
        &token,
        "a",
        &s2o_attest::public_key_b64(&cyberid_key()),
    )
    .await;
    assert!(r.is_err());
    // Token must still be unused: the agent never reached the application layer.
    assert!(f.store.consume_token(&token, now(), "x").unwrap().is_ok());
}

#[tokio::test]
async fn heartbeat_with_foreign_cyberid_token_or_revoked_agent_is_rejected() {
    let f = start().await;
    let token = f.store.create_token(now(), 3600).unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = cyberid_key();
    let e = enroll(&f.ep, &keys, &token, "a", &s2o_attest::public_key_b64(&cid))
        .await
        .unwrap();

    // Token signed by a different cyberid key
    let r = heartbeat(
        &f.ep,
        &keys,
        &e.cert_pem,
        serde_json::json!({}),
        &posture_token(&cyberid_key(), now() + 60),
    )
    .await
    .unwrap();
    assert!(
        matches!(r, Response::Error { ref message } if message.contains("cyberid")),
        "{r:?}"
    );

    // Revoked agent
    f.store.revoke(&e.agent_id).unwrap();
    let r = heartbeat(
        &f.ep,
        &keys,
        &e.cert_pem,
        serde_json::json!({}),
        &posture_token(&cid, now() + 60),
    )
    .await
    .unwrap();
    assert!(
        matches!(r, Response::Error { ref message } if message.contains("revoked")),
        "{r:?}"
    );
}

#[tokio::test]
async fn ca_reloaded_from_disk_issues_certs_that_chain_to_original() {
    let dir = std::env::temp_dir().join(format!("aegis-fleet-ca-{}", std::process::id()));
    let original = FleetCa::generate("disk").unwrap();
    original.save(&dir).unwrap();
    let reloaded = Arc::new(FleetCa::load(&dir).unwrap());
    assert_eq!(reloaded.cert_pem(), original.cert_pem());
    assert_eq!(reloaded.fingerprint(), original.fingerprint());

    let store = Arc::new(Store::in_memory().unwrap());
    let (cert, key) = reloaded
        .issue_server_cert(&["fleet.test".to_string()])
        .unwrap();
    let srv = Arc::new(
        FleetServer::new(
            reloaded.clone(),
            store.clone(),
            &cert,
            &key,
            Duration::hours(1),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(srv.serve(listener));
    let ep = FleetEndpoint {
        addr,
        server_name: "fleet.test".into(),
        ca_pem: original.cert_pem().to_string(),
    };
    let token = store.create_token(now(), 60).unwrap();
    let keys = SoftwareKeyStore::ephemeral().unwrap();
    let cid = cyberid_key();
    let e = enroll(&ep, &keys, &token, "a", &s2o_attest::public_key_b64(&cid))
        .await
        .unwrap();
    let r = heartbeat(
        &ep,
        &keys,
        &e.cert_pem,
        serde_json::json!({}),
        &posture_token(&cid, now() + 60),
    )
    .await
    .unwrap();
    assert!(matches!(r, Response::HeartbeatAck { .. }), "{r:?}");
    std::fs::remove_dir_all(dir).ok();
}
