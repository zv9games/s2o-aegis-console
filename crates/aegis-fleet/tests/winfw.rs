//! Windows-only integration test against the real Windows Firewall.
//! Creates and removes an Aegis-prefixed rule and verifies rollback.
//! Skips (with a clear message) when the process cannot change firewall
//! rules (not elevated).

#[cfg(windows)]
#[test]
fn windows_firewall_apply_and_rollback() {
    use aegis_fleet::fw::{windows::WindowsAegisFirewall, AegisFirewall, FwRule, PREFIX};
    use aegis_fleet::proto::PolicyStatus;
    use aegis_fleet::runtime::{AgentState, CaPin};
    use s2o_policy::{ActionClass, AdminKeyEntry, AdminRoster, PolicyBundle, SignedBundle};

    let fw = WindowsAegisFirewall;
    let name = format!("ci-{}", std::process::id());
    let probe: FwRule = serde_json::from_value(serde_json::json!({
        "name": format!("{name}-probe"), "direction": "in", "action": "block",
        "protocol": "tcp", "local_ports": "49999"
    }))
    .unwrap();
    if let Err(e) = fw.add(&probe) {
        println!("WINFW_INTEGRATION: SKIPPED (cannot modify firewall rules: {e})");
        return;
    }
    fw.delete(&probe.os_name()).unwrap();

    let before = fw.list_names().unwrap();
    let foreign_before: Vec<_> = before
        .iter()
        .filter(|n| !n.starts_with(PREFIX))
        .cloned()
        .collect();
    // Never run against a host with real Aegis rules.
    assert!(
        before.iter().all(|n| !n.starts_with(PREFIX)),
        "host already has Aegis rules; refusing to run"
    );

    let (ka, kb) = (
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    );
    let roster = AdminRoster::new(vec![
        AdminKeyEntry {
            key_id: "a".into(),
            admin: "a".into(),
            public_key: s2o_policy::public_key_b64(&ka),
        },
        AdminKeyEntry {
            key_id: "b".into(),
            admin: "b".into(),
            public_key: s2o_policy::public_key_b64(&kb),
        },
    ]);
    let mut st = AgentState {
        agent_id: "ci".into(),
        cert_pem: String::new(),
        not_after_unix: 0,
        server_addr: String::new(),
        server_name: String::new(),
        pins: vec![CaPin {
            pem: "X".into(),
            valid_until: None,
        }],
        roster,
        last_policy_version: 0,
        last_contact: 0,
        heartbeat_secs: 60,
        pending_results: vec![],
        audit_head: None,
        fw_applied: vec![],
        fw_pending: None,
    };
    let mut sb = SignedBundle::new(PolicyBundle {
        version: 1,
        action: ActionClass::ChangeFirewall,
        issued_at: 0,
        targets: vec![],
        body: serde_json::json!({"rules": [{
            "name": name, "direction": "in", "action": "block",
            "protocol": "tcp", "local_ports": "49998"
        }], "confirm_secs": 30}),
    });
    sb.approve("a", &ka);
    sb.approve("b", &kb);

    let r = st.apply_bundles_with(&[sb], 1000, Some(&fw));
    let os_name = format!("{PREFIX}{name}");
    let present = fw.list_names().unwrap().contains(&os_name);
    // Always clean up, even if assertions below fail.
    let rb = st.check_firewall_deadline(Some(&fw), 1031);
    let after = fw.list_names().unwrap();
    let leftover = after.contains(&os_name);
    if leftover {
        let _ = fw.delete(&os_name);
    }
    assert_eq!(r[0].status, PolicyStatus::Applied, "{r:?}");
    assert!(present, "rule was not created");
    assert_eq!(rb.map(|r| r.status), Some(PolicyStatus::RolledBack));
    assert!(!leftover, "rollback did not remove the rule");
    let foreign_after: Vec<_> = after
        .iter()
        .filter(|n| !n.starts_with(PREFIX))
        .cloned()
        .collect();
    assert_eq!(
        foreign_before.len(),
        foreign_after.len(),
        "foreign rules changed"
    );
    println!(
        "WINFW_INTEGRATION: RAN (created {os_name}, rolled back, {} foreign rules untouched)",
        foreign_after.len()
    );
}

#[cfg(not(windows))]
#[test]
fn windows_firewall_apply_and_rollback() {
    println!("WINFW_INTEGRATION: SKIPPED (not Windows)");
}
