//! Signed policy bundles with M-of-N admin approval (ARCHITECTURE.md §3, D3).
//!
//! * Admin keys are Ed25519 and meant to live offline / on hardware tokens.
//! * Agents pin an [`AdminRoster`] at enrollment and only apply bundles whose
//!   signatures satisfy the roster threshold for the bundle's action class.
//! * Bundle versions are monotonic; agents reject replays of older bundles.
//! * The fleet server only stores and forwards bundles; it holds no admin key
//!   and therefore cannot produce a bundle agents will accept.
//! * Approvals count once per **distinct key**. If the counted keys belong to
//!   fewer distinct admins than keys, the result carries a warning (D3).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod keyfile;
pub mod signer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// Read-only / low-risk configuration (e.g. telemetry intervals).
    Normal,
    /// Network isolation of a host.
    IsolateHost,
    /// Running a script or command on agents.
    RunScript,
    /// Uninstalling or disabling the agent.
    Uninstall,
    /// Replacing the pinned admin roster.
    ChangeRoster,
    /// Adding, removing or changing host firewall rules.
    ChangeFirewall,
    /// Changing the fleet's require-TPM setting.
    ChangeRequireTpm,
    /// Rotating the fleet CA (dual-pin overlap).
    RotateCa,
    /// Retiring the old CA after rotation (agents drop the old pin).
    RetireCa,
}

impl ActionClass {
    /// Risky classes need `risky_threshold` (default 2) approvals (decision
    /// D5). Only `Normal` (read-only / low-risk settings) needs one.
    pub fn is_risky(self) -> bool {
        !matches!(self, ActionClass::Normal)
    }

    pub const ALL: [ActionClass; 9] = [
        ActionClass::Normal,
        ActionClass::IsolateHost,
        ActionClass::RunScript,
        ActionClass::Uninstall,
        ActionClass::ChangeRoster,
        ActionClass::ChangeFirewall,
        ActionClass::ChangeRequireTpm,
        ActionClass::RotateCa,
        ActionClass::RetireCa,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminKeyEntry {
    /// Stable id for the key (e.g. "greg-yubikey-1").
    pub key_id: String,
    /// The human admin this key belongs to.
    pub admin: String,
    /// Base64url Ed25519 public key.
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRoster {
    pub keys: Vec<AdminKeyEntry>,
    /// Required distinct-key approvals for risky action classes (default 2).
    pub risky_threshold: u8,
    /// Per-class overrides.
    #[serde(default)]
    pub overrides: BTreeMap<ActionClass, u8>,
}

impl AdminRoster {
    pub fn new(keys: Vec<AdminKeyEntry>) -> Self {
        Self {
            keys,
            risky_threshold: 2,
            overrides: BTreeMap::new(),
        }
    }

    pub fn threshold(&self, class: ActionClass) -> u8 {
        if let Some(t) = self.overrides.get(&class) {
            return (*t).max(1);
        }
        if class.is_risky() {
            self.risky_threshold.max(1)
        } else {
            1
        }
    }

    fn lookup(&self, key_id: &str) -> Option<&AdminKeyEntry> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonic; agents reject bundles with version <= last applied.
    pub version: u64,
    pub action: ActionClass,
    pub issued_at: i64,
    /// Optional target selector (agent ids); empty = whole fleet.
    #[serde(default)]
    pub targets: Vec<String>,
    pub body: serde_json::Value,
}

impl PolicyBundle {
    /// Canonical bytes that are signed: JSON with object keys sorted
    /// (serde_json's default map is a BTreeMap), prefixed by a domain tag.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).expect("bundle serializes");
        let mut out = b"s2o-aegis-policy-v1\n".to_vec();
        out.extend(serde_json::to_vec(&v).expect("value serializes"));
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedBundle {
    pub bundle: PolicyBundle,
    pub approvals: Vec<Approval>,
}

impl SignedBundle {
    pub fn new(bundle: PolicyBundle) -> Self {
        Self {
            bundle,
            approvals: Vec::new(),
        }
    }

    /// Add an approval with a raw admin signing key (tests / tooling).
    pub fn approve(&mut self, key_id: &str, key: &SigningKey) {
        self.approve_with(&signer::SoftwareSigner::new(key_id, key.clone()));
    }

    /// Add an approval with any [`signer::PolicySigner`] (encrypted file
    /// today, FIDO2/hardware later).
    pub fn approve_with(&mut self, signer: &dyn signer::PolicySigner) {
        let sig = signer.sign(&self.bundle.signing_bytes());
        self.approvals.push(Approval {
            key_id: signer.key_id().to_string(),
            signature: B64.encode(sig),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub valid_keys: Vec<String>,
    pub distinct_admins: usize,
    /// Set when approvals came from fewer distinct admins than keys.
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("bundle version {got} is not newer than last applied {last}")]
    Rollback { got: u64, last: u64 },
    #[error("insufficient approvals for {class:?}: {have} valid distinct key(s), need {need}")]
    Insufficient {
        class: ActionClass,
        have: usize,
        need: usize,
    },
    #[error("approval from {key_id} has an invalid signature")]
    BadSignature { key_id: String },
}

pub fn parse_public_key(b64: &str) -> Option<VerifyingKey> {
    let raw: [u8; 32] = B64.decode(b64.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().as_bytes())
}

/// Verify a signed bundle against a pinned roster.
///
/// Approvals from keys not in the roster are ignored. An approval from a
/// roster key with a bad signature is a hard error (tampering signal).
pub fn verify(
    sb: &SignedBundle,
    roster: &AdminRoster,
    last_version: u64,
) -> Result<Verified, PolicyError> {
    if sb.bundle.version <= last_version {
        return Err(PolicyError::Rollback {
            got: sb.bundle.version,
            last: last_version,
        });
    }
    let msg = sb.bundle.signing_bytes();
    let mut keys = BTreeSet::new();
    let mut admins = BTreeSet::new();
    for a in &sb.approvals {
        let Some(entry) = roster.lookup(&a.key_id) else {
            continue;
        };
        let ok = parse_public_key(&entry.public_key)
            .zip(
                B64.decode(&a.signature)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok()),
            )
            .map(|(vk, sig)| vk.verify(&msg, &Signature::from_bytes(&sig)).is_ok())
            .unwrap_or(false);
        if !ok {
            return Err(PolicyError::BadSignature {
                key_id: a.key_id.clone(),
            });
        }
        if keys.insert(entry.key_id.clone()) {
            admins.insert(entry.admin.clone());
        }
    }
    let need = roster.threshold(sb.bundle.action) as usize;
    if keys.len() < need {
        return Err(PolicyError::Insufficient {
            class: sb.bundle.action,
            have: keys.len(),
            need,
        });
    }
    let warning = (need > 1 && admins.len() < keys.len().min(need)).then(|| {
        format!(
            "approvals are not independent: {} key(s) from {} admin(s)",
            keys.len(),
            admins.len()
        )
    });
    Ok(Verified {
        valid_keys: keys.into_iter().collect(),
        distinct_admins: admins.len(),
        warning,
    })
}

/// Agent-side guard that tracks the last applied version.
pub struct PolicyGuard {
    pub roster: AdminRoster,
    pub last_version: u64,
}

impl PolicyGuard {
    /// Verify and, on success, advance the version. A `ChangeRoster` bundle
    /// must carry the new roster as its body and is verified against the
    /// *current* roster.
    pub fn accept(&mut self, sb: &SignedBundle) -> Result<Verified, PolicyError> {
        let v = verify(sb, &self.roster, self.last_version)?;
        if sb.bundle.action == ActionClass::ChangeRoster {
            if let Ok(new) = serde_json::from_value::<AdminRoster>(sb.bundle.body.clone()) {
                self.roster = new;
            }
        }
        self.last_version = sb.bundle.version;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn entry(id: &str, admin: &str, k: &SigningKey) -> AdminKeyEntry {
        AdminKeyEntry {
            key_id: id.into(),
            admin: admin.into(),
            public_key: public_key_b64(k),
        }
    }

    fn bundle(version: u64, action: ActionClass) -> SignedBundle {
        SignedBundle::new(PolicyBundle {
            version,
            action,
            issued_at: 0,
            targets: vec![],
            body: serde_json::json!({"isolate": ["agent-1"]}),
        })
    }

    struct Fx {
        roster: AdminRoster,
        alice: SigningKey,
        bob: SigningKey,
        alice2: SigningKey,
    }

    fn fx() -> Fx {
        let (alice, bob, alice2) = (key(), key(), key());
        let roster = AdminRoster::new(vec![
            entry("alice-1", "alice", &alice),
            entry("bob-1", "bob", &bob),
            entry("alice-2", "alice", &alice2),
        ]);
        Fx {
            roster,
            alice,
            bob,
            alice2,
        }
    }

    #[test]
    fn unsigned_bundle_rejected() {
        let f = fx();
        let e = verify(&bundle(1, ActionClass::Normal), &f.roster, 0).unwrap_err();
        assert!(matches!(
            e,
            PolicyError::Insufficient {
                have: 0,
                need: 1,
                ..
            }
        ));
    }

    #[test]
    fn normal_needs_one_risky_needs_two() {
        let f = fx();
        let mut n = bundle(1, ActionClass::Normal);
        n.approve("alice-1", &f.alice);
        assert!(verify(&n, &f.roster, 0).unwrap().warning.is_none());

        let mut r = bundle(1, ActionClass::IsolateHost);
        r.approve("alice-1", &f.alice);
        assert!(matches!(
            verify(&r, &f.roster, 0),
            Err(PolicyError::Insufficient {
                have: 1,
                need: 2,
                ..
            })
        ));
        r.approve("bob-1", &f.bob);
        let v = verify(&r, &f.roster, 0).unwrap();
        assert_eq!(v.distinct_admins, 2);
        assert!(v.warning.is_none());
    }

    #[test]
    fn duplicate_approvals_count_once() {
        let f = fx();
        let mut r = bundle(1, ActionClass::RunScript);
        r.approve("alice-1", &f.alice);
        r.approve("alice-1", &f.alice);
        assert!(verify(&r, &f.roster, 0).is_err());
    }

    #[test]
    fn same_admin_two_keys_passes_with_warning() {
        let f = fx();
        let mut r = bundle(1, ActionClass::IsolateHost);
        r.approve("alice-1", &f.alice);
        r.approve("alice-2", &f.alice2);
        let v = verify(&r, &f.roster, 0).unwrap();
        assert!(v.warning.unwrap().contains("not independent"));
    }

    #[test]
    fn unknown_keys_ignored_and_bad_signatures_rejected() {
        let f = fx();
        let mut r = bundle(1, ActionClass::IsolateHost);
        r.approve("alice-1", &f.alice);
        r.approve("mallory", &key());
        assert!(matches!(
            verify(&r, &f.roster, 0),
            Err(PolicyError::Insufficient { have: 1, .. })
        ));

        // Roster key id but signed with someone else's key
        let mut r = bundle(1, ActionClass::Normal);
        r.approve("bob-1", &f.alice);
        assert!(matches!(
            verify(&r, &f.roster, 0),
            Err(PolicyError::BadSignature { .. })
        ));
    }

    #[test]
    fn tampered_body_rejected() {
        let f = fx();
        let mut r = bundle(1, ActionClass::IsolateHost);
        r.approve("alice-1", &f.alice);
        r.approve("bob-1", &f.bob);
        r.bundle.body = serde_json::json!({"isolate": ["agent-1", "agent-2"]});
        assert!(matches!(
            verify(&r, &f.roster, 0),
            Err(PolicyError::BadSignature { .. })
        ));
        let mut r2 = bundle(1, ActionClass::Normal);
        r2.approve("alice-1", &f.alice);
        r2.bundle.action = ActionClass::RunScript; // escalate class after signing
        assert!(verify(&r2, &f.roster, 0).is_err());
    }

    #[test]
    fn rollback_rejected_and_guard_advances() {
        let f = fx();
        let mut g = PolicyGuard {
            roster: f.roster.clone(),
            last_version: 0,
        };
        let mut b5 = bundle(5, ActionClass::Normal);
        b5.approve("bob-1", &f.bob);
        g.accept(&b5).unwrap();
        assert!(matches!(
            g.accept(&b5),
            Err(PolicyError::Rollback { got: 5, last: 5 })
        ));
        let mut b3 = bundle(3, ActionClass::Normal);
        b3.approve("bob-1", &f.bob);
        assert!(g.accept(&b3).is_err());
    }

    #[test]
    fn roster_change_needs_quorum_of_current_roster() {
        let f = fx();
        let mut g = PolicyGuard {
            roster: f.roster.clone(),
            last_version: 0,
        };
        let mallory = key();
        let evil = AdminRoster::new(vec![entry("m", "mallory", &mallory)]);
        let mut sb = SignedBundle::new(PolicyBundle {
            version: 1,
            action: ActionClass::ChangeRoster,
            issued_at: 0,
            targets: vec![],
            body: serde_json::to_value(&evil).unwrap(),
        });
        sb.approve("alice-1", &f.alice);
        assert!(
            g.accept(&sb).is_err(),
            "one admin cannot replace the roster"
        );
        sb.approve("bob-1", &f.bob);
        g.accept(&sb).unwrap();
        assert_eq!(g.roster, evil);
    }

    #[test]
    fn approved_risky_classes() {
        let r = fx().roster;
        for c in ActionClass::ALL {
            let want = if c == ActionClass::Normal { 1 } else { 2 };
            assert_eq!(r.threshold(c), want, "{c:?}");
        }
    }

    #[test]
    fn threshold_is_configurable() {
        let mut f = fx();
        f.roster.risky_threshold = 3;
        f.roster.overrides.insert(ActionClass::IsolateHost, 1);
        assert_eq!(f.roster.threshold(ActionClass::RunScript), 3);
        assert_eq!(f.roster.threshold(ActionClass::IsolateHost), 1);
        f.roster.risky_threshold = 0;
        assert_eq!(f.roster.threshold(ActionClass::Uninstall), 1, "never zero");
    }
}
