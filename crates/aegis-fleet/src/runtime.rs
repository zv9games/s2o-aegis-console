//! Agent runtime: persistent state, renewal, heartbeat and policy apply.
//!
//! Trust anchors the agent keeps locally (never taken from the server alone):
//! - CA pins (D6: old + new during a 30-day overlap after a quorum-signed
//!   `RotateCa` bundle),
//! - the admin roster (delivered out of band at enrollment, changed only by a
//!   quorum-signed `ChangeRoster` bundle),
//! - the last applied policy version (anti-rollback).

use crate::agent::{heartbeat_full, renew, FleetEndpoint};
use crate::keystore::AgentKeyStore;
use crate::policy::FleetPolicy;
use crate::proto::{PolicyResult, PolicyStatus, Response};
use crate::server::RotateCaBody;
use crate::{FleetError, FleetResult};
use s2o_audit::SignedHead;
use s2o_policy::{ActionClass, AdminRoster, PolicyGuard, SignedBundle};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaPin {
    pub pem: String,
    /// Unix time after which this pin is dropped; `None` = no expiry.
    pub valid_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub agent_id: String,
    pub cert_pem: String,
    pub not_after_unix: i64,
    pub server_addr: String,
    pub server_name: String,
    pub pins: Vec<CaPin>,
    pub roster: AdminRoster,
    pub last_policy_version: u64,
    pub last_contact: i64,
    pub heartbeat_secs: u64,
    #[serde(default)]
    pub pending_results: Vec<PolicyResult>,
    #[serde(default)]
    pub audit_head: Option<SignedHead>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    Ok {
        renewed: bool,
        results: Vec<PolicyResult>,
    },
    /// Server unreachable; still inside the offline grace period.
    Offline { error: String },
    /// Certificate expired beyond grace: an admin must re-enroll this host.
    ReenrollRequired,
}

impl AgentState {
    pub fn load(path: &Path) -> FleetResult<Self> {
        let s = std::fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(|e| FleetError::Protocol(format!("agent state: {e}")))
    }

    /// Atomic write (tmp + rename).
    pub fn save(&self, path: &Path) -> FleetResult<()> {
        let tmp = path.with_extension("tmp");
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| FleetError::Protocol(e.to_string()))?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Drop expired pins (never the last one).
    pub fn prune_pins(&mut self, now: i64) {
        let keep: Vec<CaPin> = self
            .pins
            .iter()
            .filter(|p| p.valid_until.is_none_or(|t| t > now))
            .cloned()
            .collect();
        if !keep.is_empty() {
            self.pins = keep;
        }
    }

    pub fn endpoint(&self) -> FleetEndpoint {
        FleetEndpoint {
            addr: self.server_addr.clone(),
            server_name: self.server_name.clone(),
            ca_pem: self
                .pins
                .iter()
                .map(|p| p.pem.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    /// Verify and apply bundles in version order. Verification failures are
    /// reported as `Rejected` and do not advance the version.
    pub fn apply_bundles(&mut self, bundles: &[SignedBundle], now: i64) -> Vec<PolicyResult> {
        let mut sorted: Vec<&SignedBundle> = bundles.iter().collect();
        sorted.sort_by_key(|b| b.bundle.version);
        let mut out = Vec::new();
        for sb in sorted {
            let mut guard = PolicyGuard {
                roster: self.roster.clone(),
                last_version: self.last_policy_version,
            };
            let version = sb.bundle.version;
            if let Err(e) = guard.accept(sb) {
                out.push(PolicyResult {
                    version,
                    status: PolicyStatus::Rejected,
                    detail: e.to_string(),
                });
                continue;
            }
            let (status, detail) = self.apply_one(sb, now);
            self.roster = guard.roster;
            self.last_policy_version = guard.last_version;
            out.push(PolicyResult {
                version,
                status,
                detail,
            });
        }
        out
    }

    fn apply_one(&mut self, sb: &SignedBundle, now: i64) -> (PolicyStatus, String) {
        match sb.bundle.action {
            ActionClass::Normal => match sb
                .bundle
                .body
                .get("heartbeat_secs")
                .and_then(|v| v.as_u64())
            {
                Some(h) if (10..=86_400).contains(&h) => {
                    self.heartbeat_secs = h;
                    (PolicyStatus::Applied, format!("heartbeat_secs={h}"))
                }
                _ => (
                    PolicyStatus::NotImplemented,
                    "unknown normal setting".into(),
                ),
            },
            ActionClass::ChangeRoster => (PolicyStatus::Applied, "roster replaced".into()),
            ActionClass::RotateCa => {
                match serde_json::from_value::<RotateCaBody>(sb.bundle.body.clone()) {
                    Ok(b) => {
                        let until = now + b.overlap_days.clamp(1, 365) * 86_400;
                        for p in &mut self.pins {
                            p.valid_until = Some(p.valid_until.map_or(until, |t| t.min(until)));
                        }
                        if !self.pins.iter().any(|p| p.pem == b.new_ca_pem) {
                            self.pins.push(CaPin {
                                pem: b.new_ca_pem,
                                valid_until: None,
                            });
                        }
                        (
                            PolicyStatus::Applied,
                            format!("new CA pinned; old pins valid until {until}"),
                        )
                    }
                    Err(e) => (PolicyStatus::Rejected, format!("bad rotate_ca body: {e}")),
                }
            }
            // Enforcement pillars are deliberately not implemented until they
            // can be tested on real Windows hosts.
            other => (
                PolicyStatus::NotImplemented,
                format!("{other:?} not implemented on this agent"),
            ),
        }
    }

    /// One cycle: renew if due, heartbeat, apply bundles.
    pub async fn tick(
        &mut self,
        keys: &dyn AgentKeyStore,
        policy: &FleetPolicy,
        posture: serde_json::Value,
        cyberid_token: &str,
        now: i64,
    ) -> FleetResult<TickOutcome> {
        self.prune_pins(now);
        let ep = self.endpoint();
        let mut renewed = false;
        if now >= self.not_after_unix && !policy.within_grace(self.not_after_unix, now) {
            return Ok(TickOutcome::ReenrollRequired);
        }
        if policy.needs_renewal(self.not_after_unix, now) {
            let cur = (now < self.not_after_unix).then_some(self.cert_pem.as_str());
            match renew(&ep, keys, &self.agent_id, cur).await {
                Ok(e) => {
                    self.cert_pem = e.cert_pem;
                    self.not_after_unix = e.not_after_unix;
                    renewed = true;
                }
                Err(e) if now < self.not_after_unix => {
                    // Still valid: keep going, retry next tick.
                    eprintln!("[aegisd] renewal failed, will retry: {e}");
                }
                Err(e) => {
                    return Ok(TickOutcome::Offline {
                        error: e.to_string(),
                    })
                }
            }
        }
        let pending = std::mem::take(&mut self.pending_results);
        match heartbeat_full(
            &ep,
            keys,
            &self.cert_pem,
            posture,
            cyberid_token,
            self.last_policy_version,
            pending.clone(),
        )
        .await
        {
            Ok(Response::HeartbeatAck {
                bundles,
                audit_head,
                ..
            }) => {
                self.last_contact = now;
                if audit_head.is_some() {
                    self.audit_head = audit_head;
                }
                let results = self.apply_bundles(&bundles, now);
                self.pending_results = results.clone();
                Ok(TickOutcome::Ok { renewed, results })
            }
            Ok(Response::Error { message }) => {
                self.pending_results = pending;
                Err(FleetError::Rejected(message))
            }
            Ok(other) => {
                self.pending_results = pending;
                Err(FleetError::Protocol(format!(
                    "unexpected response: {other:?}"
                )))
            }
            Err(e) => {
                self.pending_results = pending;
                Ok(TickOutcome::Offline {
                    error: e.to_string(),
                })
            }
        }
    }
}
