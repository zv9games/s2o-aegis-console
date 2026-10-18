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
    /// Last *confirmed* Aegis-owned firewall rule set (rollback snapshot).
    #[serde(default)]
    pub fw_applied: Vec<crate::fw::FwRule>,
    /// Applied but not yet confirmed by a successful heartbeat.
    #[serde(default)]
    pub fw_pending: Option<crate::fw::FwPending>,
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

/// Everything an admin hands an agent out of band at enrollment.
pub struct EnrollParams<'a> {
    pub server_addr: &'a str,
    pub server_name: &'a str,
    pub ca_pem: &'a str,
    /// Expected SHA-256 fingerprint of `ca_pem` (printed by `aegis-fleet
    /// init`/`token`). Required: protects against a swapped CA file.
    pub ca_fingerprint: &'a str,
    pub token: &'a str,
    pub hostname: &'a str,
    pub cyberid_public_key: &'a str,
    pub roster: AdminRoster,
}

/// Enroll and build the initial agent state.
pub async fn enroll_new(
    p: EnrollParams<'_>,
    keys: &dyn AgentKeyStore,
    now: i64,
) -> FleetResult<AgentState> {
    let fp = crate::ca::pem_fingerprint(p.ca_pem);
    let want = p.ca_fingerprint.replace(':', "").to_ascii_lowercase();
    if fp != want {
        return Err(FleetError::Rejected(format!(
            "CA fingerprint mismatch: file has {fp}, expected {want}"
        )));
    }
    if p.roster.keys.is_empty() {
        return Err(FleetError::Rejected("admin roster is empty".into()));
    }
    let ep = FleetEndpoint {
        addr: p.server_addr.into(),
        server_name: p.server_name.into(),
        ca_pem: p.ca_pem.into(),
    };
    let e = crate::agent::enroll(&ep, keys, p.token, p.hostname, p.cyberid_public_key).await?;
    Ok(AgentState {
        agent_id: e.agent_id,
        cert_pem: e.cert_pem,
        not_after_unix: e.not_after_unix,
        server_addr: p.server_addr.into(),
        server_name: p.server_name.into(),
        pins: vec![CaPin {
            pem: p.ca_pem.into(),
            valid_until: None,
        }],
        roster: p.roster,
        last_policy_version: 0,
        last_contact: now,
        heartbeat_secs: 60,
        pending_results: Vec::new(),
        audit_head: None,
        fw_applied: Vec::new(),
        fw_pending: None,
    })
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
        self.apply_bundles_with(bundles, now, None)
    }

    /// Like [`apply_bundles`](Self::apply_bundles) with an optional firewall
    /// backend for `ChangeFirewall` (None = not implemented on this OS).
    pub fn apply_bundles_with(
        &mut self,
        bundles: &[SignedBundle],
        now: i64,
        fw: Option<&dyn crate::fw::AegisFirewall>,
    ) -> Vec<PolicyResult> {
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
            let (status, detail) = self.apply_one(sb, now, fw);
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

    fn apply_one(
        &mut self,
        sb: &SignedBundle,
        now: i64,
        fw: Option<&dyn crate::fw::AegisFirewall>,
    ) -> (PolicyStatus, String) {
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
            ActionClass::RetireCa => {
                match serde_json::from_value::<crate::server::RetireCaBody>(sb.bundle.body.clone())
                {
                    Ok(b) => {
                        let keep: Vec<CaPin> = self
                            .pins
                            .iter()
                            .filter(|p| crate::ca::pem_fingerprint(&p.pem) != b.old_ca_fingerprint)
                            .cloned()
                            .collect();
                        if keep.is_empty() {
                            (
                                PolicyStatus::Rejected,
                                "refusing to drop the last CA pin".into(),
                            )
                        } else {
                            let n = self.pins.len() - keep.len();
                            self.pins = keep;
                            for p in &mut self.pins {
                                p.valid_until = None;
                            }
                            (
                                PolicyStatus::Applied,
                                format!("dropped {n} retired CA pin(s)"),
                            )
                        }
                    }
                    Err(e) => (PolicyStatus::Rejected, format!("bad retire_ca body: {e}")),
                }
            }
            ActionClass::ChangeFirewall => match fw {
                None => (
                    PolicyStatus::NotImplemented,
                    "firewall enforcement not implemented on this OS".into(),
                ),
                Some(fw) => self.apply_firewall(sb, now, fw),
            },
            // Enforcement pillars are deliberately not implemented until they
            // can be tested on real Windows hosts.
            other => (
                PolicyStatus::NotImplemented,
                format!("{other:?} not implemented on this agent"),
            ),
        }
    }

    fn apply_firewall(
        &mut self,
        sb: &SignedBundle,
        now: i64,
        fw: &dyn crate::fw::AegisFirewall,
    ) -> (PolicyStatus, String) {
        use crate::fw::{replace_owned, FirewallBody, FwPending, DEFAULT_CONFIRM_SECS};
        let body: FirewallBody = match serde_json::from_value(sb.bundle.body.clone()) {
            Ok(b) => b,
            Err(e) => {
                return (
                    PolicyStatus::Rejected,
                    format!("bad change_firewall body: {e}"),
                )
            }
        };
        if let Err(e) = body.validate() {
            return (PolicyStatus::Rejected, e);
        }
        // An older unconfirmed change is superseded; its snapshot (the last
        // confirmed set) stays the rollback target.
        let snapshot = self.fw_applied.clone();
        if let Err(e) = replace_owned(fw, &body.rules) {
            let restore = replace_owned(fw, &snapshot);
            return (
                PolicyStatus::RolledBack,
                format!(
                    "apply failed: {e}; restore: {}",
                    restore.err().unwrap_or_else(|| "ok".into())
                ),
            );
        }
        let deadline = now + body.confirm_secs.unwrap_or(DEFAULT_CONFIRM_SECS);
        self.fw_pending = Some(FwPending {
            version: sb.bundle.version,
            deadline,
            applied_at: now,
            snapshot,
            new_rules: body.rules,
        });
        (
            PolicyStatus::Applied,
            format!("applied; pending heartbeat confirmation until {deadline}"),
        )
    }

    /// Called after a successful heartbeat: confirm a pending firewall change
    /// applied in an earlier tick.
    pub fn confirm_firewall(&mut self, now: i64) -> Option<PolicyResult> {
        let p = self.fw_pending.as_ref()?;
        if p.applied_at >= now && p.deadline > now {
            // Applied in this same instant; needs a later heartbeat.
            return None;
        }
        let p = self.fw_pending.take()?;
        self.fw_applied = p.new_rules;
        Some(PolicyResult {
            version: p.version,
            status: PolicyStatus::Applied,
            detail: "confirmed by heartbeat".into(),
        })
    }

    /// Restore the snapshot if the confirmation window has passed.
    pub fn check_firewall_deadline(
        &mut self,
        fw: Option<&dyn crate::fw::AegisFirewall>,
        now: i64,
    ) -> Option<PolicyResult> {
        let due = self.fw_pending.as_ref().is_some_and(|p| now >= p.deadline);
        let fw = fw?;
        if !due {
            return None;
        }
        let p = self.fw_pending.take()?;
        let detail = match crate::fw::replace_owned(fw, &p.snapshot) {
            Ok(()) => "no heartbeat confirmation in time; snapshot restored".to_string(),
            Err(e) => {
                // Keep trying on the next tick.
                let d = format!("rollback failed (will retry): {e}");
                self.fw_pending = Some(crate::fw::FwPending {
                    deadline: now,
                    ..p.clone()
                });
                return Some(PolicyResult {
                    version: p.version,
                    status: PolicyStatus::RolledBack,
                    detail: d,
                });
            }
        };
        self.fw_applied = p.snapshot;
        Some(PolicyResult {
            version: p.version,
            status: PolicyStatus::RolledBack,
            detail,
        })
    }

    /// Seconds until the agent must wake (heartbeat interval, or sooner when
    /// a firewall confirmation deadline is near).
    pub fn next_wake_secs(&self, now: i64) -> u64 {
        let hb = self.heartbeat_secs.max(10);
        match &self.fw_pending {
            Some(p) => {
                let half = ((p.deadline - now) / 2).max(5) as u64;
                hb.min(half)
            }
            None => hb,
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
        self.tick_with(keys, policy, posture, cyberid_token, now, None)
            .await
    }

    /// [`tick`](Self::tick) with an optional firewall backend.
    pub async fn tick_with(
        &mut self,
        keys: &dyn AgentKeyStore,
        policy: &FleetPolicy,
        posture: serde_json::Value,
        cyberid_token: &str,
        now: i64,
        fw: Option<&dyn crate::fw::AegisFirewall>,
    ) -> FleetResult<TickOutcome> {
        if let Some(r) = self.check_firewall_deadline(fw, now) {
            eprintln!("[aegisd] firewall v{} rolled back: {}", r.version, r.detail);
            self.pending_results.push(r);
        }
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
                if let Some(h) = audit_head {
                    // Pin the audit key on first sight; never accept a head
                    // that goes backwards (truncated/forked server log).
                    let ok = match &self.audit_head {
                        None => true,
                        Some(old) => old.public_key == h.public_key && h.seq >= old.seq,
                    };
                    if ok {
                        self.audit_head = Some(h);
                    } else {
                        eprintln!("[aegisd] WARNING: server audit head regressed or changed key");
                    }
                }
                let mut results: Vec<PolicyResult> =
                    self.confirm_firewall(now).into_iter().collect();
                results.extend(self.apply_bundles_with(&bundles, now, fw));
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
