//! Fleet lifecycle settings (decisions recorded 2026-10-18).

use time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetPolicy {
    /// Reject enrollment of agents whose key is not hardware-backed (TPM).
    /// NOTE: until TPM key attestation is implemented, `hardware_backed` is
    /// self-reported by the agent, so this only stops honest misconfigured
    /// agents, not a malicious one.
    pub require_hardware_keys: bool,
    /// Client certificate lifetime (default 24 h).
    pub cert_ttl: Duration,
    /// Agents renew once the certificate is this old (default 12 h).
    pub renew_after: Duration,
    /// How long after certificate expiry an agent may still renew with its
    /// enrolled key instead of a new enrollment token (default 7 days).
    pub offline_grace: Duration,
    /// Default lifetime of one-time enrollment tokens (default 24 h).
    pub token_ttl: Duration,
}

impl Default for FleetPolicy {
    fn default() -> Self {
        Self {
            require_hardware_keys: false,
            cert_ttl: Duration::hours(24),
            renew_after: Duration::hours(12),
            offline_grace: Duration::days(7),
            token_ttl: Duration::hours(24),
        }
    }
}

impl FleetPolicy {
    /// Agent-side: should a cert expiring at `not_after` be renewed at `now`?
    pub fn needs_renewal(&self, not_after: i64, now: i64) -> bool {
        let issued_at = not_after - self.cert_ttl.whole_seconds();
        now >= issued_at + self.renew_after.whole_seconds()
    }

    /// Server-side: may an agent whose cert expired at `not_after` still renew?
    pub fn within_grace(&self, not_after: i64, now: i64) -> bool {
        now <= not_after + self.offline_grace.whole_seconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_decisions() {
        let p = FleetPolicy::default();
        assert_eq!(p.cert_ttl, Duration::hours(24));
        assert_eq!(p.renew_after, Duration::hours(12));
        assert_eq!(p.offline_grace, Duration::days(7));
        assert_eq!(p.token_ttl, Duration::hours(24));
        assert!(!p.require_hardware_keys);
    }

    #[test]
    fn renewal_and_grace_windows() {
        let p = FleetPolicy::default();
        let na = 1_000_000;
        let h = 3600;
        assert!(!p.needs_renewal(na, na - 13 * h));
        assert!(p.needs_renewal(na, na - 12 * h));
        assert!(p.within_grace(na, na + 7 * 24 * h));
        assert!(!p.within_grace(na, na + 7 * 24 * h + 1));
    }
}
