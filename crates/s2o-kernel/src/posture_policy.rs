//! Posture scoring shared by policy gate, CyberID, and Gate/ZTNA.

use std::path::{Path, PathBuf};

use s2o_schema::{
    AegisEvent, EventAction, EventKind, PosturePolicyIntent, ProductId, Severity,
};
use s2o_store::EventStore;
use serde::Serialize;

use crate::host::host_id;
use crate::platform::FirewallEngineHandle;
use crate::policy::{KernelError, KernelResult};
use cyberwall_core::FirewallEngine;

/// Default suite data directory: `$AEGIS_DATA_DIR` if set, else `.aegis`.
pub fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_DATA_DIR") {
        let t = p.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    PathBuf::from(".aegis")
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureCheck {
    pub id: &'static str,
    pub pass: bool,
    pub weight: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureScore {
    pub score: u32,
    pub max_score: u32,
    pub checks: Vec<PostureCheck>,
}

impl PostureScore {
    pub fn passes(&self, min_score: u32) -> bool {
        self.score >= min_score
    }
}

/// Compute lightweight suite posture (T0 signals) using [`default_data_dir`].
pub async fn compute_posture_score(fw: &FirewallEngineHandle) -> KernelResult<PostureScore> {
    compute_posture_score_at(fw, &default_data_dir()).await
}

/// Compute posture using an explicit data directory (IOC store, DNS blocklist, suite root).
pub async fn compute_posture_score_at(
    fw: &FirewallEngineHandle,
    data_dir: &Path,
) -> KernelResult<PostureScore> {
    let st = FirewallEngine::get_status(fw.as_ref())
        .await
        .map_err(|e| KernelError::Engine(e.to_string()))?;

    let mut checks = Vec::new();
    checks.push(PostureCheck {
        id: "firewall_enabled",
        pass: st.enabled,
        weight: 30,
        detail: format!("enabled={} backend={}", st.enabled, st.backend_driver),
    });
    checks.push(PostureCheck {
        id: "defender_or_av",
        pass: st.defender_active || !cfg!(windows),
        weight: 25,
        detail: if cfg!(windows) {
            format!("WinDefend active={}", st.defender_active)
        } else {
            "non-Windows: AV N/A (pass)".into()
        },
    });
    let ioc_path = data_dir.join("ioc-store.json");
    let ioc_ok = ioc_path.exists();
    checks.push(PostureCheck {
        id: "threatgrid_ioc_store",
        pass: ioc_ok,
        weight: 15,
        detail: if ioc_ok {
            format!("IOC store present ({})", ioc_path.display())
        } else {
            format!("missing {}", ioc_path.display())
        },
    });
    let bl_path = data_dir.join("dns-blocklist.txt");
    let bl_ok = bl_path.exists();
    checks.push(PostureCheck {
        id: "dns_blocklist",
        pass: bl_ok,
        weight: 15,
        detail: if bl_ok {
            format!("DNS blocklist present ({})", bl_path.display())
        } else {
            format!("missing {}", bl_path.display())
        },
    });
    // suite data dir present ≈ partial operational maturity (encryption is cyberid-deep)
    let suite_ok = data_dir.exists();
    checks.push(PostureCheck {
        id: "suite_datadir",
        pass: suite_ok,
        weight: 15,
        detail: if suite_ok {
            format!("{} data dir present", data_dir.display())
        } else {
            format!("missing {}", data_dir.display())
        },
    });

    let score = checks.iter().map(|c| if c.pass { c.weight } else { 0 }).sum();
    let max_score = checks.iter().map(|c| c.weight).sum();
    Ok(PostureScore {
        score,
        max_score,
        checks,
    })
}

pub async fn apply_posture_intent(
    intent: &PosturePolicyIntent,
    fw: &FirewallEngineHandle,
    store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    apply_posture_intent_at(intent, fw, store, &default_data_dir()).await
}

/// Apply posture intent using an explicit data directory for suite signals.
pub async fn apply_posture_intent_at(
    intent: &PosturePolicyIntent,
    fw: &FirewallEngineHandle,
    store: Option<&EventStore>,
    data_dir: &Path,
) -> KernelResult<Vec<String>> {
    let min = intent.min_score.unwrap_or(0);
    let report = compute_posture_score_at(fw, data_dir).await?;
    let pass = report.passes(min);

    let mut applied = vec![
        format!("posture.score={}", report.score),
        format!("posture.min={min}"),
    ];
    if pass {
        applied.push("posture.gate=allow".into());
    } else {
        applied.push("posture.gate=deny".into());
    }

    if let Some(store) = store {
        let ev = AegisEvent::new(
            host_id(),
            ProductId::CyberId,
            EventKind::Auth,
            if pass {
                EventAction::Allowed
            } else {
                EventAction::Blocked
            },
            if pass {
                Severity::Info
            } else {
                Severity::High
            },
            format!(
                "policy posture score={} min={min} pass={pass}",
                report.score
            ),
        )
        .with_attr("score", serde_json::json!(report.score))
        .with_attr("min_score", serde_json::json!(min))
        .with_attr("pass", serde_json::json!(pass));
        store.append(&ev)?;
    }

    if !pass {
        return Err(KernelError::Policy(format!(
            "posture gate failed: score={} < min={min}",
            report.score
        )));
    }

    Ok(applied)
}
