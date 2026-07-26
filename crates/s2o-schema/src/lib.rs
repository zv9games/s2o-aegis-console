//! S2O Aegis shared schema — the suite data package contract.
//!
//! Every product engine should emit [`AegisEvent`] values rather than inventing
//! ad-hoc log lines. Version the schema carefully; consumers (CyberLog, ThreatGrid,
//! Console) depend on stability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductId {
    Cyberwall,
    CyberMesh,
    CyberDefender,
    CyberEdr,
    CyberLog,
    ThreatGrid,
    CyberDns,
    CyberId,
    Gate,
    Aegis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Process,
    File,
    NetFlow,
    Dns,
    Auth,
    Policy,
    Alert,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Observed,
    Blocked,
    Quarantined,
    Allowed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ioc {
    Ip(String),
    Domain(String),
    Hash(String),
    Url(String),
}

/// Canonical security event for the Aegis data package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisEvent {
    pub schema_version: String,
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub host_id: String,
    pub product: ProductId,
    pub severity: Severity,
    pub kind: EventKind,
    pub action: EventAction,
    pub message: String,
    #[serde(default)]
    pub attrs: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub iocs: Vec<Ioc>,
}

impl AegisEvent {
    pub fn new(
        host_id: impl Into<String>,
        product: ProductId,
        kind: EventKind,
        action: EventAction,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            id: Uuid::new_v4(),
            ts: Utc::now(),
            host_id: host_id.into(),
            product,
            severity,
            kind,
            action,
            message: message.into(),
            attrs: serde_json::Map::new(),
            iocs: Vec::new(),
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }

    pub fn with_ioc(mut self, ioc: Ioc) -> Self {
        self.iocs.push(ioc);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let ev = AegisEvent::new(
            "host-1",
            ProductId::Cyberwall,
            EventKind::Policy,
            EventAction::Allowed,
            Severity::Info,
            "firewall enabled",
        )
        .with_attr("profile", serde_json::json!("private"));
        let s = serde_json::to_string(&ev).unwrap();
        let back: AegisEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.product, ProductId::Cyberwall);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }
}
