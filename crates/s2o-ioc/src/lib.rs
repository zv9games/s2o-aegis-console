//! Local IOC store for ThreatGrid / DNS / Defender consumers.
//!
//! File-backed JSON MVP (`.aegis/ioc-store.json` by default).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const STORE_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum IocError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type IocResult<T> = Result<T, IocError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Domain,
    Ip,
    Hash,
    Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub kind: IocKind,
    pub value: String,
    #[serde(default)]
    pub source: String,
    #[serde(default = "default_severity")]
    pub severity: IocSeverity,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "Utc::now")]
    pub added_at: DateTime<Utc>,
}

fn default_severity() -> IocSeverity {
    IocSeverity::Medium
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStore {
    pub version: String,
    pub updated_at: DateTime<Utc>,
    pub entries: Vec<IocEntry>,
}

impl Default for IocStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION.into(),
            updated_at: Utc::now(),
            entries: Vec::new(),
        }
    }
}

impl IocStore {
    pub fn load(path: impl AsRef<Path>) -> IocResult<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> IocResult<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut store = self.clone();
        store.updated_at = Utc::now();
        store.version = STORE_VERSION.into();
        let text = serde_json::to_string_pretty(&store)?;
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(text.as_bytes())?;
        Ok(())
    }

    pub fn normalize_value(kind: IocKind, value: &str) -> String {
        let v = value.trim();
        match kind {
            IocKind::Domain => v.trim_end_matches('.').to_ascii_lowercase(),
            IocKind::Hash => v.to_ascii_lowercase(),
            IocKind::Ip | IocKind::Url => v.to_string(),
        }
    }

    pub fn upsert(&mut self, mut entry: IocEntry) -> bool {
        entry.value = Self::normalize_value(entry.kind, &entry.value);
        if entry.value.is_empty() {
            return false;
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.kind == entry.kind && e.value == entry.value)
        {
            existing.source = entry.source;
            existing.severity = entry.severity;
            existing.note = entry.note;
            return false;
        }
        self.entries.push(entry);
        true
    }

    pub fn lookup(&self, query: &str) -> Vec<&IocEntry> {
        let q = query.trim().trim_end_matches('.').to_ascii_lowercase();
        let q_raw = query.trim();
        self.entries
            .iter()
            .filter(|e| {
                let v = e.value.to_ascii_lowercase();
                v == q
                    || v == q_raw.to_ascii_lowercase()
                    || (e.kind == IocKind::Domain && (q == v || q.ends_with(&format!(".{v}"))))
                    || e.value == q_raw
            })
            .collect()
    }

    pub fn is_domain_blocked(&self, domain: &str) -> Option<&IocEntry> {
        let d = Self::normalize_value(IocKind::Domain, domain);
        self.entries.iter().find(|e| {
            e.kind == IocKind::Domain && (e.value == d || d.ends_with(&format!(".{}", e.value)))
        })
    }

    pub fn is_hash_blocked(&self, hash: &str) -> Option<&IocEntry> {
        let h = Self::normalize_value(IocKind::Hash, hash);
        self.entries
            .iter()
            .find(|e| e.kind == IocKind::Hash && e.value == h)
    }

    pub fn count_by_kind(&self, kind: IocKind) -> usize {
        self.entries.iter().filter(|e| e.kind == kind).count()
    }

    /// Import domains from a one-domain-per-line blocklist file.
    pub fn import_domain_list(&mut self, path: impl AsRef<Path>, source: &str) -> IocResult<usize> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(0);
        }
        let text = fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if self.upsert(IocEntry {
                kind: IocKind::Domain,
                value: line.into(),
                source: source.into(),
                severity: IocSeverity::High,
                note: Some("imported from domain list".into()),
                added_at: Utc::now(),
            }) {
                n += 1;
            }
        }
        Ok(n)
    }
}

pub fn default_store_path() -> PathBuf {
    PathBuf::from(".aegis/ioc-store.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_match() {
        let mut s = IocStore::default();
        s.upsert(IocEntry {
            kind: IocKind::Domain,
            value: "evil.com".into(),
            source: "test".into(),
            severity: IocSeverity::High,
            note: None,
            added_at: Utc::now(),
        });
        assert!(s.is_domain_blocked("evil.com").is_some());
        assert!(s.is_domain_blocked("a.evil.com").is_some());
        assert!(s.is_domain_blocked("good.com").is_none());
    }
}
