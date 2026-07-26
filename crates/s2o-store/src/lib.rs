//! Local append-only JSONL event store for the Aegis data package.
//!
//! Phase 0 MVP: file-backed, no indexes. Phase 2+ can add SQLite.

use s2o_schema::AegisEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

pub struct EventStore {
    path: PathBuf,
}

impl EventStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch file so readers always have a path.
        let _ = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &AegisEvent) -> StoreResult<()> {
        let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    /// Read up to `limit` most recent events (scans full file — fine for MVP).
    pub fn recent(&self, limit: usize) -> StoreResult<Vec<AegisEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AegisEvent>(&line) {
                Ok(ev) => events.push(ev),
                Err(_) => continue,
            }
        }
        if events.len() > limit {
            let start = events.len() - limit;
            Ok(events.split_off(start))
        } else {
            Ok(events)
        }
    }

    pub fn count(&self) -> StoreResult<usize> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2o_schema::{EventAction, EventKind, ProductId, Severity};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn append_and_recent() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("s2o_store_test_{nanos}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let store = EventStore::open(&path).unwrap();
        let ev = AegisEvent::new(
            "test-host",
            ProductId::Cyberwall,
            EventKind::Health,
            EventAction::Observed,
            Severity::Info,
            "hello",
        );
        store.append(&ev).unwrap();
        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "hello");
        let _ = std::fs::remove_file(&path);
    }
}
