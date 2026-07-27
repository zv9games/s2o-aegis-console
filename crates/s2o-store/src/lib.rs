//! Local append-only JSONL event store for the Aegis data package.
//!
//! MVP: file-backed JSONL. Supports optional size-based rotation.

use s2o_schema::AegisEvent;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Default max size before rotation (10 MiB).
pub const DEFAULT_ROTATE_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Keep this many rotated archives (`events.jsonl.1` …).
pub const DEFAULT_ROTATE_KEEP: usize = 5;

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
    /// Rotate when file exceeds this many bytes (0 = never auto-rotate on append).
    rotate_max_bytes: u64,
    rotate_keep: usize,
}

impl EventStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::open_with_rotation(path, DEFAULT_ROTATE_MAX_BYTES, DEFAULT_ROTATE_KEEP)
    }

    pub fn open_with_rotation(
        path: impl AsRef<Path>,
        rotate_max_bytes: u64,
        rotate_keep: usize,
    ) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch file so readers always have a path.
        let _ = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            rotate_max_bytes,
            rotate_keep,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len_bytes(&self) -> StoreResult<u64> {
        Ok(fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0))
    }

    /// Rotate if current file exceeds configured max. Returns true if rotated.
    pub fn rotate_if_needed(&self) -> StoreResult<bool> {
        if self.rotate_max_bytes == 0 {
            return Ok(false);
        }
        let len = self.len_bytes()?;
        if len < self.rotate_max_bytes {
            return Ok(false);
        }
        self.rotate()?;
        Ok(true)
    }

    /// Force rotation: `path` → `path.1`, `path.1` → `path.2`, … drop oldest.
    pub fn rotate(&self) -> StoreResult<()> {
        let keep = self.rotate_keep.max(1);
        // Delete oldest
        let oldest = format!("{}.{}", self.path.display(), keep);
        let _ = fs::remove_file(&oldest);
        // Shift .N-1 -> .N
        for i in (1..keep).rev() {
            let from = format!("{}.{}", self.path.display(), i);
            let to = format!("{}.{}", self.path.display(), i + 1);
            if Path::new(&from).exists() {
                let _ = fs::rename(&from, &to);
            }
        }
        // Current -> .1
        let first = format!("{}.1", self.path.display());
        if self.path.exists() {
            fs::rename(&self.path, &first)?;
        }
        // Fresh empty log
        let _ = OpenOptions::new().create(true).append(true).open(&self.path)?;
        Ok(())
    }

    pub fn append(&self, event: &AegisEvent) -> StoreResult<()> {
        let _ = self.rotate_if_needed()?;
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

    /// Byte length of the log file (0 if missing).
    pub fn byte_len(&self) -> StoreResult<u64> {
        self.len_bytes()
    }

    /// Read new complete JSONL lines since `byte_offset`. Returns (new_offset, events).
    /// Incomplete trailing line is not consumed (offset stays before it).
    pub fn read_since(&self, byte_offset: u64) -> StoreResult<(u64, Vec<AegisEvent>)> {
        use std::io::{Read, Seek, SeekFrom};
        if !self.path.exists() {
            return Ok((0, Vec::new()));
        }
        let mut file = File::open(&self.path)?;
        let len = file.metadata()?.len();
        if byte_offset >= len {
            return Ok((len, Vec::new()));
        }
        file.seek(SeekFrom::Start(byte_offset))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        // Keep incomplete final line for next poll
        let (complete, remainder) = if buf.ends_with('\n') {
            (buf.as_str(), "")
        } else if let Some(pos) = buf.rfind('\n') {
            (&buf[..=pos], &buf[pos + 1..])
        } else {
            // no complete line yet
            return Ok((byte_offset, Vec::new()));
        };
        let mut events = Vec::new();
        for line in complete.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<AegisEvent>(line) {
                events.push(ev);
            }
        }
        let new_offset = len - remainder.len() as u64;
        Ok((new_offset, events))
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

    #[test]
    fn rotate_shifts_files() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("s2o_store_rot_{nanos}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.1", path.display()));
        // tiny max so next append after force still works
        let store = EventStore::open_with_rotation(&path, 1, 3).unwrap();
        let ev = AegisEvent::new(
            "h",
            ProductId::Aegis,
            EventKind::Health,
            EventAction::Observed,
            Severity::Info,
            "one",
        );
        store.append(&ev).unwrap();
        store.rotate().unwrap();
        assert!(Path::new(&format!("{}.1", path.display())).exists());
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.1", path.display()));
    }

    #[test]
    fn read_since_streams_new_lines() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("s2o_store_follow_{nanos}.jsonl"));
        let _ = std::fs::remove_file(&path);
        let store = EventStore::open(&path).unwrap();
        let (off0, e0) = store.read_since(0).unwrap();
        assert!(e0.is_empty());
        store
            .append(&AegisEvent::new(
                "h",
                ProductId::Aegis,
                EventKind::Health,
                EventAction::Observed,
                Severity::Info,
                "a",
            ))
            .unwrap();
        let (off1, e1) = store.read_since(off0).unwrap();
        assert_eq!(e1.len(), 1);
        assert_eq!(e1[0].message, "a");
        let (_, e2) = store.read_since(off1).unwrap();
        assert!(e2.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
