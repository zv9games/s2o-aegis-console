//! Tamper-evident, hash-chained, append-only audit log (JSON Lines).
//!
//! Each entry stores `prev_hash` (hash of the previous entry, or 64 zeros)
//! and its own `hash = SHA-256("s2o-audit-v1\n" || canonical JSON of the
//! entry without `hash`)`. Editing, deleting, inserting or reordering any
//! entry breaks the chain at that point.
//!
//! A hash chain alone cannot detect **truncation of the newest entries**. For
//! that, a holder of the log periodically produces a [`SignedHead`] (seq +
//! hash signed with Ed25519) and replicates it elsewhere (agents, a witness);
//! [`verify_against_head`] then detects truncation or a forked history.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub data: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Serialize)]
struct Unhashed<'a> {
    seq: u64,
    ts: i64,
    actor: &'a str,
    action: &'a str,
    data: &'a serde_json::Value,
    prev_hash: &'a str,
}

impl Entry {
    pub fn compute_hash(&self) -> String {
        let u = Unhashed {
            seq: self.seq,
            ts: self.ts,
            actor: &self.actor,
            action: &self.action,
            data: &self.data,
            prev_hash: &self.prev_hash,
        };
        // Round-trip through Value so nested object keys are sorted.
        let v = serde_json::to_value(&u).expect("serializes");
        let mut h = Sha256::new();
        h.update(b"s2o-audit-v1\n");
        h.update(serde_json::to_vec(&v).expect("serializes"));
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(String),
    #[error("line {line}: unparseable entry")]
    Parse { line: usize },
    #[error("entry {seq}: sequence break (expected {expected})")]
    Sequence { seq: u64, expected: u64 },
    #[error("entry {seq}: prev_hash does not match previous entry")]
    Chain { seq: u64 },
    #[error("entry {seq}: hash mismatch (entry modified)")]
    Hash { seq: u64 },
    #[error("log ends at seq {have:?} but signed head is at seq {head}")]
    Truncated { have: Option<u64>, head: u64 },
    #[error("entry {seq} does not match the signed head (forked history)")]
    Fork { seq: u64 },
    #[error("signed head signature invalid")]
    HeadSignature,
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditError::Io(e.to_string())
    }
}

pub struct AuditLog {
    path: PathBuf,
    last: Option<(u64, String)>,
}

impl AuditLog {
    /// Open (verifying the existing chain) or create a log.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let last = if path.exists() {
            verify_file(path)?.last().map(|e| (e.seq, e.hash.clone()))
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            last,
        })
    }

    pub fn append(
        &mut self,
        ts: i64,
        actor: &str,
        action: &str,
        data: serde_json::Value,
    ) -> Result<Entry, AuditError> {
        // Another process (CLI vs. running server) may append concurrently:
        // hold an exclusive OS lock (flock / LockFileEx) on a sidecar file
        // for read-tail + append, so the chain never forks.
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut lock_path = self.path.clone().into_os_string();
        lock_path.push(".lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(PathBuf::from(lock_path))?;
        let mut lock = fd_lock::RwLock::new(lock_file);
        let _guard = lock.write()?;
        if self.path.exists() {
            if let Some(e) = read_file(&self.path)?.last() {
                self.last = Some((e.seq, e.hash.clone()));
            }
        }
        let (seq, prev) = match &self.last {
            Some((s, h)) => (s + 1, h.clone()),
            None => (0, GENESIS.to_string()),
        };
        let mut e = Entry {
            seq,
            ts,
            actor: actor.into(),
            action: action.into(),
            data,
            prev_hash: prev,
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&e).expect("serializes"))?;
        f.sync_data()?;
        self.last = Some((e.seq, e.hash.clone()));
        Ok(e)
    }

    /// Sign the current head.
    pub fn sign_head(&self, key: &SigningKey) -> Option<SignedHead> {
        self.last
            .as_ref()
            .map(|(seq, hash)| SignedHead::sign(*seq, hash, key))
    }
}

/// Verify an in-memory sequence of entries.
pub fn verify_entries(entries: &[Entry]) -> Result<(), AuditError> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(AuditError::Sequence {
                seq: e.seq,
                expected: i as u64,
            });
        }
        if e.prev_hash != prev {
            return Err(AuditError::Chain { seq: e.seq });
        }
        if e.compute_hash() != e.hash {
            return Err(AuditError::Hash { seq: e.seq });
        }
        prev = e.hash.clone();
    }
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<Entry>, AuditError> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line).map_err(|_| AuditError::Parse { line: i + 1 })?);
    }
    Ok(out)
}

pub fn verify_file(path: &Path) -> Result<Vec<Entry>, AuditError> {
    let entries = read_file(path)?;
    verify_entries(&entries)?;
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub seq: u64,
    pub hash: String,
    pub public_key: String,
    pub signature: String,
}

impl SignedHead {
    fn msg(seq: u64, hash: &str) -> Vec<u8> {
        format!("s2o-audit-head-v1\n{seq}\n{hash}").into_bytes()
    }

    pub fn sign(seq: u64, hash: &str, key: &SigningKey) -> Self {
        Self {
            seq,
            hash: hash.into(),
            public_key: B64.encode(key.verifying_key().as_bytes()),
            signature: B64.encode(key.sign(&Self::msg(seq, hash)).to_bytes()),
        }
    }

    /// Verify the signature with an expected (pinned) public key.
    pub fn verify_sig(&self, expected: &VerifyingKey) -> Result<(), AuditError> {
        let sig: [u8; 64] = B64
            .decode(&self.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(AuditError::HeadSignature)?;
        expected
            .verify(
                &Self::msg(self.seq, &self.hash),
                &Signature::from_bytes(&sig),
            )
            .map_err(|_| AuditError::HeadSignature)
    }
}

/// Verify chain integrity and that the log still contains the signed head.
pub fn verify_against_head(
    entries: &[Entry],
    head: &SignedHead,
    key: &VerifyingKey,
) -> Result<(), AuditError> {
    head.verify_sig(key)?;
    verify_entries(entries)?;
    match entries.get(head.seq as usize) {
        None => Err(AuditError::Truncated {
            have: entries.last().map(|e| e.seq),
            head: head.seq,
        }),
        Some(e) if e.hash != head.hash => Err(AuditError::Fork { seq: head.seq }),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("s2o-audit-{}-{name}.jsonl", std::process::id()))
    }

    fn sample(path: &Path, n: u64) -> AuditLog {
        let _ = std::fs::remove_file(path);
        let mut log = AuditLog::open(path).unwrap();
        for i in 0..n {
            log.append(
                i as i64,
                "admin:greg",
                "policy.approve",
                serde_json::json!({"v": i, "k": {"b": 1, "a": 2}}),
            )
            .unwrap();
        }
        log
    }

    fn rewrite(path: &Path, entries: &[Entry]) {
        let s: String = entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        std::fs::write(path, s).unwrap();
    }

    #[test]
    fn clean_log_verifies_and_reopen_continues_chain() {
        let p = tmp("clean");
        drop(sample(&p, 5));
        let mut log = AuditLog::open(&p).unwrap();
        let e = log
            .append(9, "agent:x", "heartbeat", serde_json::json!({}))
            .unwrap();
        assert_eq!(e.seq, 5);
        assert_eq!(verify_file(&p).unwrap().len(), 6);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn modified_entry_detected() {
        let p = tmp("mod");
        sample(&p, 5);
        let mut es = read_file(&p).unwrap();
        es[2].data = serde_json::json!({"v": 999});
        rewrite(&p, &es);
        assert_eq!(verify_file(&p).unwrap_err(), AuditError::Hash { seq: 2 });
        // Recomputing the entry's own hash just moves the break to the next link
        es[2].hash = es[2].compute_hash();
        rewrite(&p, &es);
        assert_eq!(verify_file(&p).unwrap_err(), AuditError::Chain { seq: 3 });
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn deleted_and_reordered_entries_detected() {
        let p = tmp("del");
        sample(&p, 5);
        let es = read_file(&p).unwrap();
        let mut del = es.clone();
        del.remove(1);
        assert!(matches!(
            verify_entries(&del),
            Err(AuditError::Sequence {
                seq: 2,
                expected: 1
            })
        ));
        let mut re = es.clone();
        re.swap(1, 2);
        assert!(verify_entries(&re).is_err());
        assert!(AuditLog::open(&p).is_ok());
        rewrite(&p, &del);
        assert!(AuditLog::open(&p).is_err(), "open refuses a broken chain");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn truncation_and_fork_detected_with_signed_head() {
        let p = tmp("head");
        let log = sample(&p, 5);
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let head = log.sign_head(&key).unwrap();
        let es = read_file(&p).unwrap();
        let vk = key.verifying_key();
        verify_against_head(&es, &head, &vk).unwrap();

        // Truncation passes plain chain verification but not the head check
        let short = &es[..3];
        verify_entries(short).unwrap();
        assert!(matches!(
            verify_against_head(short, &head, &vk),
            Err(AuditError::Truncated { .. })
        ));

        // Rewritten history (re-chained from scratch) is caught as a fork
        let p2 = tmp("fork");
        let _ = std::fs::remove_file(&p2);
        let mut forged = AuditLog::open(&p2).unwrap();
        for i in 0..5 {
            forged
                .append(i, "admin:mallory", "policy.approve", serde_json::json!({}))
                .unwrap();
        }
        let fes = read_file(&p2).unwrap();
        assert!(matches!(
            verify_against_head(&fes, &head, &vk),
            Err(AuditError::Fork { seq: 4 })
        ));

        // Head signed by another key is rejected
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        assert_eq!(
            verify_against_head(&es, &head, &other.verifying_key()),
            Err(AuditError::HeadSignature)
        );
        std::fs::remove_file(p).ok();
        std::fs::remove_file(p2).ok();
    }
}

#[cfg(test)]
mod multi_writer {
    use super::*;

    #[test]
    fn two_handles_do_not_fork() {
        let d = std::env::temp_dir().join(format!("s2o-audit-mw-{}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        let mut a = AuditLog::open(&d).unwrap();
        let mut b = AuditLog::open(&d).unwrap();
        a.append(1, "x", "a", serde_json::json!({})).unwrap();
        b.append(2, "y", "b", serde_json::json!({})).unwrap();
        a.append(3, "x", "c", serde_json::json!({})).unwrap();
        assert_eq!(verify_file(&d).unwrap().len(), 3);
        let _ = std::fs::remove_file(&d);
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn concurrent_threads_keep_chain_linear() {
        let d = std::env::temp_dir().join(format!("s2o-audit-lock-{}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        let hs: Vec<_> = (0..4)
            .map(|t| {
                let d = d.clone();
                std::thread::spawn(move || {
                    let mut l = AuditLog::open(&d).unwrap();
                    for i in 0..10 {
                        l.append(i, &format!("t{t}"), "x", serde_json::json!({}))
                            .unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(verify_file(&d).unwrap().len(), 40);
        let _ = std::fs::remove_file(&d);
    }
}
