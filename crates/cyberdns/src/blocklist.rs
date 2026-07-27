use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn load_blocklist(path: &Path) -> std::io::Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    if !path.exists() {
        return Ok(set);
    }
    let file = fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        set.insert(normalize_domain(line));
    }
    Ok(set)
}

pub fn save_blocklist(path: &Path, set: &BTreeSet<String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "# S2O CyberDNS local blocklist")?;
    for d in set {
        writeln!(file, "{d}")?;
    }
    Ok(())
}

pub fn is_blocked(set: &BTreeSet<String>, domain: &str) -> bool {
    let d = normalize_domain(domain);
    if set.contains(&d) {
        return true;
    }
    for b in set {
        if d == *b || d.ends_with(&format!(".{b}")) {
            return true;
        }
    }
    false
}

/// Allowlist uses the same one-domain-per-line format as the blocklist.
pub fn load_allowlist(path: &Path) -> std::io::Result<BTreeSet<String>> {
    load_blocklist(path)
}

pub fn save_allowlist(path: &Path, set: &BTreeSet<String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "# S2O CyberDNS local allowlist (overrides blocklist + IOC)")?;
    for d in set {
        writeln!(file, "{d}")?;
    }
    Ok(())
}

/// Exact or parent-domain allow (e.g. allow `example.com` → `a.example.com`).
pub fn is_allowed(set: &BTreeSet<String>, domain: &str) -> bool {
    is_blocked(set, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_suffix() {
        let mut s = BTreeSet::new();
        s.insert("corp.internal".into());
        assert!(is_allowed(&s, "corp.internal"));
        assert!(is_allowed(&s, "app.corp.internal"));
        assert!(!is_allowed(&s, "evil.com"));
    }
}
