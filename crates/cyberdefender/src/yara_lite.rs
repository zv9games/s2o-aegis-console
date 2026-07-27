//! YARA-lite pattern engine (not full YARA-X).
//!
//! Line format (one rule per line):
//! ```text
//! # comment
//! eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE
//! [high] enc_ps: re:(?i)powershell.*-enc
//! shellcode_nop: hex:90 90 90 90
//! note: substr:Your files have been encrypted
//! ```
//!
//! Kinds:
//! - plain / `substr:` — substring (UTF-8 text or raw bytes)
//! - `re:` — Rust regex against UTF-8 text (lossy for binary)
//! - `hex:` — byte sequence (spaces optional)

use regex::Regex;
use s2o_schema::Severity;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Substr,
    Regex,
    Hex,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: String,
    pub kind: PatternKind,
    pub severity: Severity,
    /// Substring needle (UTF-8)
    pub needle: Option<String>,
    pub re: Option<Regex>,
    pub hex: Option<Vec<u8>>,
}

impl Pattern {
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            PatternKind::Substr => "substr",
            PatternKind::Regex => "re",
            PatternKind::Hex => "hex",
        }
    }

    pub fn display_body(&self) -> String {
        match self.kind {
            PatternKind::Substr => self.needle.clone().unwrap_or_default(),
            PatternKind::Regex => format!(
                "re:{}",
                self.re
                    .as_ref()
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_default()
            ),
            PatternKind::Hex => {
                let h = self.hex.as_ref().map(|b| hex_encode(b)).unwrap_or_default();
                format!("hex:{h}")
            }
        }
    }
}

pub fn default_seed() -> &'static str {
    r#"# S2O yara-lite rules (not full YARA-X)
# Formats:
#   name: plain substring
#   name: substr:text
#   name: re:regex
#   name: hex:DE AD BE EF
#   [high|medium|low|info|critical] name: ...

eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE
[high] powershell_enc: re:(?i)powershell.{0,80}-e(nc|ncodedcommand)
[medium] shellcode_nop_sled: hex:90 90 90 90 90 90 90 90
"#
}

fn parse_severity_token(tok: &str) -> Option<Severity> {
    match tok.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hex contains non-hex digits".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("bad hex digit".into()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Parse a single rule line (without comments). Returns None for blank.
pub fn parse_line(line: &str) -> Result<Option<Pattern>, String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let mut severity = Severity::High;
    let mut rest = line;
    if rest.starts_with('[') {
        if let Some(end) = rest.find(']') {
            let tag = &rest[1..end];
            if let Some(sev) = parse_severity_token(tag) {
                severity = sev;
                rest = rest[end + 1..].trim();
            } else {
                return Err(format!("unknown severity tag [{tag}]"));
            }
        }
    }
    let (name, body) = rest
        .split_once(':')
        .ok_or_else(|| format!("expected name: body, got: {line}"))?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("empty rule name".into());
    }
    let body = body.trim();
    if body.is_empty() {
        return Err(format!("empty body for rule {name}"));
    }

    let (kind, payload) = if let Some(p) = body.strip_prefix("re:") {
        (PatternKind::Regex, p.trim())
    } else if let Some(p) = body.strip_prefix("hex:") {
        (PatternKind::Hex, p.trim())
    } else if let Some(p) = body.strip_prefix("substr:") {
        (PatternKind::Substr, p.trim())
    } else if body.starts_with('/') && body.ends_with('/') && body.len() >= 2 {
        // /regex/ shorthand
        (PatternKind::Regex, &body[1..body.len() - 1])
    } else {
        (PatternKind::Substr, body)
    };

    match kind {
        PatternKind::Substr => Ok(Some(Pattern {
            name,
            kind,
            severity,
            needle: Some(payload.to_string()),
            re: None,
            hex: None,
        })),
        PatternKind::Regex => {
            let re = Regex::new(payload).map_err(|e| format!("regex error in {name}: {e}"))?;
            Ok(Some(Pattern {
                name,
                kind,
                severity,
                needle: None,
                re: Some(re),
                hex: None,
            }))
        }
        PatternKind::Hex => {
            let hex = parse_hex_bytes(payload).map_err(|e| format!("hex error in {name}: {e}"))?;
            if hex.is_empty() {
                return Err(format!("empty hex for {name}"));
            }
            Ok(Some(Pattern {
                name,
                kind,
                severity,
                needle: None,
                re: None,
                hex: Some(hex),
            }))
        }
    }
}

pub fn load_patterns(path: &Path) -> (Vec<Pattern>, Vec<String>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    if !path.exists() {
        return (ok, errs);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            errs.push(format!("read {}: {e}", path.display()));
            return (ok, errs);
        }
    };
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match parse_line(line) {
            Ok(Some(p)) => ok.push(p),
            Ok(None) => {}
            Err(e) => errs.push(format!("line {}: {e}", i + 1)),
        }
    }
    (ok, errs)
}

fn bytes_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Read up to max_bytes; return hit rule name + severity.
pub fn content_pattern_hit(path: &Path, patterns: &[Pattern], max_bytes: usize) -> Option<(String, Severity)> {
    if patterns.is_empty() {
        return None;
    }
    let Ok(mut f) = File::open(path) else {
        return None;
    };
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut total = 0usize;
    loop {
        let Ok(n) = f.read(&mut tmp) else {
            return None;
        };
        if n == 0 {
            break;
        }
        total += n;
        buf.extend_from_slice(&tmp[..n]);
        if total >= max_bytes {
            break;
        }
    }

    let text_lossy = String::from_utf8_lossy(&buf);

    for p in patterns {
        let hit = match p.kind {
            PatternKind::Substr => {
                if let Some(ref n) = p.needle {
                    text_lossy.contains(n.as_str()) || bytes_contains(&buf, n.as_bytes())
                } else {
                    false
                }
            }
            PatternKind::Regex => p.re.as_ref().map(|r| r.is_match(&text_lossy)).unwrap_or(false),
            PatternKind::Hex => p
                .hex
                .as_ref()
                .map(|h| bytes_contains(&buf, h))
                .unwrap_or(false),
        };
        if hit {
            return Some((p.name.clone(), p.severity));
        }
    }
    None
}

/// Test patterns against a raw buffer or string (for CLI test).
pub fn match_buffer<'a>(patterns: &'a [Pattern], buf: &[u8]) -> Vec<&'a Pattern> {
    let text_lossy = String::from_utf8_lossy(buf);
    let mut hits = Vec::new();
    for p in patterns {
        let hit = match p.kind {
            PatternKind::Substr => p
                .needle
                .as_ref()
                .map(|n| text_lossy.contains(n.as_str()) || bytes_contains(buf, n.as_bytes()))
                .unwrap_or(false),
            PatternKind::Regex => p.re.as_ref().map(|r| r.is_match(&text_lossy)).unwrap_or(false),
            PatternKind::Hex => p.hex.as_ref().map(|h| bytes_contains(buf, h)).unwrap_or(false),
        };
        if hit {
            hits.push(p);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kinds() {
        let s = parse_line("eicar: EICAR").unwrap().unwrap();
        assert_eq!(s.kind, PatternKind::Substr);
        let r = parse_line("[high] enc: re:(?i)powershell").unwrap().unwrap();
        assert_eq!(r.kind, PatternKind::Regex);
        assert_eq!(r.severity, Severity::High);
        let h = parse_line("nop: hex:90 90").unwrap().unwrap();
        assert_eq!(h.kind, PatternKind::Hex);
        assert_eq!(h.hex.as_ref().unwrap(), &[0x90, 0x90]);
    }

    #[test]
    fn match_hex_and_re() {
        let patterns = vec![
            parse_line("nop: hex:9090").unwrap().unwrap(),
            parse_line("ps: re:(?i)powershell").unwrap().unwrap(),
        ];
        let hits = match_buffer(&patterns, b"xx\x90\x90yy POWERSHELL -enc");
        assert_eq!(hits.len(), 2);
    }
}
