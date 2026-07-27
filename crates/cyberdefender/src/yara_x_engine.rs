//! YARA-X engine integration (VirusTotal pure-Rust YARA).
//!
//! Complements yara-lite substr/re/hex with real YARA rule files.

use std::fs;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Scanner};

pub fn default_seed_rule() -> &'static str {
    r#"// S2O Aegis lab YARA-X seed rules (not a full signature feed)
// Place additional .yar files in this directory.

rule s2o_eicar_string {
    meta:
        description = "EICAR test string"
        severity = "high"
        author = "S2O Aegis"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}

rule s2o_powershell_encoded {
    meta:
        description = "Suspicious PowerShell -EncodedCommand"
        severity = "high"
    strings:
        $a = /powershell.{0,80}-e(nc|ncodedcommand)/i
    condition:
        $a
}

rule s2o_nop_sled {
    meta:
        description = "NOP sled (8+ consecutive 0x90)"
        severity = "medium"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}
"#
}

/// Collect .yar / .yara sources under dir (non-recursive or one level).
pub fn collect_rule_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                let ext = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if ext == "yar" || ext == "yara" {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

pub fn write_seed_rules(dir: &Path, force: bool) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("s2o-lab.yar");
    if path.exists() && !force {
        return Ok(path);
    }
    fs::write(&path, default_seed_rule()).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Compiled rule set ready for scanning.
pub struct YaraEngine {
    rules: yara_x::Rules,
    pub sources: Vec<PathBuf>,
    pub rule_count: usize,
}

impl YaraEngine {
    pub fn compile_dir(dir: &Path) -> Result<Self, String> {
        let files = collect_rule_files(dir);
        if files.is_empty() {
            return Err(format!(
                "no .yar/.yara files in {} — run: cyberdefender yara init",
                dir.display()
            ));
        }
        let mut compiler = Compiler::new();
        let mut n = 0usize;
        for f in &files {
            let src = fs::read_to_string(f).map_err(|e| format!("read {}: {e}", f.display()))?;
            compiler
                .add_source(src.as_str())
                .map_err(|e| format!("compile {}: {e}", f.display()))?;
            n += 1;
        }
        let rules = compiler.build();
        // Rules doesn't expose count easily on all versions — count sources as proxy
        // and matching uses actual rules
        let rule_count = rules.iter().count();
        let _ = n;
        Ok(Self {
            rules,
            sources: files,
            rule_count,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn compile_source(source: &str, label: &str) -> Result<Self, String> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| format!("compile {label}: {e}"))?;
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(Self {
            rules,
            sources: vec![PathBuf::from(label)],
            rule_count,
        })
    }

    /// Scan file bytes; return matching rule identifiers.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<String>, String> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner.scan(data).map_err(|e| format!("scan: {e}"))?;
        let mut hits = Vec::new();
        for rule in results.matching_rules() {
            hits.push(rule.identifier().to_string());
        }
        Ok(hits)
    }

    pub fn scan_file(&self, path: &Path, max_bytes: usize) -> Result<Vec<String>, String> {
        let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        use std::io::Read;
        let mut total = 0usize;
        loop {
            let n = f.read(&mut tmp).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n;
            buf.extend_from_slice(&tmp[..n]);
            if total >= max_bytes {
                break;
            }
        }
        self.scan_bytes(&buf)
    }
}

pub fn engine_version() -> &'static str {
    yara_x::VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_rules_hit_eicar() {
        let eng = YaraEngine::compile_source(default_seed_rule(), "seed").unwrap();
        assert!(eng.rule_count >= 1);
        let hits = eng
            .scan_bytes(b"xx EICAR-STANDARD-ANTIVIRUS-TEST-FILE yy")
            .unwrap();
        assert!(hits.iter().any(|h| h.contains("eicar")));
        let nop = [0x90u8; 16];
        let hits2 = eng.scan_bytes(&nop).unwrap();
        assert!(hits2.iter().any(|h| h.contains("nop")));
    }
}
