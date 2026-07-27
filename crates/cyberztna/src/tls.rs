//! Self-signed TLS material for local Gate HTTPS.

use std::fs;
use std::path::Path;

/// Ensure cert/key exist; generate self-signed for localhost if missing.
pub fn ensure_self_signed(cert_path: &Path, key_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    if let Some(p) = cert_path.parent() {
        fs::create_dir_all(p)?;
    }
    if let Some(p) = key_path.parent() {
        fs::create_dir_all(p)?;
    }

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, key_pair.serialize_pem())?;
    println!(
        "[gate] generated self-signed TLS:\n  cert {}\n  key  {}",
        cert_path.display(),
        key_path.display()
    );
    println!("[gate] browsers will warn - trust locally or use your own certs");
    Ok(())
}
