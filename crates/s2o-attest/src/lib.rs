//! Ed25519-signed posture tokens in JWS compact form (`header.payload.sig`,
//! base64url without padding, `alg: EdDSA`).
//!
//! The signing key is a 32-byte seed stored at [`KEY_PATH`] (created on first
//! use, mode 0600 on Unix). It is a per-host key; there is no central
//! authority or key distribution yet (Phase 2).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::Path;

pub const KEY_PATH: &str = ".aegis/cyberid_ed25519.key";

pub type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn load_or_create_key() -> Res<SigningKey> {
    load_or_create_key_at(Path::new(KEY_PATH))
}

pub fn load_or_create_key_at(path: &Path) -> Res<SigningKey> {
    if let Ok(bytes) = std::fs::read(path) {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{} is not a 32-byte Ed25519 seed", path.display()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    std::fs::write(path, key.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().as_bytes())
}

pub fn parse_public_key(b64: &str) -> Res<VerifyingKey> {
    let raw: [u8; 32] = B64
        .decode(b64.trim())?
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&raw)?)
}

pub fn sign(key: &SigningKey, claims: &serde_json::Value) -> Res<String> {
    let header = B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = B64.encode(serde_json::to_vec(claims)?);
    let input = format!("{header}.{payload}");
    let sig = key.sign(input.as_bytes());
    Ok(format!("{input}.{}", B64.encode(sig.to_bytes())))
}

/// Verify signature and `exp`; returns the claims on success.
pub fn verify(vk: &VerifyingKey, token: &str, now: i64) -> Res<serde_json::Value> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err("token must have 3 dot-separated parts".into());
    }
    let header: serde_json::Value = serde_json::from_slice(&B64.decode(parts[0])?)?;
    if header["alg"] != "EdDSA" {
        return Err("unsupported alg (expected EdDSA)".into());
    }
    let sig_bytes: [u8; 64] = B64
        .decode(parts[2])?
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;
    vk.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| "signature verification failed")?;
    let claims: serde_json::Value = serde_json::from_slice(&B64.decode(parts[1])?)?;
    match claims["exp"].as_i64() {
        Some(exp) if exp >= now => Ok(claims),
        Some(_) => Err("token expired".into()),
        None => Err("token has no exp claim".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let claims = serde_json::json!({"sub": "t", "exp": 100, "posture_score": 50});
        let tok = sign(&key, &claims).unwrap();
        assert_eq!(verify(&key.verifying_key(), &tok, 10).unwrap(), claims);
        assert!(verify(&key.verifying_key(), &tok, 101).is_err(), "expired");

        let forged = serde_json::json!({"sub": "t", "exp": 100, "posture_score": 100});
        let parts: Vec<&str> = tok.split('.').collect();
        let bad = format!(
            "{}.{}.{}",
            parts[0],
            B64.encode(forged.to_string()),
            parts[2]
        );
        assert!(verify(&key.verifying_key(), &bad, 10).is_err(), "tampered");

        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(
            verify(&other.verifying_key(), &tok, 10).is_err(),
            "wrong key"
        );
    }

    #[test]
    fn key_persists() {
        let dir = std::env::temp_dir().join(format!("cyberid-test-{}", std::process::id()));
        let path = dir.join("k");
        let a = load_or_create_key_at(&path).unwrap();
        let b = load_or_create_key_at(&path).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        std::fs::remove_dir_all(dir).ok();
    }
}
