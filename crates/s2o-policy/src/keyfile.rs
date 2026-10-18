//! Passphrase-encrypted admin key files (decision D7).
//!
//! Format (JSON): Argon2id (m = 64 MiB, t = 3, p = 1) derives a 32-byte key
//! from the passphrase and a random 16-byte salt; XChaCha20-Poly1305 with a
//! random 24-byte nonce encrypts the 32-byte Ed25519 seed. The key id and
//! public key are bound as associated data so they cannot be swapped.
//! Keep these files **off the fleet server**.

use crate::signer::SoftwareSigner;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u8,
    pub key_id: String,
    pub public_key: String,
    pub kdf: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("wrong passphrase or corrupted key file")]
    Decrypt,
    #[error("unsupported key file: {0}")]
    Format(String),
    #[error("passphrase must be at least 12 characters")]
    WeakPassphrase,
}

const MIN_PASSPHRASE: usize = 12;

fn derive(pass: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], KeyFileError> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| KeyFileError::Format(e.to_string()))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|e| KeyFileError::Format(e.to_string()))?;
    Ok(out)
}

fn aad(key_id: &str, public_key: &str) -> Vec<u8> {
    format!("s2o-admin-key-v1\n{key_id}\n{public_key}").into_bytes()
}

impl KeyFile {
    /// Encrypt `key` under `passphrase` with production KDF parameters.
    pub fn encrypt(key_id: &str, key: &SigningKey, passphrase: &str) -> Result<Self, KeyFileError> {
        Self::encrypt_with_params(key_id, key, passphrase, 64 * 1024, 3, 1)
    }

    /// As [`encrypt`](Self::encrypt) with explicit Argon2 cost (tests use small values).
    pub fn encrypt_with_params(
        key_id: &str,
        key: &SigningKey,
        passphrase: &str,
        m: u32,
        t: u32,
        p: u32,
    ) -> Result<Self, KeyFileError> {
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(KeyFileError::WeakPassphrase);
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut k = derive(passphrase, &salt, m, t, p)?;
        let public_key = crate::public_key_b64(key);
        let mut seed = key.to_bytes();
        let ct = XChaCha20Poly1305::new((&k).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &seed,
                    aad: &aad(key_id, &public_key),
                },
            )
            .map_err(|_| KeyFileError::Decrypt)?;
        k.zeroize();
        seed.zeroize();
        Ok(Self {
            version: 1,
            key_id: key_id.into(),
            public_key,
            kdf: "argon2id".into(),
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
            salt: B64.encode(salt),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ct),
        })
    }

    pub fn decrypt(&self, passphrase: &str) -> Result<SoftwareSigner, KeyFileError> {
        if self.version != 1 || self.kdf != "argon2id" {
            return Err(KeyFileError::Format("expected version 1 / argon2id".into()));
        }
        let dec = |s: &str| {
            B64.decode(s)
                .map_err(|e| KeyFileError::Format(e.to_string()))
        };
        let (salt, nonce, ct) = (dec(&self.salt)?, dec(&self.nonce)?, dec(&self.ciphertext)?);
        if nonce.len() != 24 {
            return Err(KeyFileError::Format("bad nonce".into()));
        }
        let mut k = derive(passphrase, &salt, self.m_cost_kib, self.t_cost, self.p_cost)?;
        let pt = XChaCha20Poly1305::new((&k).into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad(&self.key_id, &self.public_key),
                },
            )
            .map_err(|_| KeyFileError::Decrypt);
        k.zeroize();
        let mut pt = pt?;
        let seed: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| KeyFileError::Decrypt)?;
        pt.zeroize();
        let key = SigningKey::from_bytes(&seed);
        if crate::public_key_b64(&key) != self.public_key {
            return Err(KeyFileError::Decrypt);
        }
        Ok(SoftwareSigner::new(&self.key_id, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::PolicySigner;

    fn small(key: &SigningKey, pass: &str) -> Result<KeyFile, KeyFileError> {
        KeyFile::encrypt_with_params("greg-1", key, pass, 1024, 1, 1)
    }

    #[test]
    fn roundtrip_and_wrong_passphrase() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let kf = small(&key, "correct horse battery").unwrap();
        let json = serde_json::to_string(&kf).unwrap();
        assert!(
            !json.contains(&B64.encode(key.to_bytes())),
            "seed must not appear in plaintext"
        );
        let kf: KeyFile = serde_json::from_str(&json).unwrap();
        let s = kf.decrypt("correct horse battery").unwrap();
        assert_eq!(s.public_key_b64(), crate::public_key_b64(&key));
        assert!(matches!(
            kf.decrypt("wrong horse battery"),
            Err(KeyFileError::Decrypt)
        ));
    }

    #[test]
    fn tampered_metadata_or_ciphertext_rejected() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let kf = small(&key, "correct horse battery").unwrap();
        let mut swapped = kf.clone();
        swapped.key_id = "bob-1".into();
        assert!(swapped.decrypt("correct horse battery").is_err());
        let mut ct = kf.clone();
        let mut raw = B64.decode(&ct.ciphertext).unwrap();
        raw[0] ^= 1;
        ct.ciphertext = B64.encode(raw);
        assert!(ct.decrypt("correct horse battery").is_err());
    }

    #[test]
    fn weak_passphrase_refused() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(matches!(
            small(&key, "short"),
            Err(KeyFileError::WeakPassphrase)
        ));
    }
}
