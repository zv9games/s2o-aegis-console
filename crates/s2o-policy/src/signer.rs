//! Admin signing abstraction (decision D7).
//!
//! * [`SoftwareSigner`]: Ed25519 key decrypted from a passphrase-protected
//!   key file (see [`crate::keyfile`]), held in memory only while signing.
//! * TODO(FIDO2): a `Fido2Signer` / PIV signer using a hardware token the
//!   admin already owns. Ed25519 is supported by FIDO2 (COSE alg -8), but the
//!   signature covers authenticator data + client data hash, so verification
//!   in [`crate::verify`] will need an approval variant carrying those fields.

use ed25519_dalek::{Signer, SigningKey};

pub trait PolicySigner {
    fn key_id(&self) -> &str;
    /// Base64url Ed25519 public key.
    fn public_key_b64(&self) -> String;
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

pub struct SoftwareSigner {
    key_id: String,
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn new(key_id: &str, key: SigningKey) -> Self {
        Self {
            key_id: key_id.to_string(),
            key,
        }
    }

    /// Underlying key (software signers only; e.g. the audit head key).
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

impl PolicySigner for SoftwareSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key_b64(&self) -> String {
        crate::public_key_b64(&self.key)
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
}
