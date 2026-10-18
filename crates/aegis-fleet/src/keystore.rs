//! Agent private-key storage.
//!
//! [`SoftwareKeyStore`] keeps a PKCS#8 key on disk (0600 on Unix) or in
//! memory. It is a **fallback**: the key can be copied by anyone with admin
//! rights on the host. The server records `hardware_backed = false` for these
//! agents so it is visible in inventory.
//!
//! TODO(TPM): implement `TpmKeyStore` (Windows CNG "Microsoft Platform Crypto
//! Provider", non-exportable P-256 key) behind this trait. rcgen can sign the
//! CSR through `rcgen::RemoteKeyPair`; rustls client auth needs a custom
//! `rustls::sign::SigningKey` that calls into CNG.

use crate::FleetResult;
use rcgen::KeyPair;
use std::path::{Path, PathBuf};

pub trait AgentKeyStore: Send + Sync {
    /// Key pair used for the CSR and TLS client auth.
    fn key_pair(&self) -> &KeyPair;
    /// True only when the private key cannot leave a hardware module.
    fn is_hardware_backed(&self) -> bool;
    /// PKCS#8 DER of the private key for rustls. Hardware stores will not
    /// support this and need a custom signer (see module docs).
    fn private_key_der(&self) -> Option<Vec<u8>>;
}

pub struct SoftwareKeyStore {
    key: KeyPair,
    path: Option<PathBuf>,
}

impl SoftwareKeyStore {
    /// New ECDSA P-256 key, memory only.
    pub fn ephemeral() -> FleetResult<Self> {
        Ok(Self {
            key: KeyPair::generate()?,
            path: None,
        })
    }

    /// Load the key at `path` or create and persist a new one.
    pub fn load_or_create(path: &Path) -> FleetResult<Self> {
        if let Ok(pem) = std::fs::read_to_string(path) {
            return Ok(Self {
                key: KeyPair::from_pem(&pem)?,
                path: Some(path.to_path_buf()),
            });
        }
        let key = KeyPair::generate()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, key.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            key,
            path: Some(path.to_path_buf()),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl AgentKeyStore for SoftwareKeyStore {
    fn key_pair(&self) -> &KeyPair {
        &self.key
    }
    fn is_hardware_backed(&self) -> bool {
        false
    }
    fn private_key_der(&self) -> Option<Vec<u8>> {
        Some(self.key.serialize_der())
    }
}
