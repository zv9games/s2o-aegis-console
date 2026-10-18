//! Fleet certificate authority (online issuing CA for short-lived certs).
//!
//! Threat-model note: this key lives on the fleet server, so a compromised
//! server can mint agent certificates. That only grants the ability to
//! *impersonate an agent to the server*; it cannot make agents run anything,
//! because policy must be signed by offline admin keys (Phase 4).

use crate::{FleetError, FleetResult};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub struct FleetCa {
    cert: Certificate,
    key: KeyPair,
    /// The exact CA certificate agents pin.
    cert_pem: String,
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut b);
    b[0] &= 0x7f; // keep it positive
    SerialNumber::from_slice(&b)
}

impl FleetCa {
    /// Create a new self-signed CA (10-year validity, path length 0).
    pub fn generate(name: &str) -> FleetResult<Self> {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{name} Fleet CA"));
        dn.push(DnType::OrganizationName, "S2O Aegis");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::minutes(5);
        p.not_after = now + Duration::days(3650);
        p.serial_number = Some(random_serial());
        let cert = p.self_signed(&key)?;
        let cert_pem = cert.pem();
        Ok(Self {
            cert,
            key,
            cert_pem,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// SHA-256 fingerprint (hex) of the CA certificate DER, for out-of-band pinning.
    pub fn fingerprint(&self) -> String {
        // Hash the stored PEM's DER, not the in-memory issuer object, which
        // is re-signed on load and therefore has different bytes.
        pem_fingerprint(&self.cert_pem)
    }

    pub fn save(&self, dir: &Path) -> FleetResult<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), &self.cert_pem)?;
        write_secret(&dir.join("ca.key"), &self.key.serialize_pem())
    }

    pub fn load(dir: &Path) -> FleetResult<Self> {
        let cert_pem = std::fs::read_to_string(dir.join("ca.pem"))?;
        let key = KeyPair::from_pem(&std::fs::read_to_string(dir.join("ca.key"))?)?;
        // Rebuild an issuer object from the stored cert; issued certs chain by
        // subject + key, so they validate against the original ca.pem.
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert,
            key,
            cert_pem,
        })
    }

    /// TLS server certificate for the fleet server (1-year validity).
    pub fn issue_server_cert(&self, names: &[String]) -> FleetResult<(String, String)> {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(names.to_vec())?;
        p.distinguished_name.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_default(),
        );
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::minutes(5);
        p.not_after = now + Duration::days(365);
        p.serial_number = Some(random_serial());
        p.use_authority_key_identifier_extension = true;
        let cert = p.signed_by(&key, &self.cert, &self.key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Issue a client certificate for `agent_id` from a CSR, valid for `ttl`.
    pub fn issue_client_cert(
        &self,
        csr_pem: &str,
        agent_id: &str,
        ttl: Duration,
    ) -> FleetResult<(String, i64)> {
        let now = OffsetDateTime::now_utc();
        self.issue_client_cert_with_validity(
            csr_pem,
            agent_id,
            now - Duration::minutes(5),
            now + ttl,
        )
    }

    /// As [`issue_client_cert`](Self::issue_client_cert) with explicit validity (used by tests).
    pub fn issue_client_cert_with_validity(
        &self,
        csr_pem: &str,
        agent_id: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> FleetResult<(String, i64)> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        // Ignore everything the agent asked for except its public key.
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, agent_id);
        p.subject_alt_names = vec![SanType::URI(
            format!("urn:s2o-aegis:agent:{agent_id}")
                .try_into()
                .map_err(|e: rcgen::Error| FleetError::Cert(e))?,
        )];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.is_ca = IsCa::ExplicitNoCa;
        p.not_before = not_before;
        p.not_after = not_after;
        p.serial_number = Some(random_serial());
        p.use_authority_key_identifier_extension = true;
        csr.params = p;
        let cert = csr.signed_by(&self.cert, &self.key)?;
        Ok((cert.pem(), not_after.unix_timestamp()))
    }
}

pub(crate) fn write_secret(path: &Path, contents: &str) -> FleetResult<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// SHA-256 (hex) of the first certificate's DER in `pem`.
pub fn pem_fingerprint(pem: &str) -> String {
    use sha2::Digest;
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .and_then(Result::ok)
        .map(|c| c.to_vec())
        .unwrap_or_default();
    hex::encode(sha2::Sha256::digest(der))
}

/// SHA-256 (hex) of every certificate's DER in `pem`.
pub fn pem_fingerprints(pem: &str) -> Vec<String> {
    use sha2::Digest;
    rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(Result::ok)
        .map(|c| hex::encode(sha2::Sha256::digest(c.as_ref())))
        .collect()
}
