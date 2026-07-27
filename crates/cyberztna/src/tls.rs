//! TLS material for Gate HTTPS and optional mTLS (client cert auth).

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

/// Lab mTLS PKI layout under `dir`.
#[derive(Debug, Clone)]
pub struct MtlsPaths {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl MtlsPaths {
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            ca_cert: dir.join("ca.pem"),
            ca_key: dir.join("ca-key.pem"),
            server_cert: dir.join("server.pem"),
            server_key: dir.join("server-key.pem"),
            client_cert: dir.join("client.pem"),
            client_key: dir.join("client-key.pem"),
            dir,
        }
    }

    pub fn complete(&self) -> bool {
        self.ca_cert.exists()
            && self.server_cert.exists()
            && self.server_key.exists()
            && self.client_cert.exists()
            && self.client_key.exists()
    }
}

/// Generate a local lab CA, server cert (for Gate), and one client cert.
pub fn generate_mtls_pki(
    dir: &Path,
    client_cn: &str,
    force: bool,
) -> Result<MtlsPaths, Box<dyn std::error::Error>> {
    let paths = MtlsPaths::in_dir(dir);
    if paths.complete() && !force {
        println!(
            "[gate] mTLS PKI already present in {} (use --force to regenerate)",
            dir.display()
        );
        return Ok(paths);
    }
    fs::create_dir_all(dir)?;

    // CA
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "S2O Gate Lab CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "S2O Aegis");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server (TLS listener identity)
    let mut server_params = CertificateParams::new(vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ])?;
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "s2o-gate");
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // Client (device / operator)
    let mut client_params = CertificateParams::new(Vec::<String>::new())?;
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, client_cn);
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()?;
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key)?;

    fs::write(&paths.ca_cert, ca_cert.pem())?;
    fs::write(&paths.ca_key, ca_key.serialize_pem())?;
    fs::write(&paths.server_cert, server_cert.pem())?;
    fs::write(&paths.server_key, server_key.serialize_pem())?;
    fs::write(&paths.client_cert, client_cert.pem())?;
    fs::write(&paths.client_key, client_key.serialize_pem())?;

    println!("[gate] mTLS lab PKI written to {}", dir.display());
    println!("  CA     : {}", paths.ca_cert.display());
    println!("  server : {} + {}", paths.server_cert.display(), paths.server_key.display());
    println!("  client : {} + {} (CN={client_cn})", paths.client_cert.display(), paths.client_key.display());
    println!(
        "  serve  : cyberztna serve --tls --tls-cert {} --tls-key {} --mtls-ca {}",
        paths.server_cert.display(),
        paths.server_key.display(),
        paths.ca_cert.display()
    );
    Ok(paths)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    // Prefer PKCS8, then RSA
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(k) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(k));
    }
    let data = fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(k) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(k));
    }
    Err(format!("no private key in {}", path.display()).into())
}

/// Build rustls ServerConfig; when `client_ca` is set, require client certs signed by that CA.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca: Option<&Path>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let builder = if let Some(ca_path) = client_ca {
        let ca_certs = load_certs(ca_path)?;
        let mut roots = RootCertStore::empty();
        for c in ca_certs {
            roots.add(c)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };

    let mut config = builder.with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
