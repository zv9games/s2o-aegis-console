//! Local JWT bearer tokens: HS256 secret and RS256/JWKS (OIDC-lite).

use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateClaims {
    pub sub: String,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub posture: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum JwtVerifier {
    Hs256(String),
    /// RSA public key PEM (SPKI)
    Rs256Pem {
        public_pem: String,
        kid: Option<String>,
    },
    /// First/matching JWK from a JWKS file
    Rs256Jwk {
        jwk: serde_json::Value,
        kid: Option<String>,
    },
}

pub fn mint(
    secret: &str,
    user: &str,
    ttl_hours: i64,
    posture: Option<u32>,
    issuer: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = GateClaims {
        sub: user.to_string(),
        exp: now + ttl_hours.max(1) * 3600,
        iat: Some(now),
        iss: Some(issuer.to_string()),
        posture,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn mint_rs256(
    private_pem: &str,
    kid: Option<&str>,
    user: &str,
    ttl_hours: i64,
    posture: Option<u32>,
    issuer: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = GateClaims {
        sub: user.to_string(),
        exp: now + ttl_hours.max(1) * 3600,
        iat: Some(now),
        iss: Some(issuer.to_string()),
        posture,
    };
    let mut header = Header::new(Algorithm::RS256);
    if let Some(k) = kid {
        header.kid = Some(k.to_string());
    }
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes())?,
    )
}

pub fn verify(secret: &str, token: &str) -> Result<GateClaims, String> {
    verify_with(&JwtVerifier::Hs256(secret.to_string()), token)
}

pub fn verify_with(verifier: &JwtVerifier, token: &str) -> Result<GateClaims, String> {
    match verifier {
        JwtVerifier::Hs256(secret) => {
            let mut validation = Validation::new(Algorithm::HS256);
            validation.validate_exp = true;
            decode::<GateClaims>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &validation,
            )
            .map(|d| d.claims)
            .map_err(|e| e.to_string())
        }
        JwtVerifier::Rs256Pem { public_pem, kid } => {
            check_rs256_header(token, kid.as_deref())?;
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            let key =
                DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(|e| e.to_string())?;
            decode::<GateClaims>(token, &key, &validation)
                .map(|d| d.claims)
                .map_err(|e| e.to_string())
        }
        JwtVerifier::Rs256Jwk { jwk, kid } => {
            check_rs256_header(token, kid.as_deref())?;
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            let jwk: jsonwebtoken::jwk::Jwk =
                serde_json::from_value(jwk.clone()).map_err(|e| format!("jwk: {e}"))?;
            let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("jwk key: {e}"))?;
            decode::<GateClaims>(token, &key, &validation)
                .map(|d| d.claims)
                .map_err(|e| e.to_string())
        }
    }
}

fn check_rs256_header(token: &str, expected_kid: Option<&str>) -> Result<(), String> {
    let header = decode_header(token).map_err(|e| e.to_string())?;
    if header.alg != Algorithm::RS256 {
        return Err(format!("expected RS256, got {:?}", header.alg));
    }
    if let Some(expected) = expected_kid {
        if let Some(ref kid) = header.kid {
            if kid != expected {
                return Err(format!("kid mismatch: token={kid} expected={expected}"));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDoc {
    pub keys: Vec<serde_json::Value>,
}

/// RSA lab material (private PEM + public PEM + JWKS JSON).
#[derive(Debug, Clone)]
pub struct Rs256Material {
    pub private_pem: String,
    pub public_pem: String,
    pub jwks_json: String,
    pub kid: String,
}

pub fn generate_rs256_lab(kid: &str) -> Result<Rs256Material, Box<dyn std::error::Error>> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use sha2::{Digest, Sha256};

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = private_key.to_public_key();
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)?;

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();
    let kid = if kid.is_empty() {
        let mut h = Sha256::new();
        h.update(&n);
        format!("s2o-{}", hex::encode(&h.finalize()[..8]))
    } else {
        kid.to_string()
    };
    let jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64_url_encode(&n),
        "e": base64_url_encode(&e),
    });
    let jwks = serde_json::json!({ "keys": [jwk] });
    Ok(Rs256Material {
        private_pem,
        public_pem,
        jwks_json: serde_json::to_string_pretty(&jwks)?,
        kid,
    })
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Load RS256 verifier from JWKS JSON or public PEM path.
pub fn rs256_verifier_from_path(path: &Path) -> Result<JwtVerifier, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    if text.contains("BEGIN PUBLIC KEY") || text.contains("BEGIN RSA PUBLIC KEY") {
        return Ok(JwtVerifier::Rs256Pem {
            public_pem: text,
            kid: None,
        });
    }
    let jwks: JwksDoc = serde_json::from_str(&text).map_err(|e| format!("jwks: {e}"))?;
    let key0 = jwks.keys.first().cloned().ok_or_else(|| "jwks empty".to_string())?;
    let kid = key0
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // Prefer sibling jwt-public.pem if present
    if let Some(parent) = path.parent() {
        let pem_path = parent.join("jwt-public.pem");
        if pem_path.exists() {
            let public_pem = fs::read_to_string(pem_path).map_err(|e| e.to_string())?;
            return Ok(JwtVerifier::Rs256Pem { public_pem, kid });
        }
    }
    Ok(JwtVerifier::Rs256Jwk { jwk: key0, kid })
}

/// Write lab RS256 files under dir: jwt-private.pem, jwt-public.pem, jwks.json
pub fn write_rs256_lab(dir: &Path, kid: &str, force: bool) -> Result<Rs256Material, Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let priv_path = dir.join("jwt-private.pem");
    let pub_path = dir.join("jwt-public.pem");
    let jwks_path = dir.join("jwks.json");
    if priv_path.exists() && pub_path.exists() && jwks_path.exists() && !force {
        let private_pem = fs::read_to_string(&priv_path)?;
        let public_pem = fs::read_to_string(&pub_path)?;
        let jwks_json = fs::read_to_string(&jwks_path)?;
        let kid = serde_json::from_str::<JwksDoc>(&jwks_json)
            .ok()
            .and_then(|j| j.keys.first().cloned())
            .and_then(|k| k.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| kid.to_string());
        return Ok(Rs256Material {
            private_pem,
            public_pem,
            jwks_json,
            kid,
        });
    }
    let mat = generate_rs256_lab(kid)?;
    fs::write(&priv_path, &mat.private_pem)?;
    fs::write(&pub_path, &mat.public_pem)?;
    fs::write(&jwks_path, &mat.jwks_json)?;
    println!("[gate] RS256 lab keys written to {}", dir.display());
    println!("  private : {}", priv_path.display());
    println!("  public  : {}", pub_path.display());
    println!("  jwks    : {}", jwks_path.display());
    println!("  kid     : {}", mat.kid);
    Ok(mat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_verify_hs256() {
        let t = mint("lab-secret", "alice", 1, Some(80), "s2o-cyberid").unwrap();
        let c = verify("lab-secret", &t).unwrap();
        assert_eq!(c.sub, "alice");
        assert!(verify("wrong", &t).is_err());
    }

    #[test]
    fn mint_verify_rs256_and_jwks() {
        let mat = generate_rs256_lab("test-kid").unwrap();
        let t = mint_rs256(
            &mat.private_pem,
            Some(&mat.kid),
            "bob",
            1,
            Some(70),
            "s2o-lab",
        )
        .unwrap();
        let v = JwtVerifier::Rs256Pem {
            public_pem: mat.public_pem.clone(),
            kid: Some(mat.kid.clone()),
        };
        assert_eq!(verify_with(&v, &t).unwrap().sub, "bob");

        let jwks: JwksDoc = serde_json::from_str(&mat.jwks_json).unwrap();
        let v2 = JwtVerifier::Rs256Jwk {
            jwk: jwks.keys[0].clone(),
            kid: Some(mat.kid),
        };
        assert_eq!(verify_with(&v2, &t).unwrap().posture, Some(70));
    }
}
