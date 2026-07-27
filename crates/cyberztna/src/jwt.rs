//! Local HS256 JWT bearer tokens (OIDC-lite prep — not a full IdP).

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateClaims {
    /// Subject / user id
    pub sub: String,
    /// Expiry (unix seconds)
    pub exp: i64,
    /// Issued at
    #[serde(default)]
    pub iat: Option<i64>,
    /// Optional issuer label
    #[serde(default)]
    pub iss: Option<String>,
    /// Optional mint-time posture score
    #[serde(default)]
    pub posture: Option<u32>,
}

pub fn mint(
    secret: &str,
    user: &str,
    ttl_hours: i64,
    posture: Option<u32>,
    issuer: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + ttl_hours.max(1) * 3600;
    let claims = GateClaims {
        sub: user.to_string(),
        exp,
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

pub fn verify(secret: &str, token: &str) -> Result<GateClaims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    // HS256 default
    decode::<GateClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_verify_roundtrip() {
        let t = mint("lab-secret", "alice", 1, Some(80), "s2o-cyberid").unwrap();
        let c = verify("lab-secret", &t).unwrap();
        assert_eq!(c.sub, "alice");
        assert_eq!(c.posture, Some(80));
        assert!(verify("wrong", &t).is_err());
    }
}
