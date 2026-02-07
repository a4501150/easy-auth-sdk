use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

use crate::error::AuthError;

#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub e: String,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}

impl Jwk {
    pub fn to_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        if self.kty != "RSA" {
            return Err(AuthError::InvalidKey(format!(
                "Unsupported key type: {}. Only RSA is supported.",
                self.kty
            )));
        }

        if self.n.is_empty() || self.e.is_empty() {
            return Err(AuthError::InvalidKey(
                "Missing RSA components (n or e)".to_string(),
            ));
        }

        let n_bytes = URL_SAFE_NO_PAD
            .decode(&self.n)
            .map_err(|e| AuthError::InvalidKey(format!("Failed to decode modulus (n): {}", e)))?;

        let e_bytes = URL_SAFE_NO_PAD
            .decode(&self.e)
            .map_err(|e| AuthError::InvalidKey(format!("Failed to decode exponent (e): {}", e)))?;

        Ok(DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes))
    }
}

pub fn parse_jwks(jwks_json: &str) -> Result<Vec<(Option<String>, DecodingKey)>, AuthError> {
    let jwks: Jwks = serde_json::from_str(jwks_json)?;

    let mut keys = Vec::new();
    for jwk in jwks.keys {
        if let Some(ref key_use) = jwk.key_use {
            if key_use != "sig" {
                continue;
            }
        }

        if let Some(ref alg) = jwk.alg {
            if alg != "RS256" {
                continue;
            }
        }

        let decoding_key = jwk.to_decoding_key()?;
        keys.push((jwk.kid.clone(), decoding_key));
    }

    if keys.is_empty() {
        return Err(AuthError::InvalidKey(
            "No valid RS256 keys found in JWKS".to_string(),
        ));
    }

    Ok(keys)
}
