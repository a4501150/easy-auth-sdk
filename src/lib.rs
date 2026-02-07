mod claims;
mod error;
mod jwks;

pub use claims::Claims;
pub use error::AuthError;
pub use jsonwebtoken::Algorithm;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

pub struct EasyAuth {
    decoding_keys: Vec<(Option<String>, DecodingKey)>,
    validation: Validation,
}

impl EasyAuth {
    /// Create an EasyAuth instance from a JWKS JSON string.
    ///
    /// # Example
    /// ```ignore
    /// let jwks_json = r#"{"keys":[...]}"#;
    /// let auth = EasyAuth::from_jwks_json(jwks_json)?;
    /// ```
    pub fn from_jwks_json(jwks_json: &str) -> Result<Self, AuthError> {
        let keys = jwks::parse_jwks(jwks_json)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        Ok(Self {
            decoding_keys: keys,
            validation,
        })
    }

    /// Create an EasyAuth instance from a PEM-encoded public key.
    ///
    /// # Example
    /// ```ignore
    /// let pem = "-----BEGIN PUBLIC KEY-----\n...";
    /// let auth = EasyAuth::from_pem(pem)?;
    /// ```
    pub fn from_pem(pem: &str) -> Result<Self, AuthError> {
        let key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| AuthError::InvalidKey(format!("Failed to parse PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        Ok(Self {
            decoding_keys: vec![(None, key)],
            validation,
        })
    }

    /// Validate the JWT token and return the claims.
    ///
    /// Verifies the token signature and expiration, then returns the decoded claims.
    ///
    /// # Example
    /// ```ignore
    /// let claims = auth.validate(&token)?;
    /// println!("User: {}", claims.sub);
    /// println!("Roles: {:?}", claims.domain_roles);
    /// ```
    pub fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        self.decode_token(token)
    }

    fn decode_token(&self, token: &str) -> Result<Claims, AuthError> {
        let header = decode_header(token)?;

        let decoding_key = self.find_key(header.kid.as_deref())?;

        let token_data = decode::<Claims>(token, decoding_key, &self.validation)?;

        Ok(token_data.claims)
    }

    fn find_key(&self, kid: Option<&str>) -> Result<&DecodingKey, AuthError> {
        match kid {
            Some(kid) => {
                for (key_kid, key) in &self.decoding_keys {
                    if key_kid.as_deref() == Some(kid) {
                        return Ok(key);
                    }
                }
                self.decoding_keys
                    .first()
                    .map(|(_, k)| k)
                    .ok_or_else(|| AuthError::InvalidKey("No keys available".to_string()))
            }
            None => self
                .decoding_keys
                .first()
                .map(|(_, k)| k)
                .ok_or_else(|| AuthError::InvalidKey("No keys available".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Serialize)]
    struct TestClaims {
        sub: String,
        domain_roles: Vec<String>,
        exp: u64,
        iat: u64,
    }

    struct TestKeys {
        encoding_key: EncodingKey,
        pem_public: String,
        jwks_json: String,
    }

    fn generate_test_keys() -> TestKeys {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        let private_pem = private_key.to_pkcs1_pem(Default::default()).unwrap();
        let public_pem = public_key.to_public_key_pem(Default::default()).unwrap();

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();

        let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());

        let jwks_json = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","use":"sig","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            n, e
        );

        TestKeys {
            encoding_key,
            pem_public: public_pem,
            jwks_json,
        }
    }

    fn create_token(keys: &TestKeys, claims: &TestClaims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_string());
        encode(&header, claims, &keys.encoding_key).unwrap()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_allowed_domain_roles_with_matching_role() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let test_claims = TestClaims {
            sub: "user-123".to_string(),
            domain_roles: vec!["moon:user".to_string(), "example:admin".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let token = create_token(&keys, &test_claims);
        let claims = auth.validate(&token).unwrap();
        assert!(claims.allowed_domain_roles(&["moon:user"]));
        assert_eq!(claims.sub, "user-123");
    }

    #[test]
    fn test_allowed_domain_roles_without_matching_role() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let test_claims = TestClaims {
            sub: "user-123".to_string(),
            domain_roles: vec!["example:viewer".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let token = create_token(&keys, &test_claims);
        let claims = auth.validate(&token).unwrap();
        assert!(!claims.allowed_domain_roles(&["moon:admin"]));
    }

    #[test]
    fn test_is_subject_matching() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_pem(&keys.pem_public).unwrap();

        let test_claims = TestClaims {
            sub: "295fafbb-7da3-4881-858f-e6ea5d2b65ae".to_string(),
            domain_roles: vec![],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        let token = encode(&header, &test_claims, &keys.encoding_key).unwrap();

        let claims = auth.validate(&token).unwrap();
        assert!(claims.is_subject("295fafbb-7da3-4881-858f-e6ea5d2b65ae"));
    }

    #[test]
    fn test_is_subject_not_matching() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_pem(&keys.pem_public).unwrap();

        let test_claims = TestClaims {
            sub: "user-123".to_string(),
            domain_roles: vec![],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        let token = encode(&header, &test_claims, &keys.encoding_key).unwrap();

        let claims = auth.validate(&token).unwrap();
        assert!(!claims.is_subject("different-user"));
    }

    #[test]
    fn test_validate() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let test_claims = TestClaims {
            sub: "user-456".to_string(),
            domain_roles: vec!["test:role".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let token = create_token(&keys, &test_claims);
        let claims = auth.validate(&token).unwrap();
        assert_eq!(claims.sub, "user-456");
        assert_eq!(claims.domain_roles, vec!["test:role".to_string()]);
    }

    #[test]
    fn test_combined_checks() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let test_claims = TestClaims {
            sub: "user-789".to_string(),
            domain_roles: vec!["api:read".to_string(), "api:write".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };

        let token = create_token(&keys, &test_claims);

        // Validate once, check multiple times
        let claims = auth.validate(&token).unwrap();
        assert!(claims.allowed_domain_roles(&["api:read"]));
        assert!(claims.is_subject("user-789"));

        // OR logic: allow if subject matches OR has admin role
        assert!(claims.is_subject("user-789") || claims.allowed_domain_roles(&["admin"]));
    }

    #[test]
    fn test_expired_token() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let test_claims = TestClaims {
            sub: "user-123".to_string(),
            domain_roles: vec!["moon:user".to_string()],
            exp: now_secs() - 3600, // Expired 1 hour ago
            iat: now_secs() - 7200,
        };

        let token = create_token(&keys, &test_claims);
        let result = auth.validate(&token);

        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_invalid_signature() {
        let keys1 = generate_test_keys();
        let keys2 = generate_test_keys();

        // Create auth with keys1
        let auth = EasyAuth::from_jwks_json(&keys1.jwks_json).unwrap();

        // Create token with keys2 (different key)
        let test_claims = TestClaims {
            sub: "user-123".to_string(),
            domain_roles: vec!["moon:user".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
        };
        let token = create_token(&keys2, &test_claims);

        let result = auth.validate(&token);
        assert!(matches!(result, Err(AuthError::InvalidSignature)));
    }

    #[test]
    fn test_malformed_token() {
        let keys = generate_test_keys();
        let auth = EasyAuth::from_jwks_json(&keys.jwks_json).unwrap();

        let result = auth.validate("not.a.valid.token");
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn test_invalid_jwks() {
        let result = EasyAuth::from_jwks_json("not valid json");
        assert!(matches!(result, Err(AuthError::JsonError(_))));
    }

    #[test]
    fn test_empty_jwks() {
        let result = EasyAuth::from_jwks_json(r#"{"keys":[]}"#);
        assert!(matches!(result, Err(AuthError::InvalidKey(_))));
    }
}
