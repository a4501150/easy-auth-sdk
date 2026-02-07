use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token signature verification failed")]
    InvalidSignature,

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Missing required claim: {0}")]
    MissingClaim(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("JSON decoding error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            ErrorKind::InvalidToken => AuthError::InvalidToken("Malformed token".to_string()),
            ErrorKind::InvalidAlgorithm => AuthError::InvalidToken("Invalid algorithm".to_string()),
            ErrorKind::Base64(_) => AuthError::InvalidToken("Base64 decoding failed".to_string()),
            ErrorKind::Json(e) => AuthError::InvalidToken(format!("JSON error: {}", e)),
            ErrorKind::Utf8(_) => AuthError::InvalidToken("UTF-8 decoding failed".to_string()),
            ErrorKind::MissingRequiredClaim(claim) => AuthError::MissingClaim(claim.to_string()),
            _ => AuthError::InvalidToken(err.to_string()),
        }
    }
}
