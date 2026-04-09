use crate::{
    audiences::{is_supported_audience, is_supported_realm},
    claims::Claims,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("authorization header must be a bearer token")]
    MissingBearerPrefix,
    #[error("token payload is not valid base64url")]
    InvalidEncoding,
    #[error("token payload is not valid json")]
    InvalidJson,
    #[error("unsupported audience")]
    UnsupportedAudience,
    #[error("unsupported realm")]
    UnsupportedRealm,
    #[error("audience and realm mismatch")]
    AudienceRealmMismatch,
    #[error("token expired")]
    Expired,
}

pub fn parse_bearer_header(value: &str) -> Result<Claims, JwtError> {
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(JwtError::MissingBearerPrefix)?;
    decode_token(token)
}

pub fn decode_token(token: &str) -> Result<Claims, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| JwtError::InvalidEncoding)?;
    serde_json::from_slice::<Claims>(&bytes).map_err(|_| JwtError::InvalidJson)
}

pub fn validate_claims(claims: &Claims) -> Result<(), JwtError> {
    if !is_supported_audience(&claims.aud) {
        return Err(JwtError::UnsupportedAudience);
    }
    if !is_supported_realm(&claims.realm) {
        return Err(JwtError::UnsupportedRealm);
    }
    if claims.aud != claims.realm {
        return Err(JwtError::AudienceRealmMismatch);
    }
    if claims.exp <= Utc::now().timestamp() {
        return Err(JwtError::Expired);
    }
    Ok(())
}
