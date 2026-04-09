use axum::http::StatusCode;
use errors::{DomainError, ErrorEnvelope};
use std::collections::BTreeMap;

pub fn grpc_error_tuple(err: tonic::Status, request_id: &str) -> (StatusCode, String) {
    let domain = DomainError::from(err.code());
    let http_status =
        StatusCode::from_u16(domain.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let envelope = ErrorEnvelope::new(
        domain,
        safe_message(domain),
        request_id.to_string(),
        None,
        BTreeMap::new(),
    );
    let payload = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"error\":{\"code\":\"ERROR_CODE_INTERNAL\",\"message\":\"internal error\",\"request_id\":\"missing\"}}".to_string()
    });

    (http_status, payload)
}

fn safe_message(domain: DomainError) -> &'static str {
    match domain {
        DomainError::Unauthorized => "Authentication required",
        DomainError::Forbidden => "Forbidden",
        DomainError::NotFound => "Resource not found",
        DomainError::Conflict => "Conflict",
        DomainError::InvalidArgument => "Invalid request",
        DomainError::RateLimited => "Too many requests",
        DomainError::Unavailable => "Service unavailable",
        DomainError::Internal => "Internal error",
    }
}
