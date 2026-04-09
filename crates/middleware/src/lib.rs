use axum::{
    body::Body,
    http::{header::HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use errors::{DomainError, ErrorEnvelope};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

pub async fn inject_request_id(mut request: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static("x-request-id");
    let request_id = request
        .headers()
        .get(&header_name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(&header_name, value);
    }
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(header_name, value);
    }
    response
}

pub async fn enforce_json_request_shape(request: Request<Body>, next: Next) -> Response {
    if is_bypass_path(request.uri().path()) || !requires_json_body(request.method()) {
        return next.run(request).await;
    }

    if !has_request_body(request.headers()) {
        return next.run(request).await;
    }

    let content_type = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if !(content_type.starts_with("application/json")
        || content_type.starts_with("multipart/form-data"))
    {
        let request_id = request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("missing")
            .to_string();

        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            axum::Json(ErrorEnvelope::new(
                DomainError::InvalidArgument,
                "content-type must be application/json",
                request_id,
                None,
                BTreeMap::new(),
            )),
        )
            .into_response();
    }

    next.run(request).await
}

fn requires_json_body(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn is_bypass_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/v1/public/ping" | "/v1/proxy/auth-health"
    )
}

fn has_request_body(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0)
        || headers.contains_key(axum::http::header::TRANSFER_ENCODING)
}
