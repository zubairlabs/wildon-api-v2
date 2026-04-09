use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn enforce_json_request_shape(request: Request<Body>, next: Next) -> Response {
    if is_bypass_path(request.uri().path()) || !requires_json_body(request.method()) {
        return next.run(request).await;
    }

    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if !content_type.starts_with("application/json") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content-type must be application/json",
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
