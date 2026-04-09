use crate::state::AppState;
use axum::{
    body::Body,
    extract::State,
    http::{header::ORIGIN, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn enforce_csrf(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_safe_method(request.method()) || is_bypass_path(request.uri().path()) {
        return next.run(request).await;
    }

    let cookies = request
        .headers()
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    // CSRF is only enforced for browser cookie-auth flows.
    if !has_cookie(cookies, "auth_session") {
        return next.run(request).await;
    }

    let origin = request
        .headers()
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if origin.is_empty() || !state.browser_allowed_origins.contains(origin) {
        return (StatusCode::FORBIDDEN, "csrf origin check failed").into_response();
    }

    let csrf_cookie = cookie_value(cookies, "csrf_token").unwrap_or_default();
    let csrf_header = request
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if csrf_cookie.is_empty() || csrf_header.is_empty() || csrf_cookie != csrf_header {
        return (StatusCode::FORBIDDEN, "csrf token mismatch").into_response();
    }

    next.run(request).await
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn has_cookie(raw_cookie: &str, name: &str) -> bool {
    cookie_value(raw_cookie, name).is_some()
}

fn cookie_value(raw_cookie: &str, name: &str) -> Option<String> {
    raw_cookie.split(';').map(str::trim).find_map(|cookie| {
        let (key, value) = cookie.split_once('=')?;
        if key.trim() == name {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn is_bypass_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/v1/public/ping" | "/v1/proxy/auth-health"
    )
}

#[cfg(test)]
mod tests {
    use super::cookie_value;

    #[test]
    fn cookie_value_extracts_named_cookie() {
        let raw = "auth_session=abc123; csrf_token=token-1; other=value";
        assert_eq!(cookie_value(raw, "csrf_token").as_deref(), Some("token-1"));
    }

    #[test]
    fn cookie_value_returns_none_when_missing() {
        let raw = "auth_session=abc123; other=value";
        assert!(cookie_value(raw, "csrf_token").is_none());
    }
}
