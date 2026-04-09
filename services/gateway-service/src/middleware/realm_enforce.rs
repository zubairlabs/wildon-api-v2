use crate::{
    routing::host_router::resolve_surface,
    state::{AppState, ValidatedClient},
};
use auth::claims::Claims;
use axum::{
    body::Body,
    extract::State,
    http::{header::HOST, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn enforce_realm(
    State(_state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_public_path(request.uri().path()) || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let host = request.headers().get(HOST).and_then(|v| v.to_str().ok());
    let client_surface = request
        .extensions()
        .get::<ValidatedClient>()
        .map(|client| client.policy.surface.as_str());
    let surface = resolve_surface(host, client_surface);

    let Some(claims) = request.extensions().get::<Claims>() else {
        return (StatusCode::UNAUTHORIZED, "missing claims context").into_response();
    };

    if claims.aud != surface.expected_audience() || claims.realm != surface.expected_realm() {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "realm mismatch for host surface '{}' (aud='{}', realm='{}')",
                surface.as_str(),
                claims.aud,
                claims.realm
            ),
        )
            .into_response();
    }

    next.run(request).await
}

fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/docs"
            | "/docs/"
            | "/docs/openapi/control-v1.json"
            | "/openapi/gateway-v1.json"
            | "/openapi/control-v1.json"
            | "/v1/public/ping"
            | "/.well-known/openid-configuration"
            | "/.well-known/scopes"
            | "/oauth2/jwks.json"
            | "/oauth2/token"
            | "/oauth2/revoke"
            | "/oauth2/introspect"
            | "/v1/auth/register"
            | "/v1/auth/verify-email/request"
            | "/v1/auth/verify-email/confirm"
            | "/v1/auth/login"
            | "/v1/auth/login/mfa/verify"
            | "/v1/auth/social/google"
            | "/v1/auth/social/apple"
            | "/v1/auth/refresh"
            | "/v1/auth/forgot-password"
            | "/v1/auth/password/forgot/request"
            | "/v1/auth/password/forgot/verify"
            | "/v1/auth/password/reset"
    )
}
