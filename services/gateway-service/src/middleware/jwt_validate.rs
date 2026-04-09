use crate::state::{AppState, ValidatedClient};
use auth::jwt;
use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn validate_jwt(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if is_public_path(request.uri().path()) || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let header_value = match request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(value) => value,
        None => return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response(),
    };

    let claims = match jwt::parse_bearer_header(header_value) {
        Ok(claims) => claims,
        Err(err) => {
            return (StatusCode::UNAUTHORIZED, format!("invalid token: {err}")).into_response();
        }
    };

    if let Err(err) = jwt::validate_claims(&claims) {
        return (StatusCode::UNAUTHORIZED, format!("invalid claims: {err}")).into_response();
    }

    if claims.iss != state.expected_issuer {
        return (StatusCode::UNAUTHORIZED, "invalid issuer").into_response();
    }

    if claims.cid.trim().is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing cid claim on access token".to_string(),
        )
            .into_response();
    }

    if let Some(validated_client) = request.extensions().get::<ValidatedClient>() {
        if claims.cid != validated_client.client_id {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "client identity mismatch: header client '{}' does not match token cid '{}'",
                    validated_client.client_id, claims.cid
                ),
            )
                .into_response();
        }
    }

    if let Err(err) = state
        .validate_claim_freshness(&claims.sub, claims.sv, claims.perm_rev)
        .await
    {
        return (
            StatusCode::UNAUTHORIZED,
            format!("token freshness rejected: {err}"),
        )
            .into_response();
    }

    request.extensions_mut().insert(claims);
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
