use crate::{
    routing::host_router::{classify_host, host_has_explicit_surface},
    state::{AppState, ValidatedClient},
};
use axum::{
    body::Body,
    extract::State,
    http::{
        header::{AUTHORIZATION, HOST, ORIGIN},
        HeaderMap, Method, Request, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;

pub async fn validate_client(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if is_bypass_path(request.uri().path()) || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let headers = request.headers();
    let client_id = match header_value(headers, "x-client-id") {
        Some(value) if !value.trim().is_empty() => value.trim().to_ascii_lowercase(),
        _ => return (StatusCode::UNAUTHORIZED, "missing x-client-id header").into_response(),
    };

    let app_version = header_value(headers, "x-app-version").map(ToString::to_string);
    let host = headers.get(HOST).and_then(|v| v.to_str().ok());
    let host_surface = classify_host(host);
    let explicit_surface_host = host_has_explicit_surface(host);
    let requested_audience = if explicit_surface_host {
        host_surface.expected_audience().to_string()
    } else {
        String::new()
    };
    let surface = if explicit_surface_host {
        host_surface.as_str()
    } else {
        ""
    };
    let source_ip = extract_source_ip(headers);
    let origin = headers.get(ORIGIN).and_then(|value| value.to_str().ok());
    let client_secret = extract_client_secret(headers);
    let mtls_verified = header_value(headers, "x-mtls-verified")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    let policy = match state
        .validate_client(
            &client_id,
            requested_audience.as_str(),
            surface,
            app_version.as_deref(),
            origin,
            source_ip,
            client_secret.as_deref(),
            mtls_verified,
        )
        .await
    {
        Ok(policy) => policy,
        Err(reason) => {
            let status = classify_validation_error_status(reason.as_str());
            return (status, format!("client validation failed: {reason}")).into_response();
        }
    };

    request.extensions_mut().insert(ValidatedClient {
        client_id,
        policy,
        app_version,
    });

    next.run(request).await
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn extract_source_ip(headers: &HeaderMap) -> Option<&str> {
    let forwarded = header_value(headers, "x-forwarded-for")?;
    forwarded
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| header_value(headers, "x-real-ip"))
}

fn extract_client_secret(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = header_value(headers, "x-client-secret") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;

    if let Some(secret) = auth.strip_prefix("ClientSecret ") {
        let secret = secret.trim();
        if !secret.is_empty() {
            return Some(secret.to_string());
        }
    }

    let basic = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(basic.as_bytes())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_, secret) = decoded.split_once(':')?;
    let secret = secret.trim();
    if secret.is_empty() {
        None
    } else {
        Some(secret.to_string())
    }
}

fn classify_validation_error_status(reason: &str) -> StatusCode {
    let normalized = reason.trim().to_ascii_lowercase();
    if normalized.contains("not found")
        || normalized.contains("required")
        || normalized.contains("missing")
        || normalized.contains("invalid client secret")
    {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::FORBIDDEN
    }
}

fn is_bypass_path(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/docs"
            | "/docs/"
            | "/docs/openapi/control-v1.json"
            | "/openapi/gateway-v1.json"
            | "/openapi/control-v1.json"
            | "/v1/public/ping"
            | "/v1/proxy/auth-health"
            | "/.well-known/openid-configuration"
            | "/.well-known/scopes"
            | "/oauth2/jwks.json"
            | "/oauth2/authorize"
            | "/oauth2/token"
            | "/oauth2/revoke"
            | "/oauth2/introspect"
            | "/oauth2/userinfo"
    )
}
