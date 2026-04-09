use crate::state::{AppState, RateLimitCheckError, RateLimitRejection, ValidatedClient};
use ::middleware::RequestId;
use auth::claims::Claims;
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::RETRY_AFTER, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use errors::{DomainError, ErrorEnvelope};
use rate_limit::RouteId;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
struct RouteRateMetadata {
    route_group: &'static str,
    pre_auth: bool,
}

pub async fn apply_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_bypass_path(request.uri().path()) || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let Some(validated_client) = request.extensions().get::<ValidatedClient>() else {
        return (StatusCode::UNAUTHORIZED, "missing validated client context").into_response();
    };

    let claims = request.extensions().get::<Claims>();
    let route_template = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let route_id = RouteId::new(request.method().as_str(), route_template.clone());
    let route_key = route_id.as_key();
    let metadata = classify_route_rate(request.method(), route_template.as_str());

    let authenticated = claims.is_some() && !metadata.pre_auth;
    let limits = state.resolve_rate_limits(
        &validated_client.policy,
        route_key.as_str(),
        metadata.route_group,
        authenticated,
    );

    let source_ip = extract_source_ip(request.headers());
    let user_id = if authenticated {
        claims.map(|value| value.sub.as_str())
    } else {
        None
    };
    match state
        .evaluate_rate_limits(
            user_id,
            source_ip,
            &route_id,
            metadata.route_group,
            metadata.pre_auth,
            limits,
        )
        .await
    {
        Ok(()) => {}
        Err(RateLimitCheckError::Rejected(rejection)) => {
            let request_id = request_id(&request);
            return build_rate_limited_response(rejection, request_id);
        }
        Err(RateLimitCheckError::Backend(err)) => {
            if state.rate_limit_fail_open {
                tracing::warn!(error = %err, "rate-limit backend unavailable; fail-open active");
            } else {
                tracing::error!(
                    error = %err,
                    "rate-limit backend unavailable and fail-open disabled"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "rate-limit backend unavailable",
                )
                    .into_response();
            }
        }
    }

    next.run(request).await
}

fn classify_route_rate(method: &Method, path: &str) -> RouteRateMetadata {
    if path.starts_with("/oauth2/") {
        return RouteRateMetadata {
            route_group: "oauth",
            pre_auth: true,
        };
    }

    if matches!(
        path,
        "/v1/auth/register"
            | "/v1/auth/verify-email/request"
            | "/v1/auth/verify-email/confirm"
            | "/v1/auth/login"
            | "/v1/auth/login/mfa/verify"
            | "/v1/auth/social/google"
            | "/v1/auth/social/apple"
            | "/v1/auth/refresh"
            | "/v1/auth/forgot-password"
            | "/v1/auth/forgot-password/verify"
            | "/v1/auth/password/reset"
    ) {
        return RouteRateMetadata {
            route_group: "auth",
            pre_auth: true,
        };
    }

    if path.starts_with("/v1/system/") {
        return RouteRateMetadata {
            route_group: "system",
            pre_auth: false,
        };
    }

    if path.contains("telemetry") || path.contains("location") {
        return RouteRateMetadata {
            route_group: "telemetry",
            pre_auth: false,
        };
    }

    if path.starts_with("/v1/media/") {
        return RouteRateMetadata {
            route_group: "media",
            pre_auth: false,
        };
    }

    if path.starts_with("/v1/devices") {
        return RouteRateMetadata {
            route_group: "devices",
            pre_auth: false,
        };
    }

    if path.starts_with("/v1/exports") {
        return RouteRateMetadata {
            route_group: "exports",
            pre_auth: false,
        };
    }

    if path.starts_with("/v1/public") {
        return RouteRateMetadata {
            route_group: "public",
            pre_auth: false,
        };
    }

    if path.starts_with("/v1/auth/") {
        let is_authenticated_auth_route = matches!(
            path,
            "/v1/auth/password/change"
                | "/v1/auth/logout"
                | "/v1/auth/sessions"
                | "/v1/auth/sessions/logout"
                | "/v1/auth/sessions/logout-all"
                | "/v1/auth/mfa/authenticator/setup"
                | "/v1/auth/mfa/authenticator/confirm"
                | "/v1/auth/mfa/authenticator/disable"
                | "/v1/auth/mfa/backup-codes/regenerate"
        );
        return RouteRateMetadata {
            route_group: "auth",
            pre_auth: method == Method::POST && !is_authenticated_auth_route,
        };
    }

    RouteRateMetadata {
        route_group: "core",
        pre_auth: false,
    }
}

fn extract_source_ip(headers: &HeaderMap) -> Option<&str> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());

    if let Some(forwarded) = forwarded {
        if let Some(ip) = forwarded
            .split(',')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(ip);
        }
    }

    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn build_rate_limited_response(rejection: RateLimitRejection, request_id: String) -> Response {
    let mut meta = BTreeMap::new();
    meta.insert("scope".to_string(), rejection.dimension.to_string());
    meta.insert("endpoint".to_string(), rejection.route_id.clone());
    meta.insert(
        "retry_after_seconds".to_string(),
        rejection.retry_after_seconds.to_string(),
    );
    meta.insert("limit_per_window".to_string(), rejection.limit.to_string());

    let payload = ErrorEnvelope::new(
        DomainError::RateLimited,
        "Rate limit exceeded for this endpoint.",
        request_id,
        None,
        meta,
    );

    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(payload)).into_response();
    if let Ok(value) = HeaderValue::from_str(&rejection.retry_after_seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

fn request_id(request: &Request<Body>) -> String {
    request
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0.clone())
        .unwrap_or_else(|| "missing".to_string())
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
