use crate::{
    routing::host_router::{resolve_surface, HostSurface},
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

#[derive(Debug, Clone)]
struct RoutePolicy {
    required_roles: &'static [&'static str],
    third_party_required_scopes: Vec<&'static str>,
    always_required_scopes: Vec<&'static str>,
    required_permissions: Vec<&'static str>,
    require_step_up_mfa: bool,
}

pub async fn enforce_authorization_policy(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_public_path(request.uri().path()) || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let Some(claims) = request.extensions().get::<Claims>() else {
        return (StatusCode::UNAUTHORIZED, "missing claims context").into_response();
    };
    let Some(validated_client) = request.extensions().get::<ValidatedClient>() else {
        return (StatusCode::UNAUTHORIZED, "missing client context").into_response();
    };

    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok());
    let surface = resolve_surface(host, Some(validated_client.policy.surface.as_str()));
    let policy = build_route_policy(surface, request.method(), request.uri().path());

    if !policy.required_roles.is_empty()
        && !claims.roles.iter().any(|role| {
            policy
                .required_roles
                .iter()
                .any(|required| role == required)
        })
    {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "role is not allowed for surface '{}' (required one of: {})",
                surface.as_str(),
                policy.required_roles.join(", ")
            ),
        )
            .into_response();
    }

    if policy.require_step_up_mfa && !claims.amr.iter().any(|value| value == "mfa") {
        return (
            StatusCode::FORBIDDEN,
            "step-up authentication required (amr must include mfa)",
        )
            .into_response();
    }

    if !policy.always_required_scopes.is_empty()
        && !policy
            .always_required_scopes
            .iter()
            .all(|scope| claims.scopes.iter().any(|present| present == scope))
    {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "missing required scope(s): {}",
                policy.always_required_scopes.join(", ")
            ),
        )
            .into_response();
    }

    if !is_first_party_client(validated_client)
        && !policy.third_party_required_scopes.is_empty()
        && !policy
            .third_party_required_scopes
            .iter()
            .all(|scope| claims.scopes.iter().any(|present| present == scope))
    {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "third-party client missing required scope(s): {}",
                policy.third_party_required_scopes.join(", ")
            ),
        )
            .into_response();
    }

    if !policy.required_permissions.is_empty() {
        match state
            .resolve_permissions(&claims.sub, claims.perm_rev)
            .await
        {
            Some(permission_set) => {
                let missing = policy
                    .required_permissions
                    .iter()
                    .filter(|perm| !permission_set.contains(**perm))
                    .copied()
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    return (
                        StatusCode::FORBIDDEN,
                        format!("missing required permission(s): {}", missing.join(", ")),
                    )
                        .into_response();
                }
            }
            None => {
                let fallback_scopes = policy
                    .required_permissions
                    .iter()
                    .map(|permission| permission_to_scope(permission))
                    .collect::<Vec<_>>();
                if !fallback_scopes
                    .iter()
                    .all(|scope| claims.scopes.iter().any(|present| present == scope))
                {
                    return (
                        StatusCode::FORBIDDEN,
                        "missing required permission scopes".to_string(),
                    )
                        .into_response();
                }
            }
        }
    }

    next.run(request).await
}

fn build_route_policy(surface: HostSurface, method: &Method, path: &str) -> RoutePolicy {
    let mut policy = RoutePolicy {
        required_roles: required_roles_for_route(surface, path),
        third_party_required_scopes: default_third_party_scopes(surface, method),
        always_required_scopes: Vec::new(),
        required_permissions: Vec::new(),
        require_step_up_mfa: false,
    };

    if path.starts_with("/v1/system/billing") {
        policy.always_required_scopes.push("billing:admin");
        policy.required_permissions.push("billing.admin.write");
        policy.require_step_up_mfa = true;
    }

    if path.starts_with("/v1/system/users/")
        && matches!(
            *method,
            Method::PUT | Method::PATCH | Method::DELETE | Method::POST
        )
    {
        policy.require_step_up_mfa = true;
    }

    if path.starts_with("/v1/system/feature-flags/")
        && matches!(*method, Method::PUT | Method::PATCH | Method::DELETE)
    {
        policy.require_step_up_mfa = true;
    }

    policy
}

fn required_roles_for_route(surface: HostSurface, path: &str) -> &'static [&'static str] {
    if path.starts_with("/v1/auth/") {
        return &[];
    }

    match surface {
        HostSurface::Public => &["user"],
        HostSurface::Platform => {
            if path.starts_with("/v1/support") {
                &["support"]
            } else if path.starts_with("/v1/partner") {
                &["partner"]
            } else {
                &["support"]
            }
        }
        HostSurface::Control => &["superadmin", "admin", "manager", "auditor"],
    }
}

fn default_third_party_scopes(surface: HostSurface, method: &Method) -> Vec<&'static str> {
    match surface {
        HostSurface::Public => {
            if method == Method::GET {
                vec!["public:read"]
            } else {
                vec!["public:write"]
            }
        }
        HostSurface::Platform => {
            if method == Method::GET {
                vec!["platform:read"]
            } else {
                vec!["platform:write"]
            }
        }
        HostSurface::Control => {
            if method == Method::GET {
                vec!["control:read"]
            } else {
                vec!["control:write"]
            }
        }
    }
}

fn permission_to_scope(permission: &str) -> String {
    permission.replace('.', ":")
}

fn is_first_party_client(client: &ValidatedClient) -> bool {
    client.client_id.starts_with("wildon-")
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
            | "/v1/proxy/auth-health"
            | "/.well-known/openid-configuration"
            | "/.well-known/scopes"
            | "/oauth2/jwks.json"
            | "/oauth2/authorize"
            | "/oauth2/token"
            | "/oauth2/revoke"
            | "/oauth2/introspect"
            | "/oauth2/userinfo"
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
