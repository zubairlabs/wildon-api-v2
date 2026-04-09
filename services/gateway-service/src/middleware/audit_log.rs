use crate::state::{AppState, ValidatedClient};
use ::middleware::RequestId;
use auth::{claims::Claims, jwt};
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::AUTHORIZATION, Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use config::grpc::inject_internal_metadata;
use contracts::wildon::logs::v1::{
    AuditAccessPurpose, AuditActorType, AuditAuthMechanism, AuditDataSensitivityLevel,
    AuditResult,
};
use logs_sdk::AuditEventBuilder;
use tonic::Request as GrpcRequest;
use uuid::Uuid;

const EDGE_AUDIT_SKIP_ROUTES: &[(&str, &str)] = &[("PATCH", "/v1/users/me")];

pub async fn audit_mutations(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if should_skip(path.as_str()) {
        return next.run(request).await;
    }
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| path.clone());

    if EDGE_AUDIT_SKIP_ROUTES
        .iter()
        .any(|(skip_method, skip_path)| {
            *skip_method == method.as_str() && *skip_path == matched_path
        })
    {
        return next.run(request).await;
    }

    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0.clone())
        .or_else(|| header_value(request.headers(), "x-request-id"));
    let traceparent = header_value(request.headers(), "traceparent");
    let host = header_value(request.headers(), "host");
    let user_agent = header_value(request.headers(), "user-agent");
    let forwarded_for = header_value(request.headers(), "x-forwarded-for");
    let claims = request
        .extensions()
        .get::<Claims>()
        .cloned()
        .or_else(|| parse_claims(request.headers()));
    let validated_client = request.extensions().get::<ValidatedClient>().cloned();
    let client_id = validated_client
        .as_ref()
        .map(|value| value.client_id.clone())
        .or_else(|| header_value(request.headers(), "x-client-id"));

    let response = next.run(request).await;
    let status = response.status();
    if !should_capture(&method, status, matched_path.as_str()) {
        return response;
    }

    let actor_user_id = claims.as_ref().map(|value| value.sub.clone());
    let action = classify_action(status);
    let result = classify_result(status);
    let (actor_type, actor_id, actor_role, auth_mechanism, session_id) = infer_actor_context(
        claims.as_ref(),
        client_id.as_deref(),
    );
    let payload = serde_json::json!({
        "layer": "edge",
        "host": host,
        "matched_path": matched_path,
        "original_path": path,
        "forwarded_for": forwarded_for,
        "actor_user_id": actor_user_id,
        "client_id": client_id,
    });
    let status_code = i32::from(status.as_u16());
    let reason = denial_reason(status);
    let path_for_event = matched_path.clone();

    tokio::spawn(async move {
        publish_audit(
            state,
            request_id,
            traceparent,
            actor_type,
            actor_id,
            actor_role,
            auth_mechanism,
            session_id,
            action,
            path_for_event,
            method.as_str().to_string(),
            user_agent,
            forwarded_for,
            status_code,
            result,
            reason,
            infer_sensitivity(matched_path.as_str()),
            payload,
        )
        .await;
    });

    response
}

async fn publish_audit(
    state: AppState,
    request_id: Option<String>,
    traceparent: Option<String>,
    actor_type: AuditActorType,
    actor_id: String,
    actor_role: String,
    auth_mechanism: AuditAuthMechanism,
    session_id: Option<String>,
    action: String,
    resource_id: String,
    method: String,
    user_agent: Option<String>,
    forwarded_for: Option<String>,
    status_code: i32,
    result: AuditResult,
    reason: Option<String>,
    sensitivity: AuditDataSensitivityLevel,
    payload_json: serde_json::Value,
) {
    let mut request = GrpcRequest::new(
        AuditEventBuilder::new("gateway-service", action, "route", resource_id.clone())
            .event_id(Uuid::new_v4().to_string())
            .actor(actor_type, actor_id, actor_role, auth_mechanism)
            .context(
                request_id.as_deref(),
                traceparent.as_deref(),
                session_id.as_deref(),
                forwarded_for.as_deref(),
                user_agent.as_deref(),
                Some(method.as_str()),
                Some(resource_id.as_str()),
                Some(status_code),
                AuditAccessPurpose::System,
            )
            .result(result)
            .reason(reason.unwrap_or_default())
            .sensitivity(sensitivity)
            .metadata_value(payload_json)
            .into_ingest_request(),
    );

    if let Err(err) = inject_internal_metadata(
        &mut request,
        "gateway-service",
        request_id.as_deref(),
        traceparent.as_deref(),
    ) {
        tracing::warn!(error = %err, resource_id = resource_id, "failed to build gateway audit metadata");
        return;
    }

    let mut logs_client = state.logs_client.lock().await;
    if let Err(err) = logs_client.ingest_audit(request).await {
        tracing::warn!(error = %err, resource_id = resource_id, "failed to publish gateway audit event");
    }
}

fn should_audit(method: &Method, path: &str) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && !should_skip(path)
}

fn should_skip(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/docs"
            | "/docs/"
            | "/openapi/gateway-v1.json"
            | "/openapi/control-v1.json"
            | "/docs/openapi/control-v1.json"
    )
}

fn should_capture(method: &Method, status: StatusCode, path: &str) -> bool {
    should_audit(method, path) || matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS)
}

fn classify_action(status: StatusCode) -> String {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        "gateway.request.denied".to_string()
    } else if status.is_client_error() || status.is_server_error() {
        "gateway.request.failed".to_string()
    } else {
        "gateway.request.completed".to_string()
    }
}

fn classify_result(status: StatusCode) -> AuditResult {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        AuditResult::Denied
    } else if status.is_client_error() || status.is_server_error() {
        AuditResult::Failure
    } else {
        AuditResult::Success
    }
}

fn denial_reason(status: StatusCode) -> Option<String> {
    match status {
        StatusCode::BAD_REQUEST => Some("malformed_request".to_string()),
        StatusCode::UNAUTHORIZED => Some("unauthenticated".to_string()),
        StatusCode::FORBIDDEN => Some("permission_denied".to_string()),
        StatusCode::TOO_MANY_REQUESTS => Some("rate_limited".to_string()),
        _ => None,
    }
}

fn parse_claims(headers: &axum::http::HeaderMap) -> Option<Claims> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| jwt::parse_bearer_header(value).ok())
}

fn infer_actor_context(
    claims: Option<&Claims>,
    client_id: Option<&str>,
) -> (
    AuditActorType,
    String,
    String,
    AuditAuthMechanism,
    Option<String>,
) {
    if let Some(claims) = claims {
        return (
            AuditActorType::User,
            claims.sub.clone(),
            claims
                .roles
                .first()
                .cloned()
                .unwrap_or_else(|| "user".to_string()),
            AuditAuthMechanism::Jwt,
            claims.sid.clone(),
        );
    }
    if let Some(client_id) = client_id.filter(|value| !value.trim().is_empty()) {
        return (
            AuditActorType::ApiClient,
            client_id.to_string(),
            "api_client".to_string(),
            AuditAuthMechanism::ApiKey,
            None,
        );
    }

    (
        AuditActorType::System,
        "anonymous".to_string(),
        "anonymous".to_string(),
        AuditAuthMechanism::Unspecified,
        None,
    )
}

fn infer_sensitivity(path: &str) -> AuditDataSensitivityLevel {
    let path = path.to_ascii_lowercase();
    if path.contains("audit") || path.contains("export") || path.contains("billing") {
        AuditDataSensitivityLevel::Critical
    } else if path.contains("care-circle")
        || path.contains("medication")
        || path.contains("allerg")
        || path.contains("condition")
        || path.contains("incident")
        || path.contains("location")
        || path.contains("note")
    {
        AuditDataSensitivityLevel::Phi
    } else if path.contains("device") || path.contains("access") {
        AuditDataSensitivityLevel::Sensitive
    } else {
        AuditDataSensitivityLevel::Normal
    }
}

fn header_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}
