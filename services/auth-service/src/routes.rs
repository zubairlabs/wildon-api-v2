use crate::{
    modules::sessions::{
        issue_session_tokens, refresh_session_tokens, revoke_all_sessions_for_user,
        validate_claims_against_session, IssueSessionInput, RefreshSessionInput,
        RevokeAllSessionsInput, SessionError,
    },
    state::AppState,
};
use auth::{claims::Claims, jwt};
use axum::{
    extract::State,
    http::{header::USER_AGENT, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct HealthPayload {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct IssueTokenRequest {
    pub sub: String,
    pub aud: String,
    pub realm: String,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub device_fingerprint_hash: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub mfa_level: Option<i16>,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeAllSessionsRequest {
    pub sub: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_at: i64,
    pub refresh_expires_at: i64,
    pub session_id: String,
    pub session_version: i32,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub claims: Option<Claims>,
}

#[derive(Debug, Serialize)]
pub struct RevokeAllSessionsResponse {
    pub session_version: i32,
    pub revoked_sessions: i64,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/tokens/issue", post(issue_token))
        .route("/v1/tokens/refresh", post(refresh_token))
        .route("/v1/tokens/introspect", post(introspect_token))
        .route("/v1/sessions/revoke-all", post(revoke_all_sessions))
        .with_state(state)
}

async fn health() -> Json<HealthPayload> {
    Json(HealthPayload { status: "ok" })
}

async fn issue_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IssueTokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let user_agent = payload
        .user_agent
        .or_else(|| {
            headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string)
        })
        .or_else(|| {
            headers
                .get("x-user-agent")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string)
        });

    let ip_address = payload.ip_address.or_else(|| {
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(|value| value.trim().to_string())
    });

    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let client_id = payload.client_id.or_else(|| {
        headers
            .get("x-client-id")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
    });

    let issued = issue_session_tokens(
        &state,
        IssueSessionInput {
            sub: payload.sub,
            aud: payload.aud,
            realm: payload.realm,
            client_id,
            scopes: None,
            device_id: payload.device_id,
            device_fingerprint_hash: payload.device_fingerprint_hash,
            user_agent,
            ip_address,
            mfa_level: payload.mfa_level.unwrap_or(0),
            remember_me: payload.remember_me.unwrap_or(true),
            request_id,
        },
    )
    .await
    .map_err(map_session_error)?;

    Ok(Json(TokenResponse {
        access_token: issued.access_token,
        refresh_token: issued.refresh_token,
        token_type: issued.token_type,
        expires_at: issued.access_expires_at,
        refresh_expires_at: issued.refresh_expires_at,
        session_id: issued.session_id,
        session_version: issued.session_version,
    }))
}

async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    let refreshed = refresh_session_tokens(
        &state,
        RefreshSessionInput {
            token: payload.token,
            device_id: payload.device_id,
            request_id,
        },
    )
    .await
    .map_err(map_session_error)?;

    Ok(Json(TokenResponse {
        access_token: refreshed.access_token,
        refresh_token: refreshed.refresh_token,
        token_type: refreshed.token_type,
        expires_at: refreshed.access_expires_at,
        refresh_expires_at: refreshed.refresh_expires_at,
        session_id: refreshed.session_id,
        session_version: refreshed.session_version,
    }))
}

async fn introspect_token(
    State(state): State<AppState>,
    Json(payload): Json<IntrospectRequest>,
) -> Json<IntrospectResponse> {
    let claims = match jwt::decode_token(&payload.token)
        .and_then(|claims| jwt::validate_claims(&claims).map(|_| claims))
    {
        Ok(claims) => claims,
        Err(_) => {
            return Json(IntrospectResponse {
                active: false,
                claims: None,
            });
        }
    };

    let active = validate_claims_against_session(&state, &claims)
        .await
        .unwrap_or(false);

    Json(IntrospectResponse {
        active,
        claims: active.then_some(claims),
    })
}

async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeAllSessionsRequest>,
) -> Result<Json<RevokeAllSessionsResponse>, (StatusCode, String)> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    let result = revoke_all_sessions_for_user(
        &state,
        RevokeAllSessionsInput {
            sub: payload.sub,
            reason: payload
                .reason
                .unwrap_or_else(|| "manual_admin_revoke_all".to_string()),
            request_id,
        },
    )
    .await
    .map_err(map_session_error)?;

    Ok(Json(RevokeAllSessionsResponse {
        session_version: result.session_version,
        revoked_sessions: result.revoked_sessions,
    }))
}

fn map_session_error(err: SessionError) -> (StatusCode, String) {
    match err {
        SessionError::InvalidSubject
        | SessionError::InvalidDeviceId
        | SessionError::InvalidSessionId
        | SessionError::InvalidCursor
        | SessionError::UnsupportedAudience
        | SessionError::AudienceRealmMismatch => (StatusCode::BAD_REQUEST, err.to_string()),
        SessionError::InvalidRefreshToken
        | SessionError::RefreshTokenExpired
        | SessionError::SessionExpiredOrRevoked
        | SessionError::DeviceBindingMismatch
        | SessionError::RefreshReuseDetected
        | SessionError::UserNotFound => (StatusCode::UNAUTHORIZED, err.to_string()),
        SessionError::UserDisabled | SessionError::AuditorAccessDenied => {
            (StatusCode::FORBIDDEN, err.to_string())
        }
        SessionError::UserStateUnavailable(_) => (StatusCode::BAD_GATEWAY, err.to_string()),
        SessionError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}
