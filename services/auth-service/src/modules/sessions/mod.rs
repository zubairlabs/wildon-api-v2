use crate::state::AppState;
use auth::{audiences::is_supported_audience, claims::Claims, scope_catalog};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use config::grpc::inject_internal_metadata;
use contracts::wildon::users::v1::GetUserAuthStateRequest;
use redis::AsyncCommands;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;
use tonic::{Code, Request as GrpcRequest};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IssueSessionInput {
    pub sub: String,
    pub aud: String,
    pub realm: String,
    pub client_id: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub device_id: Option<String>,
    pub device_fingerprint_hash: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub mfa_level: i16,
    pub remember_me: bool,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshSessionInput {
    pub token: String,
    pub device_id: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ListSessionsInput {
    pub sub: String,
    pub limit: u32,
    pub cursor: String,
}

#[derive(Debug, Clone)]
pub struct RevokeAllSessionsInput {
    pub sub: String,
    pub reason: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogoutSessionInput {
    pub refresh_token: String,
    pub reason: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogoutSessionByIdInput {
    pub sub: String,
    pub session_id: String,
    pub reason: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevokeAllSessionsResult {
    pub session_version: i32,
    pub revoked_sessions: i64,
}

#[derive(Debug, Clone)]
pub struct LogoutSessionResult {
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub session_id: String,
    pub aud: String,
    pub realm: String,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub remember_me: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_activity_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
    pub mfa_level: i16,
}

#[derive(Debug, Clone)]
pub struct ListSessionsOutput {
    pub sessions: Vec<SessionSummary>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub session_id: String,
    pub session_version: i32,
}

#[derive(Debug, Clone)]
struct UserAuthState {
    status: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    perm_rev: i64,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid subject: expected uuid")]
    InvalidSubject,
    #[error("invalid device id: expected uuid")]
    InvalidDeviceId,
    #[error("invalid session id: expected uuid")]
    InvalidSessionId,
    #[error("invalid cursor: expected unsigned integer offset")]
    InvalidCursor,
    #[error("unsupported audience")]
    UnsupportedAudience,
    #[error("audience and realm mismatch")]
    AudienceRealmMismatch,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("session expired or revoked")]
    SessionExpiredOrRevoked,
    #[error("device binding mismatch")]
    DeviceBindingMismatch,
    #[error("refresh token reuse detected")]
    RefreshReuseDetected,
    #[error("user not found")]
    UserNotFound,
    #[error("user account disabled")]
    UserDisabled,
    #[error("auditor access expired or revoked")]
    AuditorAccessDenied,
    #[error("users-service unavailable: {0}")]
    UserStateUnavailable(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 200;

fn normalize_list_limit(limit: u32) -> i64 {
    let bounded = if limit == 0 {
        DEFAULT_LIST_LIMIT
    } else {
        limit.min(MAX_LIST_LIMIT)
    };
    i64::from(bounded)
}

fn parse_list_cursor(cursor: &str) -> Result<i64, SessionError> {
    let trimmed = cursor.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| SessionError::InvalidCursor)?;
    i64::try_from(parsed).map_err(|_| SessionError::InvalidCursor)
}

pub async fn issue_session_tokens(
    state: &AppState,
    input: IssueSessionInput,
) -> Result<SessionTokens, SessionError> {
    if !is_supported_audience(&input.aud) {
        return Err(SessionError::UnsupportedAudience);
    }
    if input.aud != input.realm {
        return Err(SessionError::AudienceRealmMismatch);
    }

    let user_id = Uuid::parse_str(&input.sub).map_err(|_| SessionError::InvalidSubject)?;
    let device_id = match input.device_id.as_deref() {
        Some(value) => Some(Uuid::parse_str(value).map_err(|_| SessionError::InvalidDeviceId)?),
        None => None,
    };
    let user_auth_state = load_user_auth_state(state, &user_id.to_string()).await?;
    if !is_active_user_status(&user_auth_state.status) {
        return Err(SessionError::UserDisabled);
    }

    let now = Utc::now();
    let access_exp = now + Duration::seconds(state.access_ttl_seconds(&input.aud));
    let refresh_exp = now
        + Duration::seconds(effective_refresh_ttl_seconds(
            state,
            &input.aud,
            input.remember_me,
        ));
    let session_exp = now
        + Duration::seconds(effective_absolute_session_ttl_seconds(
            state,
            &input.aud,
            input.remember_me,
        ));

    let session_id = Uuid::new_v4();
    let session_family_id = Uuid::new_v4();
    let refresh_token_raw = generate_refresh_token();
    let refresh_token_hash = hash_token(&refresh_token_raw);
    let refresh_id = Uuid::new_v4();

    let mut tx = state.db.begin().await?;

    sqlx::query(
        "INSERT INTO auth.users (id, updated_at) VALUES ($1, NOW()) ON CONFLICT (id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    let session_version: i32 =
        sqlx::query_scalar("SELECT session_version FROM auth.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;

    sqlx::query(
        "INSERT INTO auth.sessions (
            id, user_id, session_family_id, aud, realm,
            client_id, device_id, device_fingerprint_hash, created_at, last_activity_at,
            expires_at, ip_address, user_agent, mfa_level, remember_me
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, $12::INET, $13, $14, $15
        )",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(session_family_id)
    .bind(&input.aud)
    .bind(&input.realm)
    .bind(&input.client_id)
    .bind(device_id)
    .bind(&input.device_fingerprint_hash)
    .bind(now)
    .bind(now)
    .bind(session_exp)
    .bind(&input.ip_address)
    .bind(&input.user_agent)
    .bind(input.mfa_level.max(0))
    .bind(input.remember_me)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO auth.refresh_tokens (
            id, session_id, token_hash, replaced_by_token_id,
            expires_at, revoked_at, revoked_reason, created_at
        ) VALUES ($1, $2, $3, NULL, $4, NULL, NULL, $5)",
    )
    .bind(refresh_id)
    .bind(session_id)
    .bind(&refresh_token_hash)
    .bind(refresh_exp)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    emit_security_event_tx(
        &mut tx,
        "login_success",
        Some(user_id),
        Some(session_id),
        input.request_id.as_deref(),
        json!({
            "aud": input.aud,
            "realm": input.realm,
            "mfa_level": input.mfa_level.max(0),
            "device_bound": device_id.is_some(),
            "remember_me": input.remember_me,
        }),
    )
    .await?;

    tx.commit().await?;

    cache_session_version(state, user_id, session_version).await;
    cache_perm_revision(state, user_id, user_auth_state.perm_rev).await;
    cache_session_active(state, session_id, true).await;

    let access_token = mint_access_token(
        state,
        user_id,
        session_id,
        &input.aud,
        &input.realm,
        input.client_id.as_deref(),
        input.scopes.as_deref(),
        session_version,
        device_id,
        input.mfa_level.max(0),
        &user_auth_state.roles,
        &user_auth_state.scopes,
        user_auth_state.perm_rev,
    );

    Ok(SessionTokens {
        access_token,
        refresh_token: refresh_token_raw,
        token_type: "Bearer",
        access_expires_at: access_exp.timestamp(),
        refresh_expires_at: refresh_exp.timestamp(),
        session_id: session_id.to_string(),
        session_version,
    })
}

pub async fn refresh_session_tokens(
    state: &AppState,
    input: RefreshSessionInput,
) -> Result<SessionTokens, SessionError> {
    let presented_hash = hash_token(&input.token);
    let device_id = match input.device_id.as_deref() {
        Some(value) => Some(Uuid::parse_str(value).map_err(|_| SessionError::InvalidDeviceId)?),
        None => None,
    };

    let record = sqlx::query(
        "SELECT
            rt.id,
            rt.session_id,
            rt.replaced_by_token_id,
            rt.expires_at AS refresh_expires_at,
            rt.revoked_at AS refresh_revoked_at,
            s.user_id,
            s.session_family_id,
            s.aud,
            s.realm,
            s.client_id,
            s.device_id,
            s.remember_me,
            s.last_activity_at,
            s.expires_at AS session_expires_at,
            s.revoked_at AS session_revoked_at,
            s.mfa_level,
            u.session_version
         FROM auth.refresh_tokens rt
         JOIN auth.sessions s ON s.id = rt.session_id
         JOIN auth.users u ON u.id = s.user_id
         WHERE rt.token_hash = $1",
    )
    .bind(&presented_hash)
    .fetch_optional(&state.db)
    .await?;

    let row = match record {
        Some(row) => row,
        None => {
            emit_security_event(
                &state.db,
                "login_failed",
                None,
                None,
                input.request_id.as_deref(),
                json!({"reason": "refresh_not_found"}),
            )
            .await?;
            return Err(SessionError::InvalidRefreshToken);
        }
    };

    let refresh_id: Uuid = row.get("id");
    let session_id: Uuid = row.get("session_id");
    let replaced_by: Option<Uuid> = row.get("replaced_by_token_id");
    let refresh_exp: chrono::DateTime<Utc> = row.get("refresh_expires_at");
    let refresh_revoked_at: Option<chrono::DateTime<Utc>> = row.get("refresh_revoked_at");
    let user_id: Uuid = row.get("user_id");
    let session_family_id: Uuid = row.get("session_family_id");
    let aud: String = row.get("aud");
    let realm: String = row.get("realm");
    let client_id: Option<String> = row.get("client_id");
    let bound_device_id: Option<Uuid> = row.get("device_id");
    let remember_me: bool = row.get("remember_me");
    let last_activity_at: chrono::DateTime<Utc> = row.get("last_activity_at");
    let session_exp: chrono::DateTime<Utc> = row.get("session_expires_at");
    let session_revoked_at: Option<chrono::DateTime<Utc>> = row.get("session_revoked_at");
    let mfa_level: i16 = row.get("mfa_level");
    let session_version: i32 = row.get("session_version");
    let now = Utc::now();
    let user_auth_state = load_user_auth_state(state, &user_id.to_string()).await?;
    if !is_active_user_status(&user_auth_state.status) {
        return Err(SessionError::UserDisabled);
    }
    ensure_auditor_session_access(state, user_id, now).await?;

    if replaced_by.is_some() {
        revoke_session_family(
            state,
            session_family_id,
            "refresh_reuse_detected",
            Some(user_id),
            Some(session_id),
            input.request_id.as_deref(),
        )
        .await?;
        return Err(SessionError::RefreshReuseDetected);
    }

    if refresh_revoked_at.is_some() {
        return Err(SessionError::InvalidRefreshToken);
    }

    if refresh_exp <= now {
        return Err(SessionError::RefreshTokenExpired);
    }

    let inactivity_cutoff = now - Duration::seconds(state.inactivity_ttl_seconds(&aud));
    if session_revoked_at.is_some() || session_exp <= now || last_activity_at <= inactivity_cutoff {
        return Err(SessionError::SessionExpiredOrRevoked);
    }

    if let Some(bound) = bound_device_id {
        if device_id != Some(bound) {
            revoke_session_family(
                state,
                session_family_id,
                "device_binding_mismatch",
                Some(user_id),
                Some(session_id),
                input.request_id.as_deref(),
            )
            .await?;
            return Err(SessionError::DeviceBindingMismatch);
        }
    }

    let new_refresh_id = Uuid::new_v4();
    let new_refresh_raw = generate_refresh_token();
    let new_refresh_hash = hash_token(&new_refresh_raw);
    let new_refresh_exp =
        now + Duration::seconds(effective_refresh_ttl_seconds(state, &aud, remember_me));
    let access_exp = now + Duration::seconds(state.access_ttl_seconds(&aud));

    let mut tx = state.db.begin().await?;

    sqlx::query(
        "INSERT INTO auth.refresh_tokens (
            id, session_id, token_hash, replaced_by_token_id,
            expires_at, revoked_at, revoked_reason, created_at
         ) VALUES ($1, $2, $3, NULL, $4, NULL, NULL, $5)",
    )
    .bind(new_refresh_id)
    .bind(session_id)
    .bind(&new_refresh_hash)
    .bind(new_refresh_exp)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let updated = sqlx::query(
        "UPDATE auth.refresh_tokens
         SET replaced_by_token_id = $1, revoked_at = NOW(), revoked_reason = 'rotated'
         WHERE id = $2 AND replaced_by_token_id IS NULL AND revoked_at IS NULL",
    )
    .bind(new_refresh_id)
    .bind(refresh_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if updated != 1 {
        tx.rollback().await?;
        revoke_session_family(
            state,
            session_family_id,
            "refresh_reuse_detected",
            Some(user_id),
            Some(session_id),
            input.request_id.as_deref(),
        )
        .await?;
        return Err(SessionError::RefreshReuseDetected);
    }

    sqlx::query("UPDATE auth.sessions SET last_activity_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    cache_session_version(state, user_id, session_version).await;
    cache_perm_revision(state, user_id, user_auth_state.perm_rev).await;
    cache_session_active(state, session_id, true).await;

    let access_token = mint_access_token(
        state,
        user_id,
        session_id,
        &aud,
        &realm,
        client_id.as_deref(),
        None,
        session_version,
        bound_device_id,
        mfa_level,
        &user_auth_state.roles,
        &user_auth_state.scopes,
        user_auth_state.perm_rev,
    );

    Ok(SessionTokens {
        access_token,
        refresh_token: new_refresh_raw,
        token_type: "Bearer",
        access_expires_at: access_exp.timestamp(),
        refresh_expires_at: new_refresh_exp.timestamp(),
        session_id: session_id.to_string(),
        session_version,
    })
}

pub async fn validate_claims_against_session(
    state: &AppState,
    claims: &Claims,
) -> Result<bool, SessionError> {
    let session_id = match claims.sid.as_deref() {
        Some(value) => Uuid::parse_str(value).ok(),
        None => None,
    };

    let Some(session_id) = session_id else {
        return Ok(true);
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };

    let current_sv = load_session_version(state, user_id).await?;
    if current_sv != claims.sv {
        return Ok(false);
    }

    if let Some(cached_active) = load_cached_session_active(state, session_id).await {
        return Ok(cached_active);
    }

    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM auth.sessions
            WHERE id = $1
              AND revoked_at IS NULL
              AND expires_at > NOW()
        )",
    )
    .bind(session_id)
    .fetch_one(&state.db)
    .await?;

    cache_session_active(state, session_id, active).await;
    Ok(active)
}

pub async fn run_cleanup_once(state: &AppState) -> Result<(), SessionError> {
    sqlx::query("DELETE FROM auth.refresh_tokens WHERE expires_at < NOW() - INTERVAL '7 days'")
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM auth.sessions WHERE expires_at < NOW() - INTERVAL '30 days'")
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn list_sessions_for_user(
    state: &AppState,
    input: ListSessionsInput,
) -> Result<ListSessionsOutput, SessionError> {
    let user_id = Uuid::parse_str(&input.sub).map_err(|_| SessionError::InvalidSubject)?;
    let limit = normalize_list_limit(input.limit);
    let cursor = parse_list_cursor(input.cursor.as_str())?;
    let rows = sqlx::query(
        "SELECT
            id,
            aud,
            realm,
            client_id,
            device_id,
            remember_me,
            ip_address::TEXT AS ip_address,
            user_agent,
            created_at,
            last_activity_at,
            expires_at,
            revoked_at,
            revoked_reason,
            mfa_level
         FROM auth.sessions
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT $2
         OFFSET $3",
    )
    .bind(user_id)
    .bind(limit + 1)
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;

    let mut sessions = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows {
        let session_id: Uuid = row.get("id");
        let device_id: Option<Uuid> = row.get("device_id");
        let created_at: chrono::DateTime<Utc> = row.get("created_at");
        let last_activity_at: chrono::DateTime<Utc> = row.get("last_activity_at");
        let expires_at: chrono::DateTime<Utc> = row.get("expires_at");
        let revoked_at: Option<chrono::DateTime<Utc>> = row.get("revoked_at");
        sessions.push(SessionSummary {
            session_id: session_id.to_string(),
            aud: row.get("aud"),
            realm: row.get("realm"),
            client_id: row.get("client_id"),
            device_id: device_id.map(|value| value.to_string()),
            remember_me: row.get("remember_me"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            created_at: created_at.timestamp(),
            last_activity_at: last_activity_at.timestamp(),
            expires_at: expires_at.timestamp(),
            revoked_at: revoked_at.map(|value| value.timestamp()),
            revoked_reason: row.get("revoked_reason"),
            mfa_level: row.get("mfa_level"),
        });
    }

    let has_more = sessions.len() > limit as usize;
    if has_more {
        sessions.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        Some(cursor.saturating_add(limit).to_string())
    } else {
        None
    };

    Ok(ListSessionsOutput {
        sessions,
        next_cursor,
        has_more,
    })
}

pub async fn revoke_all_sessions_for_user(
    state: &AppState,
    input: RevokeAllSessionsInput,
) -> Result<RevokeAllSessionsResult, SessionError> {
    let user_id = Uuid::parse_str(&input.sub).map_err(|_| SessionError::InvalidSubject)?;
    let reason = if input.reason.trim().is_empty() {
        "manual_admin_revoke_all".to_string()
    } else {
        input.reason.trim().to_string()
    };

    let mut tx = state.db.begin().await?;

    let session_version: i32 = sqlx::query_scalar(
        "UPDATE auth.users
         SET session_version = session_version + 1, updated_at = NOW()
         WHERE id = $1
         RETURNING session_version",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    let revoked_sessions = sqlx::query(
        "UPDATE auth.sessions
         SET revoked_at = COALESCE(revoked_at, NOW()),
             revoked_reason = COALESCE(revoked_reason, $2)
         WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await?
    .rows_affected() as i64;

    sqlx::query(
        "UPDATE auth.refresh_tokens rt
         SET revoked_at = COALESCE(rt.revoked_at, NOW()),
             revoked_reason = COALESCE(rt.revoked_reason, $2)
         FROM auth.sessions s
         WHERE s.id = rt.session_id
           AND s.user_id = $1",
    )
    .bind(user_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await?;

    emit_security_event_tx(
        &mut tx,
        "permission_changed",
        Some(user_id),
        None,
        input.request_id.as_deref(),
        json!({ "reason": reason, "revoked_sessions": revoked_sessions }),
    )
    .await?;

    tx.commit().await?;
    cache_session_version(state, user_id, session_version).await;

    Ok(RevokeAllSessionsResult {
        session_version,
        revoked_sessions,
    })
}

pub async fn logout_session_by_refresh_token(
    state: &AppState,
    input: LogoutSessionInput,
) -> Result<LogoutSessionResult, SessionError> {
    if input.refresh_token.trim().is_empty() {
        return Ok(LogoutSessionResult { revoked: false });
    }

    let presented_hash = hash_token(input.refresh_token.trim());
    let row = sqlx::query(
        "SELECT
            rt.session_id,
            s.session_family_id,
            s.user_id
         FROM auth.refresh_tokens rt
         JOIN auth.sessions s ON s.id = rt.session_id
         WHERE rt.token_hash = $1",
    )
    .bind(presented_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(LogoutSessionResult { revoked: false });
    };

    let session_id: Uuid = row.get("session_id");
    let session_family_id: Uuid = row.get("session_family_id");
    let user_id: Uuid = row.get("user_id");
    let reason = if input.reason.trim().is_empty() {
        "logout".to_string()
    } else {
        input.reason.trim().to_string()
    };

    revoke_session_family(
        state,
        session_family_id,
        reason.as_str(),
        Some(user_id),
        Some(session_id),
        input.request_id.as_deref(),
    )
    .await?;

    Ok(LogoutSessionResult { revoked: true })
}

pub async fn logout_session_by_id(
    state: &AppState,
    input: LogoutSessionByIdInput,
) -> Result<LogoutSessionResult, SessionError> {
    let user_id = Uuid::parse_str(&input.sub).map_err(|_| SessionError::InvalidSubject)?;
    let session_id =
        Uuid::parse_str(&input.session_id).map_err(|_| SessionError::InvalidSessionId)?;
    let row = sqlx::query(
        "SELECT session_family_id
         FROM auth.sessions
         WHERE id = $1
           AND user_id = $2",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(LogoutSessionResult { revoked: false });
    };

    let session_family_id: Uuid = row.get("session_family_id");
    let reason = if input.reason.trim().is_empty() {
        "logout".to_string()
    } else {
        input.reason.trim().to_string()
    };

    revoke_session_family(
        state,
        session_family_id,
        reason.as_str(),
        Some(user_id),
        Some(session_id),
        input.request_id.as_deref(),
    )
    .await?;

    Ok(LogoutSessionResult { revoked: true })
}

fn mint_access_token(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    aud: &str,
    realm: &str,
    client_id: Option<&str>,
    requested_scopes: Option<&[String]>,
    session_version: i32,
    device_id: Option<Uuid>,
    mfa_level: i16,
    roles: &[String],
    user_scopes: &[String],
    perm_rev: i64,
) -> String {
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(state.access_ttl_seconds(aud));

    let mut amr = vec!["pwd".to_string()];
    if mfa_level > 0 {
        amr.push("mfa".to_string());
    }

    let claims = Claims {
        sub: user_id.to_string(),
        cid: client_id.unwrap_or_default().to_string(),
        aud: aud.to_string(),
        iss: state.issuer.clone(),
        realm: realm.to_string(),
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
        jti: Uuid::new_v4().to_string(),
        sid: Some(session_id.to_string()),
        scopes: resolve_scopes(aud, roles, user_scopes, requested_scopes),
        amr,
        sv: session_version,
        perm_rev,
        device_id: device_id.map(|value| value.to_string()),
        roles: roles.to_vec(),
    };

    let raw = serde_json::to_vec(&claims).expect("failed to encode claims json");
    URL_SAFE_NO_PAD.encode(raw)
}

fn resolve_scopes(
    aud: &str,
    roles: &[String],
    user_scopes: &[String],
    requested: Option<&[String]>,
) -> Vec<String> {
    let mut allowed = Vec::new();
    let is_auditor = roles
        .iter()
        .any(|role| role.eq_ignore_ascii_case("auditor"));
    if !is_auditor {
        allowed.extend(
            scope_catalog::audience_default_scopes(aud)
                .iter()
                .map(|scope| (*scope).to_string()),
        );
    }
    allowed.extend(
        scope_catalog::oidc_default_scopes()
            .iter()
            .map(|scope| (*scope).to_string()),
    );

    for role in roles {
        allowed.extend(
            scope_catalog::role_default_scopes(role)
                .iter()
                .map(|scope| (*scope).to_string()),
        );
    }

    for scope in user_scopes {
        let normalized = scope.trim().to_lowercase();
        if !scope_catalog::is_supported_scope(&normalized) {
            continue;
        }
        if is_auditor && normalized != "audit_only" {
            continue;
        }
        allowed.push(normalized);
    }

    let mut unique_allowed = std::collections::HashSet::new();
    let allowed = allowed
        .into_iter()
        .filter(|scope| unique_allowed.insert(scope.clone()))
        .collect::<Vec<_>>();

    if let Some(requested) = requested {
        let allowed_set = allowed
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut seen = std::collections::HashSet::new();
        let filtered = requested
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .filter(|value| allowed_set.contains(*value))
            .map(ToString::to_string)
            .filter(|value| seen.insert(value.clone()))
            .collect::<Vec<_>>();
        if !filtered.is_empty() {
            return filtered;
        }
    }

    allowed
}

fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn generate_refresh_token() -> String {
    format!("rt_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn effective_refresh_ttl_seconds(state: &AppState, aud: &str, remember_me: bool) -> i64 {
    const NON_REMEMBER_REFRESH_TTL_SECONDS: i64 = 24 * 60 * 60;
    let configured = state.refresh_ttl_seconds(aud);
    if remember_me {
        configured
    } else {
        configured.min(NON_REMEMBER_REFRESH_TTL_SECONDS)
    }
}

fn effective_absolute_session_ttl_seconds(state: &AppState, aud: &str, remember_me: bool) -> i64 {
    const NON_REMEMBER_ABSOLUTE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
    let configured = state.absolute_session_ttl_seconds(aud);
    if remember_me {
        configured
    } else {
        configured.min(NON_REMEMBER_ABSOLUTE_TTL_SECONDS)
    }
}

async fn load_user_auth_state(
    state: &AppState,
    user_id: &str,
) -> Result<UserAuthState, SessionError> {
    let response = {
        let mut users_client = state.users_client.lock().await;
        let mut grpc_request = GrpcRequest::new(GetUserAuthStateRequest {
            user_id: user_id.to_string(),
        });
        let _ = inject_internal_metadata(&mut grpc_request, "auth-service", None, None);
        users_client.get_user_auth_state(grpc_request).await
    };

    match response {
        Ok(response) => {
            let payload = response.into_inner();
            Ok(UserAuthState {
                status: payload.status,
                roles: payload.roles,
                scopes: payload.scopes,
                perm_rev: payload.perm_rev.max(1),
            })
        }
        Err(status) if status.code() == Code::NotFound => Err(SessionError::UserNotFound),
        Err(status) => Err(SessionError::UserStateUnavailable(status.to_string())),
    }
}

async fn ensure_auditor_session_access(
    state: &AppState,
    user_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(), SessionError> {
    let row = sqlx::query(
        "SELECT is_active, expires_at
         FROM control_app.audit_accounts
         WHERE user_id = $1
           AND role = 'auditor'
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(());
    };

    let is_active: bool = row.get("is_active");
    let expires_at: chrono::DateTime<Utc> = row.get("expires_at");
    if !is_active || expires_at <= now {
        return Err(SessionError::AuditorAccessDenied);
    }

    Ok(())
}

fn is_active_user_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("active")
}

async fn load_session_version(state: &AppState, user_id: Uuid) -> Result<i32, SessionError> {
    if let Some(redis_client) = &state.redis {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            let key = format!("sv:user:{user_id}");
            if let Ok(value) = conn.get::<_, Option<i32>>(&key).await {
                if let Some(value) = value {
                    return Ok(value);
                }
            }
        }
    }

    let version: i32 = sqlx::query_scalar("SELECT session_version FROM auth.users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    cache_session_version(state, user_id, version).await;
    Ok(version)
}

async fn cache_session_version(state: &AppState, user_id: Uuid, session_version: i32) {
    if let Some(redis_client) = &state.redis {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            let key = format!("sv:user:{user_id}");
            let _ = conn
                .set_ex::<_, _, ()>(key, session_version, state.redis_cache_ttl_seconds)
                .await;
        }
    }
}

async fn cache_perm_revision(state: &AppState, user_id: Uuid, perm_rev: i64) {
    if let Some(redis_client) = &state.redis {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            let key = format!("perm:user:{user_id}");
            let _ = conn
                .set_ex::<_, _, ()>(key, perm_rev, state.redis_cache_ttl_seconds)
                .await;
        }
    }
}

async fn load_cached_session_active(state: &AppState, session_id: Uuid) -> Option<bool> {
    let redis_client = state.redis.as_ref()?;
    let mut conn = redis_client.get_multiplexed_async_connection().await.ok()?;
    let key = format!("session:active:{session_id}");
    let value = conn.get::<_, Option<u8>>(&key).await.ok()?;
    value.map(|value| value == 1)
}

async fn cache_session_active(state: &AppState, session_id: Uuid, active: bool) {
    if let Some(redis_client) = &state.redis {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            let key = format!("session:active:{session_id}");
            let value = if active { 1 } else { 0 };
            let _ = conn
                .set_ex::<_, _, ()>(key, value, state.redis_cache_ttl_seconds)
                .await;
        }
    }
}

async fn revoke_session_family(
    state: &AppState,
    session_family_id: Uuid,
    reason: &str,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    request_id: Option<&str>,
) -> Result<(), SessionError> {
    let mut tx = state.db.begin().await?;

    sqlx::query(
        "UPDATE auth.sessions
         SET revoked_at = COALESCE(revoked_at, NOW()),
             revoked_reason = COALESCE(revoked_reason, $2)
         WHERE session_family_id = $1",
    )
    .bind(session_family_id)
    .bind(reason)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE auth.refresh_tokens rt
         SET revoked_at = COALESCE(rt.revoked_at, NOW()),
             revoked_reason = COALESCE(rt.revoked_reason, $2)
         FROM auth.sessions s
         WHERE s.id = rt.session_id
           AND s.session_family_id = $1",
    )
    .bind(session_family_id)
    .bind(reason)
    .execute(&mut *tx)
    .await?;

    let event_type = if reason == "refresh_reuse_detected" {
        "refresh_reuse_detected"
    } else {
        "session_revoked"
    };
    emit_security_event_tx(
        &mut tx,
        event_type,
        user_id,
        session_id,
        request_id,
        json!({ "reason": reason, "session_family_id": session_family_id }),
    )
    .await?;

    tx.commit().await?;
    if let Some(session_id) = session_id {
        cache_session_active(state, session_id, false).await;
    }
    Ok(())
}

async fn emit_security_event(
    db: &sqlx::PgPool,
    event_type: &str,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    request_id: Option<&str>,
    details: Value,
) -> Result<(), SessionError> {
    sqlx::query(
        "INSERT INTO auth.security_events (
            event_type, user_id, session_id, request_id, details
        ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(session_id)
    .bind(request_id)
    .bind(details)
    .execute(db)
    .await?;
    Ok(())
}

async fn emit_security_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_type: &str,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    request_id: Option<&str>,
    details: Value,
) -> Result<(), SessionError> {
    sqlx::query(
        "INSERT INTO auth.security_events (
            event_type, user_id, session_id, request_id, details
        ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(session_id)
    .bind(request_id)
    .bind(details)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
