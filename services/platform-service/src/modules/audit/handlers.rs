use ::middleware::RequestId;
use auth::{claims::Claims, jwt};
use axum::{
    body::Body,
    extract::{Extension, MatchedPath, Query, State},
    http::{header::AUTHORIZATION, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use contracts::wildon::logs::v1::AuditLogRecord;
use ipnet::IpNet;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::Row;
use std::{net::IpAddr, str::FromStr};
use uuid::Uuid;

use crate::state::AppState;

const AUDITOR_RATE_LIMIT_WINDOW_SECONDS: i64 = 60;
const AUDITOR_RATE_LIMIT_PER_IP: i64 = 120;
const AUDITOR_RATE_LIMIT_PER_USER: i64 = 240;

#[derive(Debug, Clone)]
struct AuditAccountRecord {
    user_id: Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
    allowed_ips: Option<Vec<String>>,
    is_active: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditLogsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    action: Option<String>,
    consumer: Option<String>,
    user_id: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ManagedUsersQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SystemDevicesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    status: Option<String>,
    search: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MemberSearchQuery {
    q: Option<String>,
    condition: Option<String>,
    allergy: Option<String>,
    medication: Option<String>,
    has_active_incidents: Option<bool>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AuditLogItemResponse {
    event_id: String,
    user_id: String,
    action: String,
    consumer: String,
    created_at: i64,
    payload: JsonValue,
}

#[derive(Debug, Serialize)]
struct AuditLogsPageResponse {
    limit: u32,
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct AuditLogsListResponse {
    items: Vec<AuditLogItemResponse>,
    page: AuditLogsPageResponse,
    total: u64,
}

pub async fn audit_auditor_requests(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0.clone());
    let traceparent = header_value(request.headers(), "traceparent");
    let host = header_value(request.headers(), "host");
    let user_agent = header_value(request.headers(), "user-agent");
    let forwarded_for = extract_request_ip(request.headers());
    let query = request.uri().query().map(ToString::to_string);
    let parsed_claims = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| jwt::parse_bearer_header(value).ok());

    let response = next.run(request).await;
    let status = response.status();

    let actor_user_id = parsed_claims.as_ref().map(|claims| claims.sub.clone());
    let action = format!(
        "auditor.{}.{}",
        method.as_str().to_ascii_lowercase(),
        action_suffix(&matched_path)
    );
    let payload = serde_json::json!({
        "layer": "http",
        "service": "platform-service",
        "method": method.as_str(),
        "path": path,
        "matched_path": matched_path.clone(),
        "query": query,
        "status_code": status.as_u16(),
        "success": status.is_success(),
        "request_id": request_id,
        "host": host,
        "user_agent": user_agent,
        "forwarded_for": forwarded_for,
        "actor": {
            "user_id": actor_user_id,
            "audience": parsed_claims.as_ref().map(|claims| claims.aud.clone()),
            "realm": parsed_claims.as_ref().map(|claims| claims.realm.clone()),
            "roles": parsed_claims.as_ref().map(|claims| claims.roles.clone()).unwrap_or_default(),
            "scopes": parsed_claims.as_ref().map(|claims| claims.scopes.clone()).unwrap_or_default(),
        }
    });

    let audit_user_id = parsed_claims
        .as_ref()
        .map(|claims| claims.sub.as_str())
        .unwrap_or("anonymous");
    state
        .shared_clients
        .ingest_audit_event(
            "platform-service",
            request_id.as_deref(),
            traceparent.as_deref(),
            audit_user_id,
            &action,
            &payload.to_string(),
        )
        .await;

    response
}

pub async fn enforce_auditor_auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() != Method::GET {
        return (StatusCode::FORBIDDEN, "auditor accounts are read-only").into_response();
    }

    let header_value = match request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
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
    if claims.aud != "platform" || claims.realm != "platform" {
        return (
            StatusCode::FORBIDDEN,
            "token audience/realm must be platform".to_string(),
        )
            .into_response();
    }
    if !claims.roles.iter().any(|role| role == "auditor") {
        return (
            StatusCode::FORBIDDEN,
            "role is not allowed for audit surface".to_string(),
        )
            .into_response();
    }
    if !claims.scopes.iter().any(|scope| scope == "audit_only") {
        return (
            StatusCode::FORBIDDEN,
            "auditor token is missing the audit_only scope",
        )
            .into_response();
    }

    let auditor = match load_audit_account_by_subject(&state, &claims.sub).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                "auditor account is not active for this identity",
            )
                .into_response();
        }
        Err(err) => return err.into_response(),
    };
    if !auditor.is_active || auditor.expires_at <= Utc::now() {
        return (
            StatusCode::FORBIDDEN,
            "auditor access has expired or been revoked",
        )
            .into_response();
    }
    if let Some(allowed_ips) = auditor.allowed_ips.as_ref() {
        let Some(request_ip) = extract_request_ip(request.headers()) else {
            return (
                StatusCode::FORBIDDEN,
                "auditor access requires an allowed request IP",
            )
                .into_response();
        };
        if !ip_matches_any_allowed(&request_ip, allowed_ips) {
            return (
                StatusCode::FORBIDDEN,
                "auditor access is not allowed from this IP",
            )
                .into_response();
        }
    }

    request.extensions_mut().insert(claims);
    request.extensions_mut().insert(auditor);
    next.run(request).await
}

pub async fn rate_limit_auditor_requests(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(redis) = &state.redis else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "auditor rate limiting is unavailable",
        )
            .into_response();
    };
    let claims = match request.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return (StatusCode::UNAUTHORIZED, "missing claims context").into_response(),
    };
    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "auditor rate limiting is unavailable",
        )
            .into_response();
    };

    let request_ip = extract_request_ip(request.headers()).unwrap_or_else(|| "unknown".to_string());
    let ip_allowed = consume_rate_limit(
        &mut conn,
        &format!("rl:platform:auditor:ip:{request_ip}"),
        AUDITOR_RATE_LIMIT_PER_IP,
        AUDITOR_RATE_LIMIT_WINDOW_SECONDS,
    )
    .await;
    let user_allowed = consume_rate_limit(
        &mut conn,
        &format!("rl:platform:auditor:user:{}", claims.sub),
        AUDITOR_RATE_LIMIT_PER_USER,
        AUDITOR_RATE_LIMIT_WINDOW_SECONDS,
    )
    .await;

    match (ip_allowed, user_allowed) {
        (Ok(true), Ok(true)) => next.run(request).await,
        (Ok(false), _) | (_, Ok(false)) => (
            StatusCode::TOO_MANY_REQUESTS,
            "auditor request rate limit exceeded",
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "auditor rate limiting is unavailable",
        )
            .into_response(),
    }
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ManagedUsersQuery>,
) -> Result<Response, (StatusCode, String)> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_offset_cursor(query.cursor.as_deref())?;

    let rows = sqlx::query(
        "SELECT
            au.id::text AS user_id,
            COALESCE(au.email, '') AS email,
            COALESCE(uu.status, 'unknown') AS status,
            COALESCE((
                SELECT array_agg(role ORDER BY role)
                FROM users_app.role_assignments ra
                WHERE ra.user_id = au.id
            ), ARRAY[]::text[]) AS roles,
            COALESCE((
                SELECT array_agg(scope ORDER BY scope)
                FROM users_app.user_scope_assignments usa
                WHERE usa.user_id = au.id
            ), ARRAY[]::text[]) AS scopes,
            EXTRACT(EPOCH FROM au.created_at)::BIGINT AS created_at,
            EXTRACT(EPOCH FROM au.updated_at)::BIGINT AS updated_at
         FROM auth.users au
         LEFT JOIN users_app.users uu ON uu.user_id = au.id
         ORDER BY au.created_at DESC
         LIMIT $1
         OFFSET $2",
    )
    .bind(i64::from(limit + 1))
    .bind(cursor as i64)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    let has_more = rows.len() > limit as usize;
    let users = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| {
            serde_json::json!({
                "user_id": row.get::<String, _>("user_id"),
                "email": row.get::<String, _>("email"),
                "status": row.get::<String, _>("status"),
                "roles": row.get::<Vec<String>, _>("roles"),
                "scopes": row.get::<Vec<String>, _>("scopes"),
                "created_at": row.get::<i64, _>("created_at"),
                "updated_at": row.get::<i64, _>("updated_at"),
            })
        })
        .collect::<Vec<_>>();

    masked_json_response(&serde_json::json!({
        "users": users,
        "page": {
            "limit": limit,
            "next_cursor": if has_more {
                Some(cursor.saturating_add(limit as usize).to_string())
            } else {
                None::<String>
            },
            "has_more": has_more
        }
    }))
}

pub async fn list_devices(
    State(state): State<AppState>,
    Query(query): Query<SystemDevicesQuery>,
) -> Result<Response, (StatusCode, String)> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_offset_cursor(query.cursor.as_deref())?;
    let status = query
        .status
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty());
    let search = query
        .search
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let rows = sqlx::query(
        "SELECT
            d.id::text AS id,
            d.display_ref,
            d.imei,
            d.model_code,
            d.status,
            d.connection_status,
            d.owner_id::text AS owner_id,
            d.assigned_member_id::text AS assigned_member_id,
            COALESCE(m.name, '') AS assigned_member_name,
            d.subscription_status,
            d.firmware_version,
            d.last_ip,
            EXTRACT(EPOCH FROM d.last_seen_at)::BIGINT AS last_seen_at,
            EXTRACT(EPOCH FROM d.last_telemetry_at)::BIGINT AS last_telemetry_at,
            EXTRACT(EPOCH FROM d.created_at)::BIGINT AS created_at,
            EXTRACT(EPOCH FROM d.updated_at)::BIGINT AS updated_at
         FROM care_app.devices d
         LEFT JOIN care_app.members m ON m.id = d.assigned_member_id AND m.deleted_at IS NULL
         WHERE d.deleted_at IS NULL
           AND ($1::text IS NULL OR d.status = $1)
           AND (
                $2::text IS NULL
                OR d.display_ref ILIKE '%' || $2 || '%'
                OR d.imei ILIKE '%' || $2 || '%'
                OR d.model_code ILIKE '%' || $2 || '%'
                OR COALESCE(m.name, '') ILIKE '%' || $2 || '%'
           )
         ORDER BY d.created_at DESC
         LIMIT $3
         OFFSET $4",
    )
    .bind(status.as_deref())
    .bind(search.as_deref())
    .bind(i64::from(limit + 1))
    .bind(cursor as i64)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    let has_more = rows.len() > limit as usize;
    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| {
            serde_json::json!({
                "id": row.get::<String, _>("id"),
                "display_ref": row.get::<String, _>("display_ref"),
                "imei": row.get::<String, _>("imei"),
                "model_code": row.get::<String, _>("model_code"),
                "status": row.get::<String, _>("status"),
                "connection_status": row.get::<String, _>("connection_status"),
                "owner_id": row.get::<String, _>("owner_id"),
                "assigned_member_id": row.get::<Option<String>, _>("assigned_member_id"),
                "assigned_member_name": row.get::<String, _>("assigned_member_name"),
                "subscription_status": row.get::<Option<String>, _>("subscription_status").unwrap_or_default(),
                "firmware_version": row.get::<Option<String>, _>("firmware_version"),
                "last_ip": row.get::<Option<String>, _>("last_ip"),
                "last_seen_at": row.get::<Option<i64>, _>("last_seen_at"),
                "last_telemetry_at": row.get::<Option<i64>, _>("last_telemetry_at"),
                "created_at": row.get::<i64, _>("created_at"),
                "updated_at": row.get::<i64, _>("updated_at"),
            })
        })
        .collect::<Vec<_>>();

    masked_json_response(&serde_json::json!({
        "items": items,
        "page": {
            "limit": limit,
            "next_cursor": if has_more {
                Some(cursor.saturating_add(limit as usize).to_string())
            } else {
                None::<String>
            },
            "has_more": has_more
        }
    }))
}

pub async fn list_members(
    State(state): State<AppState>,
    Query(query): Query<MemberSearchQuery>,
) -> Result<Response, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).min(200).max(1) as i64;
    let fetch_limit = limit + 1;
    let q = query.q.filter(|s| !s.is_empty());
    let condition = query.condition.filter(|s| !s.is_empty());
    let allergy = query.allergy.filter(|s| !s.is_empty());
    let medication = query.medication.filter(|s| !s.is_empty());
    let has_active = query.has_active_incidents;
    let (cursor_ts, cursor_id) = parse_compound_cursor(query.cursor.as_deref())?;

    let rows = sqlx::query(
        "SELECT
            msi.member_id::text AS id,
            msi.display_ref,
            msi.name,
            msi.email,
            msi.phone,
            msi.address,
            msi.birth_date,
            msi.relationship,
            msi.owner_id::text,
            msi.conditions_summary,
            msi.allergies_summary,
            msi.medications_summary,
            msi.active_incident_count,
            EXTRACT(EPOCH FROM msi.member_created_at)::BIGINT AS created_at,
            CASE WHEN $1::text IS NOT NULL
                 THEN ts_rank(msi.search_vector, plainto_tsquery('simple', $1))
                 ELSE 0.0
            END AS relevance
         FROM care_app.member_search_index msi
         WHERE
            ($1::text IS NULL OR (
                msi.search_vector @@ plainto_tsquery('simple', $1)
                OR msi.name ILIKE '%' || $1 || '%'
                OR msi.email ILIKE '%' || $1 || '%'
                OR msi.phone ILIKE '%' || $1 || '%'
                OR msi.display_ref ILIKE '%' || $1 || '%'
            ))
            AND ($2::text IS NULL OR msi.conditions_text ILIKE '%' || $2 || '%')
            AND ($3::text IS NULL OR msi.allergies_text ILIKE '%' || $3 || '%')
            AND ($4::text IS NULL OR msi.medications_text ILIKE '%' || $4 || '%')
            AND ($5::bool IS NULL OR ($5 = true AND msi.active_incident_count > 0) OR $5 = false)
            AND ($6::timestamptz IS NULL OR msi.member_created_at < $6
                 OR (msi.member_created_at = $6 AND msi.member_id < $7::uuid))
         ORDER BY
            CASE WHEN $1::text IS NOT NULL
                 THEN ts_rank(msi.search_vector, plainto_tsquery('simple', $1))
                 ELSE 0.0
            END DESC,
            msi.member_created_at DESC,
            msi.member_id DESC
         LIMIT $8",
    )
    .bind(q.as_deref())
    .bind(condition.as_deref())
    .bind(allergy.as_deref())
    .bind(medication.as_deref())
    .bind(has_active)
    .bind(cursor_ts)
    .bind(cursor_id)
    .bind(fetch_limit)
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;

    let has_more = rows.len() as i64 > limit;
    let items = rows
        .iter()
        .take(limit as usize)
        .map(|row| {
            serde_json::json!({
                "id": row.get::<String, _>("id"),
                "display_ref": row.get::<String, _>("display_ref"),
                "name": row.get::<String, _>("name"),
                "email": row.get::<String, _>("email"),
                "phone": row.get::<String, _>("phone"),
                "address": row.get::<String, _>("address"),
                "birth_date": row.get::<Option<chrono::NaiveDate>, _>("birth_date").map(|date| date.to_string()),
                "relationship": row.get::<String, _>("relationship"),
                "owner_id": row.get::<String, _>("owner_id"),
                "conditions": row.get::<JsonValue, _>("conditions_summary"),
                "allergies": row.get::<JsonValue, _>("allergies_summary"),
                "medications": row.get::<JsonValue, _>("medications_summary"),
                "active_incident_count": row.get::<i32, _>("active_incident_count"),
                "created_at": row.get::<i64, _>("created_at"),
                "relevance": row.get::<f32, _>("relevance"),
            })
        })
        .collect::<Vec<_>>();

    let next_cursor = if has_more {
        items.last().map(|item| {
            format!(
                "{}_{}",
                item.get("created_at")
                    .and_then(|value| value.as_i64())
                    .unwrap_or(0),
                item.get("id")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
            )
        })
    } else {
        None
    };

    masked_json_response(&serde_json::json!({
        "items": items,
        "pagination": {
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": has_more
        }
    }))
}

pub async fn list_logs(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Response, (StatusCode, String)> {
    let response = fetch_audit_logs_response(&state, &request_id, query).await?;
    masked_json_response(&response)
}

pub async fn list_trail(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Response, (StatusCode, String)> {
    let response = fetch_audit_logs_response(&state, &request_id, query).await?;
    masked_json_response(&response)
}

fn normalize_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(50).clamp(1, 200)
}

fn parse_offset_cursor(cursor: Option<&str>) -> Result<usize, (StatusCode, String)> {
    cursor
        .unwrap_or_default()
        .trim()
        .parse::<usize>()
        .map_or_else(
            |err| {
                if cursor.unwrap_or_default().trim().is_empty() {
                    Ok(0)
                } else {
                    Err((StatusCode::BAD_REQUEST, format!("invalid cursor: {err}")))
                }
            },
            Ok,
        )
}

fn parse_compound_cursor(
    cursor: Option<&str>,
) -> Result<(Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>), (StatusCode, String)> {
    let Some(raw) = cursor.filter(|value| !value.is_empty()) else {
        return Ok((None, None));
    };
    let parts = raw.splitn(2, '_').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "cursor format: {timestamp}_{uuid}".to_string(),
        ));
    }
    let ts = parts[0]
        .parse::<i64>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad cursor timestamp".to_string()))?;
    let dt = chrono::DateTime::from_timestamp(ts, 0)
        .ok_or((StatusCode::BAD_REQUEST, "bad cursor timestamp".to_string()))?;
    let id = parts[1]
        .parse::<Uuid>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad cursor uuid".to_string()))?;
    Ok((Some(dt), Some(id)))
}

async fn fetch_audit_logs_response(
    state: &AppState,
    request_id: &RequestId,
    query: AuditLogsQuery,
) -> Result<AuditLogsListResponse, (StatusCode, String)> {
    let limit = normalize_limit(query.limit);
    let response = state
        .shared_clients
        .list_audit_logs(
            "platform-service",
            Some(request_id.0.as_str()),
            limit,
            query.cursor.unwrap_or_default(),
            query.action.unwrap_or_default(),
            query.consumer.unwrap_or_default(),
            query.user_id.unwrap_or_default(),
            query.from.unwrap_or_default(),
            query.to.unwrap_or_default(),
        )
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("logs grpc error: {err}")))?;

    Ok(AuditLogsListResponse {
        items: response
            .items
            .into_iter()
            .map(audit_log_item_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: if response.next_cursor.trim().is_empty() {
                None
            } else {
                Some(response.next_cursor)
            },
            has_more: response.has_more,
        },
        total: response.total,
    })
}

fn audit_log_item_response(record: AuditLogRecord) -> AuditLogItemResponse {
    let payload = match serde_json::from_str::<JsonValue>(&record.payload_json) {
        Ok(JsonValue::Object(map)) => JsonValue::Object(map),
        Ok(value) => serde_json::json!({ "value": value }),
        Err(_) => serde_json::json!({ "raw": record.payload_json }),
    };
    AuditLogItemResponse {
        event_id: record.event_id,
        user_id: record.user_id,
        action: record.action,
        consumer: record.consumer,
        created_at: record.created_at,
        payload,
    }
}

async fn load_audit_account_by_subject(
    state: &AppState,
    subject: &str,
) -> Result<Option<AuditAccountRecord>, (StatusCode, String)> {
    let user_id = Uuid::parse_str(subject.trim()).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "authenticated subject must be a valid UUID".to_string(),
        )
    })?;
    let row = sqlx::query(
        "SELECT user_id, expires_at, allowed_ips, is_active
         FROM control_app.audit_accounts
         WHERE user_id = $1
           AND role = 'auditor'
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?;

    row.map(|row| {
        Ok(AuditAccountRecord {
            user_id: row.get("user_id"),
            expires_at: row.get("expires_at"),
            allowed_ips: parse_allowed_ips_json(row.get::<Option<JsonValue>, _>("allowed_ips"))?,
            is_active: row.get("is_active"),
        })
    })
    .transpose()
}

fn masked_json_response<T: Serialize>(value: &T) -> Result<Response, (StatusCode, String)> {
    let mut json = serde_json::to_value(value).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialization error: {err}"),
        )
    })?;
    mask_json_value(&mut json, None);
    Ok(Json(json).into_response())
}

fn mask_json_value(value: &mut JsonValue, field_name: Option<&str>) {
    match value {
        JsonValue::Object(map) => {
            let keys = map.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                let normalized = key.trim().to_ascii_lowercase();
                if is_secret_field_name(&normalized) {
                    map.insert(key, JsonValue::String("[redacted]".to_string()));
                    continue;
                }
                if let Some(child) = map.get_mut(key.as_str()) {
                    mask_json_value(child, Some(&normalized));
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                mask_json_value(item, field_name);
            }
        }
        JsonValue::String(text) => {
            if field_name.is_some_and(is_email_field_name) || looks_like_email(text) {
                *text = mask_email(text);
            } else if field_name.is_some_and(is_phone_field_name) {
                *text = mask_phone(text);
            }
        }
        _ => {}
    }
}

fn is_secret_field_name(field_name: &str) -> bool {
    field_name == "password"
        || field_name == "password_hash"
        || field_name == "token"
        || field_name == "access_token"
        || field_name == "refresh_token"
        || field_name == "reset_token"
        || field_name == "secret"
        || field_name == "secret_plaintext"
        || field_name.ends_with("_token")
        || field_name.ends_with("_secret")
}

fn is_email_field_name(field_name: &str) -> bool {
    field_name == "email" || field_name.ends_with("_email")
}

fn is_phone_field_name(field_name: &str) -> bool {
    field_name == "phone" || field_name.ends_with("_phone") || field_name.contains("phone_")
}

fn looks_like_email(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.')
}

fn mask_email(value: &str) -> String {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "[redacted]".to_string();
    };
    let visible = local.chars().take(2).collect::<String>();
    let prefix = if visible.is_empty() {
        "*".to_string()
    } else {
        visible
    };
    format!("{prefix}***@{domain}")
}

fn mask_phone(value: &str) -> String {
    let digits = value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return "[redacted]".to_string();
    }
    let last4 = digits
        .iter()
        .rev()
        .take(4)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    if value.trim().starts_with("+1") || (digits.len() == 11 && digits.first() == Some(&'1')) {
        format!("+1 *** *** {last4}")
    } else if value.trim().starts_with('+') {
        let country = digits
            .iter()
            .take(digits.len().saturating_sub(10).max(1))
            .collect::<String>();
        format!("+{country} *** *** {last4}")
    } else {
        format!("*** *** {last4}")
    }
}

async fn consume_rate_limit(
    conn: &mut redis::aio::MultiplexedConnection,
    key: &str,
    limit: i64,
    window_seconds: i64,
) -> redis::RedisResult<bool> {
    let count = conn.incr::<_, _, i64>(key, 1).await?;
    if count == 1 {
        let _ = conn.expire::<_, bool>(key, window_seconds).await?;
    }
    Ok(count <= limit)
}

fn extract_request_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    for header in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers.get(header).and_then(|value| value.to_str().ok()) {
            if let Some(ip) = value
                .split(',')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Some(ip.to_string());
            }
        }
    }
    None
}

fn parse_allowed_ips_json(
    value: Option<JsonValue>,
) -> Result<Option<Vec<String>>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value.as_array().ok_or((
        StatusCode::BAD_GATEWAY,
        "audit_accounts.allowed_ips must be a JSON array".to_string(),
    ))?;
    let mut allowed = Vec::with_capacity(items.len());
    for item in items {
        let candidate = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or((
                StatusCode::BAD_GATEWAY,
                "audit_accounts.allowed_ips entries must be strings".to_string(),
            ))?;
        validate_allowed_ip_entry(candidate).map_err(|err| (StatusCode::BAD_GATEWAY, err))?;
        allowed.push(candidate.to_string());
    }
    Ok(if allowed.is_empty() {
        None
    } else {
        Some(allowed)
    })
}

fn validate_allowed_ip_entry(value: &str) -> Result<(), String> {
    if value.contains('/') {
        value
            .parse::<IpNet>()
            .map(|_| ())
            .map_err(|_| format!("invalid allowed_ips entry '{value}'"))
    } else {
        IpAddr::from_str(value)
            .map(|_| ())
            .map_err(|_| format!("invalid allowed_ips entry '{value}'"))
    }
}

fn ip_matches_any_allowed(ip: &str, allowed_ips: &[String]) -> bool {
    let Ok(request_ip) = IpAddr::from_str(ip.trim()) else {
        return false;
    };
    allowed_ips.iter().any(|candidate| {
        let candidate = candidate.trim();
        if candidate.contains('/') {
            candidate
                .parse::<IpNet>()
                .map(|network| network.contains(&request_ip))
                .unwrap_or(false)
        } else {
            IpAddr::from_str(candidate)
                .map(|allowed| allowed == request_ip)
                .unwrap_or(false)
        }
    })
}

fn header_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn action_suffix(path: &str) -> String {
    let mut normalized = String::new();
    let mut last_separator = false;
    for ch in path.trim_matches('/').chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_separator = false;
        } else if !last_separator {
            normalized.push('.');
            last_separator = true;
        }
    }
    let normalized = normalized.trim_matches('.').to_string();
    if normalized.is_empty() {
        "root".to_string()
    } else {
        normalized
    }
}

fn db_error(err: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_allowlist_matches_exact_and_cidr_entries() {
        let allowed = vec!["203.0.113.10".to_string(), "10.0.0.0/24".to_string()];
        assert!(ip_matches_any_allowed("203.0.113.10", &allowed));
        assert!(ip_matches_any_allowed("10.0.0.15", &allowed));
        assert!(!ip_matches_any_allowed("198.51.100.1", &allowed));
    }

    #[test]
    fn masking_redacts_sensitive_fields() {
        let mut value = serde_json::json!({
            "email": "john.doe@example.com",
            "phone": "+1 415 555 1234",
            "password_hash": "secret",
            "access_token": "abc",
            "profile": {
                "work_email": "ops@example.com",
                "contact_phone": "+1 650 555 7777"
            }
        });

        mask_json_value(&mut value, None);

        assert_eq!(
            value["email"],
            JsonValue::String("jo***@example.com".to_string())
        );
        assert_eq!(
            value["phone"],
            JsonValue::String("+1 *** *** 1234".to_string())
        );
        assert_eq!(
            value["password_hash"],
            JsonValue::String("[redacted]".to_string())
        );
        assert_eq!(
            value["access_token"],
            JsonValue::String("[redacted]".to_string())
        );
        assert_eq!(
            value["profile"]["work_email"],
            JsonValue::String("op***@example.com".to_string())
        );
    }
}
