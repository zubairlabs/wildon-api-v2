use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

const INCIDENT_SELECT: &str = "
    SELECT
        i.id::text, i.display_ref, i.member_id::text, i.device_id::text,
        i.owner_id::text, i.incident_type, i.status, i.severity,
        i.latitude, i.longitude,
        i.contacts_snapshot, i.telemetry_snapshot,
        i.acknowledged_by::text,
        EXTRACT(EPOCH FROM i.acknowledged_at)::BIGINT AS acknowledged_at,
        i.resolved_by::text,
        EXTRACT(EPOCH FROM i.resolved_at)::BIGINT AS resolved_at,
        i.resolution_notes,
        i.assigned_to::text,
        EXTRACT(EPOCH FROM i.assigned_at)::BIGINT AS assigned_at,
        EXTRACT(EPOCH FROM i.triggered_at)::BIGINT AS triggered_at,
        EXTRACT(EPOCH FROM (NOW() - i.triggered_at))::BIGINT AS time_since_trigger,
        CASE WHEN i.acknowledged_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (i.acknowledged_at - i.triggered_at))::BIGINT
             ELSE NULL END AS acknowledged_within_secs,
        CASE WHEN i.resolved_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (i.resolved_at - i.triggered_at))::BIGINT
             ELSE NULL END AS resolved_within_secs,
        m.name AS member_name,
        d.name AS device_name
    FROM care_app.emergency_incidents i
    LEFT JOIN care_app.members m ON m.id = i.member_id
    LEFT JOIN care_app.devices d ON d.id = i.device_id
";

fn get_db(state: &AppState) -> &sqlx::PgPool {
    &state.db
}

/// Extract support user ID from `x-support-user-id` header, falling back to nil UUID.
fn extract_support_user(headers: &HeaderMap) -> Uuid {
    headers
        .get("x-support-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<Uuid>().ok())
        .unwrap_or(Uuid::nil())
}

fn row_to_json(r: &sqlx::postgres::PgRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.get::<String, _>("id"),
        "display_ref": r.get::<String, _>("display_ref"),
        "member_id": r.get::<String, _>("member_id"),
        "device_id": r.get::<String, _>("device_id"),
        "owner_id": r.get::<String, _>("owner_id"),
        "incident_type": r.get::<String, _>("incident_type"),
        "status": r.get::<String, _>("status"),
        "severity": r.get::<String, _>("severity"),
        "latitude": r.get::<Option<f64>, _>("latitude"),
        "longitude": r.get::<Option<f64>, _>("longitude"),
        "contacts_snapshot": r.get::<serde_json::Value, _>("contacts_snapshot"),
        "telemetry_snapshot": r.get::<Option<serde_json::Value>, _>("telemetry_snapshot"),
        "acknowledged_by": r.get::<Option<String>, _>("acknowledged_by"),
        "acknowledged_at": r.get::<Option<i64>, _>("acknowledged_at"),
        "resolved_by": r.get::<Option<String>, _>("resolved_by"),
        "resolved_at": r.get::<Option<i64>, _>("resolved_at"),
        "resolution_notes": r.get::<Option<String>, _>("resolution_notes"),
        "assigned_to": r.get::<Option<String>, _>("assigned_to"),
        "assigned_at": r.get::<Option<i64>, _>("assigned_at"),
        "triggered_at": r.get::<i64, _>("triggered_at"),
        "time_since_trigger": r.get::<i64, _>("time_since_trigger"),
        "acknowledged_within_secs": r.get::<Option<i64>, _>("acknowledged_within_secs"),
        "resolved_within_secs": r.get::<Option<i64>, _>("resolved_within_secs"),
        "member_name": r.get::<Option<String>, _>("member_name"),
        "device_name": r.get::<Option<String>, _>("device_name"),
    })
}

#[derive(Debug, Deserialize)]
pub struct IncidentListQuery {
    pub status: Option<String>,
    pub incident_type: Option<String>,
    pub severity: Option<String>,
    pub member_id: Option<String>,
    pub device_id: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    // Health cross-filters
    pub condition: Option<String>,
    pub allergy: Option<String>,
    pub medication: Option<String>,
}

pub async fn list_incidents(
    State(state): State<AppState>,
    Query(query): Query<IncidentListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);

    let limit = query.limit.unwrap_or(50).min(200).max(1) as i64;
    let fetch_limit = limit + 1;

    let status = query.status.filter(|s| !s.is_empty());
    let incident_type = query.incident_type.filter(|s| !s.is_empty());
    let severity = query.severity.filter(|s| !s.is_empty());
    let member_uuid: Option<Uuid> = query
        .member_id
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "bad member_id".to_string()))
        })
        .transpose()?;
    let device_uuid: Option<Uuid> = query
        .device_id
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "bad device_id".to_string()))
        })
        .transpose()?;
    let from_ts = query
        .from
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));
    let to_ts = query
        .to
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));
    let cursor_ts = query
        .cursor
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<i64>()
                .map_err(|_| (StatusCode::BAD_REQUEST, "bad cursor".to_string()))
        })
        .transpose()?
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    let use_priority_sort = status.as_deref() == Some("ACTIVE");

    let condition = query.condition.filter(|s| !s.is_empty());
    let allergy = query.allergy.filter(|s| !s.is_empty());
    let medication = query.medication.filter(|s| !s.is_empty());
    let has_health_filter = condition.is_some() || allergy.is_some() || medication.is_some();

    let health_join = if has_health_filter {
        "LEFT JOIN care_app.member_search_index msi ON msi.member_id = i.member_id"
    } else {
        ""
    };
    let health_where = if has_health_filter {
        "AND ($10::text IS NULL OR msi.conditions_text ILIKE '%' || $10 || '%')
         AND ($11::text IS NULL OR msi.allergies_text ILIKE '%' || $11 || '%')
         AND ($12::text IS NULL OR msi.medications_text ILIKE '%' || $12 || '%')"
    } else {
        "AND ($10::text IS NULL) AND ($11::text IS NULL) AND ($12::text IS NULL)"
    };

    let order = if use_priority_sort {
        "ORDER BY CASE i.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END, i.triggered_at ASC"
    } else {
        "ORDER BY i.triggered_at DESC"
    };

    let sql = format!(
        "{INCIDENT_SELECT}
         {health_join}
         WHERE i.deleted_at IS NULL
           AND ($1::text IS NULL OR i.status = $1)
           AND ($2::text IS NULL OR i.incident_type = $2)
           AND ($3::text IS NULL OR i.severity = $3)
           AND ($4::uuid IS NULL OR i.member_id = $4)
           AND ($5::uuid IS NULL OR i.device_id = $5)
           AND ($6::timestamptz IS NULL OR i.triggered_at >= $6)
           AND ($7::timestamptz IS NULL OR i.triggered_at <= $7)
           AND ($8::timestamptz IS NULL OR i.triggered_at < $8)
           {health_where}
         {order}
         LIMIT $9"
    );

    let rows = sqlx::query(&sql)
        .bind(status.as_deref())
        .bind(incident_type.as_deref())
        .bind(severity.as_deref())
        .bind(member_uuid)
        .bind(device_uuid)
        .bind(from_ts)
        .bind(to_ts)
        .bind(cursor_ts)
        .bind(fetch_limit)
        .bind(condition.as_deref())
        .bind(allergy.as_deref())
        .bind(medication.as_deref())
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let items: Vec<serde_json::Value> = rows.iter().take(limit as usize).map(row_to_json).collect();

    let next_cursor = if has_more {
        items
            .last()
            .and_then(|i| i.get("triggered_at"))
            .and_then(|v| v.as_i64())
            .map(|ts| ts.to_string())
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "items": items,
        "pagination": { "limit": limit, "next_cursor": next_cursor, "has_more": has_more }
    })))
}

pub async fn get_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);
    let incident_uuid: Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad id".to_string()))?;

    let row = sqlx::query(&format!(
        "{INCIDENT_SELECT} WHERE i.id = $1 AND i.deleted_at IS NULL"
    ))
    .bind(incident_uuid)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "incident not found".to_string()))?;

    Ok(Json(row_to_json(&row)))
}

pub async fn acknowledge_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);
    let incident_uuid: Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad id".to_string()))?;
    let support_user = extract_support_user(&headers);

    let result = sqlx::query(
        "UPDATE care_app.emergency_incidents
         SET status = 'ACKNOWLEDGED', acknowledged_by = $2, acknowledged_at = NOW(), updated_at = NOW()
         WHERE id = $1 AND status = 'ACTIVE' AND deleted_at IS NULL",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::CONFLICT,
            "incident not found or not ACTIVE".to_string(),
        ));
    }

    let _ = sqlx::query(
        "INSERT INTO care_app.incident_timeline (incident_id, event_type, actor_id, actor_type, description)
         VALUES ($1, 'ACKNOWLEDGED', $2, 'USER', 'Acknowledged by support')",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .execute(db)
    .await;

    let after = serde_json::json!({
        "incident_id": id,
        "status": "ACKNOWLEDGED",
        "support_user": support_user.to_string(),
    });
    state
        .shared_clients
        .audit_log(
            &support_user.to_string(),
            "incident.acknowledged",
            "emergency_incident",
            &id,
            None,
            Some(&after.to_string()),
        )
        .await;

    Ok(Json(
        serde_json::json!({ "id": id, "status": "ACKNOWLEDGED" }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ResolveBody {
    #[serde(default)]
    pub resolution_notes: String,
}

pub async fn resolve_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ResolveBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);
    let incident_uuid: Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad id".to_string()))?;
    let support_user = extract_support_user(&headers);

    let result = sqlx::query(
        "UPDATE care_app.emergency_incidents
         SET status = 'RESOLVED', resolved_by = $2, resolved_at = NOW(),
             resolution_notes = $3, updated_at = NOW()
         WHERE id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED') AND deleted_at IS NULL",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .bind(body.resolution_notes.trim())
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::CONFLICT,
            "incident not found or already resolved".to_string(),
        ));
    }

    let _ = sqlx::query(
        "INSERT INTO care_app.incident_timeline (incident_id, event_type, actor_id, actor_type, description, metadata)
         VALUES ($1, 'RESOLVED', $2, 'USER', 'Resolved by support', $3)",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .bind(serde_json::json!({ "resolution_notes": body.resolution_notes.trim() }))
    .execute(db)
    .await;

    let after = serde_json::json!({
        "incident_id": id,
        "status": "RESOLVED",
        "support_user": support_user.to_string(),
        "resolution_notes": body.resolution_notes.trim(),
    });
    state
        .shared_clients
        .audit_log(
            &support_user.to_string(),
            "incident.resolved",
            "emergency_incident",
            &id,
            None,
            Some(&after.to_string()),
        )
        .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "RESOLVED" })))
}

pub async fn assign_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);
    let incident_uuid: Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad id".to_string()))?;
    let support_user = extract_support_user(&headers);

    let result = sqlx::query(
        "UPDATE care_app.emergency_incidents
         SET assigned_to = $2, assigned_at = NOW(), updated_at = NOW()
         WHERE id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED') AND deleted_at IS NULL
           AND (assigned_to IS NULL OR assigned_to = $2)",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::CONFLICT,
            "incident not found, resolved, or already assigned".to_string(),
        ));
    }

    let _ = sqlx::query(
        "INSERT INTO care_app.incident_timeline (incident_id, event_type, actor_id, actor_type, description)
         VALUES ($1, 'ASSIGNED', $2, 'USER', 'Assigned to support agent')",
    )
    .bind(incident_uuid)
    .bind(support_user)
    .execute(db)
    .await;

    let after = serde_json::json!({
        "incident_id": id,
        "assigned_to": support_user.to_string(),
    });
    state
        .shared_clients
        .audit_log(
            &support_user.to_string(),
            "incident.assigned",
            "emergency_incident",
            &id,
            None,
            Some(&after.to_string()),
        )
        .await;

    Ok(Json(
        serde_json::json!({ "id": id, "assigned_to": support_user.to_string() }),
    ))
}

pub async fn list_incident_timeline(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = get_db(&state);
    let incident_uuid: Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad id".to_string()))?;

    let rows = sqlx::query(
        "SELECT id::text, event_type, actor_id::text, actor_type, description, metadata,
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at
         FROM care_app.incident_timeline
         WHERE incident_id = $1
         ORDER BY created_at ASC",
    )
    .bind(incident_uuid)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<String, _>("id"),
                "event_type": r.get::<String, _>("event_type"),
                "actor_id": r.get::<Option<String>, _>("actor_id"),
                "actor_type": r.get::<String, _>("actor_type"),
                "description": r.get::<String, _>("description"),
                "metadata": r.get::<Option<serde_json::Value>, _>("metadata"),
                "created_at": r.get::<i64, _>("created_at"),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "entries": entries })))
}
