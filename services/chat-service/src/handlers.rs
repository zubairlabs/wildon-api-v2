use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;

use crate::{queue, state::AppState};

// ──────────────────────────────────────────────
// GET /v1/chat/sessions
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListSessionsQuery {
    pub status: Option<String>,
    pub user_id: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub user_id: String,
    pub user_name: Option<String>,
    pub status: String,
    pub queue_position: Option<i32>,
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub ticket_id: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListSessionsResponse {
    pub sessions: Vec<SessionSummary>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, String)> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * limit) as i64;

    let rows = sqlx::query(
        r#"
        SELECT session_id, user_id, user_name, status, queue_position,
               agent_id, agent_name, ticket_id, created_at, started_at, ended_at
        FROM control_app.live_chat_sessions
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR user_id = $2)
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(query.status.clone())
    .bind(query.user_id.clone())
    .bind(limit as i64)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_row = sqlx::query(
        "SELECT COUNT(*) AS count FROM control_app.live_chat_sessions WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR user_id = $2)",
    )
    .bind(query.status)
    .bind(query.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let sessions = rows
        .into_iter()
        .map(|r| SessionSummary {
            session_id: r.get("session_id"),
            user_id: r.get("user_id"),
            user_name: r.get("user_name"),
            status: r.get("status"),
            queue_position: r.get("queue_position"),
            agent_id: r.get("agent_id"),
            agent_name: r.get("agent_name"),
            ticket_id: r.get("ticket_id"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").timestamp(),
            started_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at").map(|t| t.timestamp()),
            ended_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("ended_at").map(|t| t.timestamp()),
        })
        .collect();

    let total: i64 = total_row.get("count");

    Ok(Json(ListSessionsResponse {
        sessions,
        total,
        page,
        limit,
    }))
}

// ──────────────────────────────────────────────
// GET /v1/chat/sessions/:id
// ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ChatMessage {
    pub id: String,
    pub sender_id: String,
    pub sender_type: String,
    pub content: String,
    pub sent_at: i64,
}

#[derive(Debug, Serialize)]
pub struct SessionDetailResponse {
    pub session_id: String,
    pub user_id: String,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub status: String,
    pub queue_position: Option<i32>,
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub ticket_id: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub messages: Vec<ChatMessage>,
}

pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionDetailResponse>, (StatusCode, String)> {
    let session = sqlx::query(
        r#"
        SELECT session_id, user_id, user_name, user_email, status,
               queue_position, agent_id, agent_name, ticket_id,
               created_at, started_at, ended_at
        FROM control_app.live_chat_sessions
        WHERE session_id = $1
        "#,
    )
    .bind(session_id.clone())
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "session not found".to_string()))?;

    let messages = sqlx::query(
        "SELECT id, sender_id, sender_type, content, sent_at FROM control_app.live_chat_messages WHERE session_id = $1 ORDER BY sent_at ASC",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SessionDetailResponse {
        session_id: session.get("session_id"),
        user_id: session.get("user_id"),
        user_name: session.get("user_name"),
        user_email: session.get("user_email"),
        status: session.get("status"),
        queue_position: session.get("queue_position"),
        agent_id: session.get("agent_id"),
        agent_name: session.get("agent_name"),
        ticket_id: session.get("ticket_id"),
        created_at: session.get::<chrono::DateTime<chrono::Utc>, _>("created_at").timestamp(),
        started_at: session.get::<Option<chrono::DateTime<chrono::Utc>>, _>("started_at").map(|t| t.timestamp()),
        ended_at: session.get::<Option<chrono::DateTime<chrono::Utc>>, _>("ended_at").map(|t| t.timestamp()),
        messages: messages
            .into_iter()
            .map(|m| ChatMessage {
                id: m.get::<uuid::Uuid, _>("id").to_string(),
                sender_id: m.get("sender_id"),
                sender_type: m.get("sender_type"),
                content: m.get("content"),
                sent_at: m.get::<chrono::DateTime<chrono::Utc>, _>("sent_at").timestamp(),
            })
            .collect(),
    }))
}

// ──────────────────────────────────────────────
// GET /health
// ──────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

// ──────────────────────────────────────────────
// GET /v1/chat/queue
// ──────────────────────────────────────────────

pub async fn get_queue(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<crate::messages::QueueEntry>> {
    Json(queue::get_waiting_queue(&state.db).await)
}
