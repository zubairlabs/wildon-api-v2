use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use sqlx::Row;
use uuid::Uuid;

use crate::state::AppState;

use super::{
    dashboard,
    models::{
        AddReplyRequest, CreateTicketRequest, PartnerDashboardResponse,
        PartnerReportingSummaryResponse, PartnerSettingsResponse, ReplyResponse, TicketResponse,
        UpdatePartnerSettingsRequest,
    },
    reporting, settings,
};

const SOURCE: &str = "partner";

pub async fn get_dashboard_summary(
    State(state): State<AppState>,
) -> Result<Json<PartnerDashboardResponse>, (StatusCode, String)> {
    dashboard::summarize(&state.db, SOURCE).await
}

pub async fn get_reporting_summary(
    State(state): State<AppState>,
) -> Result<Json<PartnerReportingSummaryResponse>, (StatusCode, String)> {
    reporting::summarize(&state.db, SOURCE).await
}

pub async fn get_settings(
    State(state): State<AppState>,
) -> Result<Json<PartnerSettingsResponse>, (StatusCode, String)> {
    settings::get_settings(&state.db).await
}

pub async fn update_settings(
    State(state): State<AppState>,
    Json(payload): Json<UpdatePartnerSettingsRequest>,
) -> Result<Json<PartnerSettingsResponse>, (StatusCode, String)> {
    if payload.alert_email.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "alert_email is required".to_string(),
        ));
    }

    let before = settings::get_settings(&state.db).await?;
    let response = settings::apply_update(&state.db, &payload).await?;

    let before_json = serde_json::to_string(&before.0).unwrap_or_default();
    let after_json = serde_json::to_string(&response.0).unwrap_or_default();
    state
        .shared_clients
        .audit_log(
            "system",
            "partner.settings.updated",
            "partner_settings",
            "default",
            Some(&before_json),
            Some(&after_json),
        )
        .await;

    Ok(response)
}

pub async fn create_ticket(
    State(state): State<AppState>,
    Json(payload): Json<CreateTicketRequest>,
) -> Result<Json<TicketResponse>, (StatusCode, String)> {
    if payload.user_id.trim().is_empty()
        || payload.subject.trim().is_empty()
        || payload.message.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "user_id, subject, and message are required".to_string(),
        ));
    }

    let ticket_id = Uuid::new_v4().to_string();
    let status = "open";

    let row = sqlx::query(
        "INSERT INTO platform_app.support_tickets
            (ticket_id, user_id, subject, message, status, source, contact_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING ticket_id, user_id, subject, message, status, contact_email,
                   EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
                   EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at",
    )
    .bind(&ticket_id)
    .bind(&payload.user_id)
    .bind(&payload.subject)
    .bind(&payload.message)
    .bind(status)
    .bind(SOURCE)
    .bind(&payload.contact_email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    state
        .shared_clients
        .dispatch_ticket_follow_up(
            "platform-service",
            SOURCE,
            &payload.user_id,
            &payload.contact_email,
            &payload.subject,
            &ticket_id,
        )
        .await;

    let after = serde_json::json!({
        "ticket_id": &ticket_id,
        "user_id": &payload.user_id,
        "subject": &payload.subject,
        "source": SOURCE,
    });
    state
        .shared_clients
        .audit_log(
            &payload.user_id,
            "partner.ticket.created",
            "support_ticket",
            &ticket_id,
            None,
            Some(&after.to_string()),
        )
        .await;

    Ok(Json(row_to_ticket_response(&row, vec![])))
}

pub async fn get_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
) -> Result<Json<TicketResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT ticket_id, user_id, subject, message, status,
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at
         FROM platform_app.support_tickets
         WHERE ticket_id = $1 AND source = $2",
    )
    .bind(&ticket_id)
    .bind(SOURCE)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "ticket not found".to_string()))?;

    let replies = fetch_replies(&state.db, &ticket_id).await?;
    Ok(Json(row_to_ticket_response(&row, replies)))
}

pub async fn add_reply(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Json(payload): Json<AddReplyRequest>,
) -> Result<Json<TicketResponse>, (StatusCode, String)> {
    if payload.author.trim().is_empty() || payload.message.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "author and message are required".to_string(),
        ));
    }

    let reply_id = Uuid::new_v4().to_string();

    let ticket_exists = sqlx::query(
        "SELECT ticket_id FROM platform_app.support_tickets WHERE ticket_id = $1 AND source = $2",
    )
    .bind(&ticket_id)
    .bind(SOURCE)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if ticket_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "ticket not found".to_string()));
    }

    sqlx::query(
        "INSERT INTO platform_app.support_ticket_replies (reply_id, ticket_id, author, message)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&reply_id)
    .bind(&ticket_id)
    .bind(&payload.author)
    .bind(&payload.message)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    sqlx::query(
        "UPDATE platform_app.support_tickets SET status = 'responded', updated_at = NOW()
         WHERE ticket_id = $1",
    )
    .bind(&ticket_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let after = serde_json::json!({
        "reply_id": &reply_id,
        "ticket_id": &ticket_id,
        "author": &payload.author,
        "source": SOURCE,
    });
    state
        .shared_clients
        .audit_log(
            &payload.author,
            "partner.ticket.replied",
            "support_ticket",
            &ticket_id,
            None,
            Some(&after.to_string()),
        )
        .await;

    let row = sqlx::query(
        "SELECT ticket_id, user_id, subject, message, status,
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at
         FROM platform_app.support_tickets
         WHERE ticket_id = $1",
    )
    .bind(&ticket_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let replies = fetch_replies(&state.db, &ticket_id).await?;
    Ok(Json(row_to_ticket_response(&row, replies)))
}

async fn fetch_replies(
    db: &sqlx::PgPool,
    ticket_id: &str,
) -> Result<Vec<ReplyResponse>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT author, message, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at
         FROM platform_app.support_ticket_replies
         WHERE ticket_id = $1
         ORDER BY created_at ASC",
    )
    .bind(ticket_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(rows
        .iter()
        .map(|r| ReplyResponse {
            author: r.get("author"),
            message: r.get("message"),
            created_at: r.get("created_at"),
        })
        .collect())
}

fn row_to_ticket_response(
    row: &sqlx::postgres::PgRow,
    replies: Vec<ReplyResponse>,
) -> TicketResponse {
    TicketResponse {
        ticket_id: row.get("ticket_id"),
        user_id: row.get("user_id"),
        subject: row.get("subject"),
        message: row.get("message"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        replies,
    }
}
