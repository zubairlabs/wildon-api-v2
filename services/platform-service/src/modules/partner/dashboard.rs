use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use sqlx::{PgPool, Row};

use super::models::PartnerDashboardResponse;

pub async fn summarize(
    db: &PgPool,
    source: &str,
) -> Result<Json<PartnerDashboardResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'open') AS open_count,
            COUNT(*) FILTER (WHERE status = 'closed') AS closed_count
         FROM platform_app.support_tickets
         WHERE source = $1",
    )
    .bind(source)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(Json(PartnerDashboardResponse {
        total_tickets: row.get::<i64, _>("total") as u64,
        open_tickets: row.get::<i64, _>("open_count") as u64,
        closed_tickets: row.get::<i64, _>("closed_count") as u64,
        flagged_content_count: 0,
        partner_alerts_count: 0,
        generated_at: Utc::now().timestamp(),
    }))
}
