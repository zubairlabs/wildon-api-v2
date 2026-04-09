use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use sqlx::{PgPool, Row};

use super::models::PartnerReportingSummaryResponse;

pub async fn summarize(
    db: &PgPool,
    source: &str,
) -> Result<Json<PartnerReportingSummaryResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'responded') AS responded_count
         FROM platform_app.support_tickets
         WHERE source = $1",
    )
    .bind(source)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let total = row.get::<i64, _>("total") as u64;
    let responded = row.get::<i64, _>("responded_count") as u64;

    Ok(Json(PartnerReportingSummaryResponse {
        total_tickets: total,
        responded_tickets: responded,
        outstanding_tickets: total.saturating_sub(responded),
        generated_at: Utc::now().timestamp(),
    }))
}
