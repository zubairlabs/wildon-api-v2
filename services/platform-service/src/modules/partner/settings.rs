use axum::http::StatusCode;
use axum::Json;
use sqlx::{PgPool, Row};

use super::models::{PartnerSettingsResponse, UpdatePartnerSettingsRequest};

pub async fn get_settings(
    db: &PgPool,
) -> Result<Json<PartnerSettingsResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT notifications_enabled, alert_email
         FROM platform_app.partner_settings
         WHERE key = 'default'",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    match row {
        Some(r) => Ok(Json(PartnerSettingsResponse {
            notifications_enabled: r.get("notifications_enabled"),
            alert_email: r.get("alert_email"),
        })),
        None => Ok(Json(PartnerSettingsResponse {
            notifications_enabled: true,
            alert_email: "support@wildon.local".to_string(),
        })),
    }
}

pub async fn apply_update(
    db: &PgPool,
    update: &UpdatePartnerSettingsRequest,
) -> Result<Json<PartnerSettingsResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        "INSERT INTO platform_app.partner_settings (key, notifications_enabled, alert_email, updated_at)
         VALUES ('default', $1, $2, NOW())
         ON CONFLICT (key) DO UPDATE
            SET notifications_enabled = EXCLUDED.notifications_enabled,
                alert_email = EXCLUDED.alert_email,
                updated_at = NOW()
         RETURNING notifications_enabled, alert_email",
    )
    .bind(update.notifications_enabled)
    .bind(&update.alert_email)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(Json(PartnerSettingsResponse {
        notifications_enabled: row.get("notifications_enabled"),
        alert_email: row.get("alert_email"),
    }))
}
