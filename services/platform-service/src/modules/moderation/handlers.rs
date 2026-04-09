use axum::{extract::State, Json};

use crate::state::AppState;

use super::dashboard::{self, ModerationDashboardResponse};

pub async fn get_dashboard_summary(
    State(_state): State<AppState>,
) -> Json<ModerationDashboardResponse> {
    Json(dashboard::summarize())
}
