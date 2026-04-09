use crate::state::AppState;
use axum::{routing::get, Router};

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new().route("/dashboard/summary", get(handlers::get_dashboard_summary))
}
