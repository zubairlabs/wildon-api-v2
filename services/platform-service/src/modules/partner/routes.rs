use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard/summary", get(handlers::get_dashboard_summary))
        .route("/reporting/summary", get(handlers::get_reporting_summary))
        .route(
            "/settings",
            get(handlers::get_settings).put(handlers::update_settings),
        )
        .route("/tickets", post(handlers::create_ticket))
        .route(
            "/tickets/:ticket_id",
            get(handlers::get_ticket).post(handlers::add_reply),
        )
}
