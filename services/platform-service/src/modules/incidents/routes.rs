use crate::state::AppState;
use axum::{
    routing::{get, patch},
    Router,
};

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::list_incidents))
        .route("/:id", get(handlers::get_incident))
        .route("/:id/acknowledge", patch(handlers::acknowledge_incident))
        .route("/:id/resolve", patch(handlers::resolve_incident))
        .route("/:id/assign", patch(handlers::assign_incident))
        .route("/:id/timeline", get(handlers::list_incident_timeline))
}
