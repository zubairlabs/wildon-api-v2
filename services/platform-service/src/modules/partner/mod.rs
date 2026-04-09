pub mod dashboard;
pub mod handlers;
pub mod models;
pub mod reporting;
pub mod routes;
pub mod settings;

use crate::state::AppState;
use axum::Router;

pub fn router() -> Router<AppState> {
    routes::router()
}
