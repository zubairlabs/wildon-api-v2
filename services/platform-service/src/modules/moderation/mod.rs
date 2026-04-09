pub mod dashboard;
pub mod handlers;
pub mod routes;

use crate::state::AppState;
use axum::Router;

pub fn router() -> Router<AppState> {
    routes::router()
}
