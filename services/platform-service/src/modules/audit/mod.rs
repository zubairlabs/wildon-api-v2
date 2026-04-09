pub mod handlers;
pub mod routes;

use crate::state::AppState;
use axum::Router;

pub fn router(state: AppState) -> Router<AppState> {
    routes::router(state)
}
