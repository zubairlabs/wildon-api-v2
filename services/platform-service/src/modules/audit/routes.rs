use crate::state::AppState;
use axum::{routing::get, Router};

use super::handlers;

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/users", get(handlers::list_users))
        .route("/members", get(handlers::list_members))
        .route("/devices", get(handlers::list_devices))
        .route("/logs", get(handlers::list_logs))
        .route("/trail", get(handlers::list_trail))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::rate_limit_auditor_requests,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::enforce_auditor_auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state,
            handlers::audit_auditor_requests,
        ))
        .layer(axum::middleware::from_fn(::middleware::inject_request_id))
}
