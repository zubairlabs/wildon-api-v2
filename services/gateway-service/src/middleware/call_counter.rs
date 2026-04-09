use crate::state::AppState;
use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use std::time::Instant;

/// Axum middleware that records API call metrics (count, method, service, latency, status).
pub async fn record_call(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().to_string();

    // Read ServiceName extension if set by route group, else derive from path.
    let service = req
        .extensions()
        .get::<ServiceName>()
        .map(|s| s.0.to_string())
        .unwrap_or_else(|| service_from_path(req.uri().path()));

    let start = Instant::now();
    let resp = next.run(req).await;
    let latency_us = start.elapsed().as_micros() as u32;
    let status = resp.status().as_u16();

    state.api_metrics.record(&method, &service, status, latency_us).await;

    resp
}

/// Tag attached to each route group so the middleware can identify it without URL parsing.
#[derive(Clone, Debug)]
pub struct ServiceName(pub &'static str);

/// Fallback: derive service name from the first meaningful path segment.
fn service_from_path(path: &str) -> String {
    // e.g. "/v1/auth/login" → "auth"
    //      "/v1/users/123"  → "users"
    let segments: Vec<&str> = path.trim_start_matches('/').splitn(4, '/').collect();
    // segments[0] = "v1", segments[1] = service name
    segments.get(1).copied().unwrap_or("unknown").to_string()
}
