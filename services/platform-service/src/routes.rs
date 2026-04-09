use crate::{
    modules::{audit, incidents, moderation, partner, support},
    state::AppState,
};
use auth::jwt;
use axum::{
    body::Body,
    http::header::AUTHORIZATION,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;

const PLATFORM_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/platform-v1.json");

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/openapi/platform-v1.json", get(openapi_platform))
        .route("/health", get(health))
        .nest("/v1/audit", audit::router(state.clone()))
        .nest("/v1/partner", partner::router())
        .nest("/v1/support", support::router())
        .nest("/v1/moderation", moderation::router())
        .nest(
            "/v1/incidents",
            incidents::routes::router().layer(axum::middleware::from_fn(enforce_platform_auth)),
        )
        .layer(axum::middleware::from_fn(deny_auditor_outside_audit))
        .with_state(state)
}

async fn swagger_ui() -> axum::response::Html<&'static str> {
    axum::response::Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Wildon Platform API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/openapi/platform-v1.json",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    </script>
  </body>
</html>"##,
    )
}

async fn openapi_platform() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        PLATFORM_OPENAPI_JSON,
    )
}

async fn enforce_platform_auth(request: Request<Body>, next: Next) -> Response {
    let expected = std::env::var("PLATFORM_API_KEY").unwrap_or_default();
    if expected.is_empty() {
        return next.run(request).await;
    }
    let provided = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if provided != expected {
        return (StatusCode::UNAUTHORIZED, "invalid api key").into_response();
    }
    next.run(request).await
}

async fn deny_auditor_outside_audit(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/docs" | "/docs/" | "/openapi/platform-v1.json"
    ) || path.starts_with("/v1/audit/")
    {
        return next.run(request).await;
    }

    let Some(header_value) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return next.run(request).await;
    };
    let Ok(claims) = jwt::parse_bearer_header(header_value) else {
        return next.run(request).await;
    };
    if claims.roles.iter().any(|role| role == "auditor") {
        return (
            StatusCode::FORBIDDEN,
            "auditor access is restricted to /v1/audit routes",
        )
            .into_response();
    }

    next.run(request).await
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
