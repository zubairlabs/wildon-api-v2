mod events;
mod handlers;
mod messages;
mod queue;
mod state;
mod ws;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    http::header::CONTENT_TYPE,
    response::Html,
    routing::get,
    Router,
};
use tokio::net::TcpListener;

use state::AppState;

const CHAT_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/chat-v1.json");

#[tokio::main]
async fn main() {
    observability::init_tracing("chat-service");

    let bind_addr = std::env::var("CHAT_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8082".to_string())
        .parse::<SocketAddr>()
        .expect("invalid CHAT_BIND_ADDR");

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let queue_timeout_mins: u64 = std::env::var("CHAT_QUEUE_TIMEOUT_MINS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    // Database
    let db = sqlx::PgPool::connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to connect to database");
            std::process::exit(1);
        });
    tracing::info!("connected to database");

    // NATS
    let nats = async_nats::connect(&nats_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, url = %nats_url, "failed to connect to NATS");
            std::process::exit(1);
        });
    tracing::info!(url = %nats_url, "connected to NATS");

    let state = Arc::new(AppState::new(db, nats, queue_timeout_mins));

    // Subscribe to NATS subjects for cross-replica message delivery
    events::spawn_nats_subscriber(Arc::clone(&state)).await;

    // Background task: auto-close timed-out waiting sessions
    let timeout_state = Arc::clone(&state);
    tokio::spawn(queue::run_queue_timeout_task(timeout_state));

    let app = build_router(Arc::clone(&state));

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind chat-service listener");
    tracing::info!(address = %bind_addr, "chat-service listening");

    axum::serve(listener, app)
        .await
        .expect("chat-service server failed");
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // WebSocket endpoint
        .route("/ws/chat", get(ws::ws_handler))
        // REST endpoints
        .route("/health", get(handlers::health))
        .route("/v1/chat/sessions", get(handlers::list_sessions))
        .route("/v1/chat/sessions/:id", get(handlers::get_session))
        .route("/v1/chat/queue", get(handlers::get_queue))
        // Docs
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/openapi/chat-v1.json", get(openapi_spec))
        .with_state(state)
}

async fn swagger_ui() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Wildon Chat API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/openapi/chat-v1.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
      });
    </script>
  </body>
</html>"##,
    )
}

async fn openapi_spec() -> impl axum::response::IntoResponse {
    ([(CONTENT_TYPE, "application/json; charset=utf-8")], CHAT_OPENAPI_JSON)
}
