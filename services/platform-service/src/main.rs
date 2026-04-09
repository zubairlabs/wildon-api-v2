#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::state::AppState;
use config::grpc::connect_channel;
use observability::init_tracing;
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    init_tracing("platform-service");

    let bind_addr = env::var("PLATFORM_HTTP_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8083".to_string())
        .parse::<SocketAddr>()
        .expect("invalid PLATFORM_HTTP_BIND_ADDR");

    let core_endpoint =
        env::var("CORE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50053".to_string());
    let core_channel = connect_channel(&core_endpoint, "core-service")
        .await
        .expect("failed to connect core grpc endpoint");
    let core_client =
        contracts::wildon::core::v1::core_service_client::CoreServiceClient::new(core_channel);

    let logs_endpoint =
        env::var("LOGS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50054".to_string());
    let logs_channel = connect_channel(&logs_endpoint, "logs-service")
        .await
        .expect("failed to connect logs grpc endpoint");
    let logs_client =
        contracts::wildon::logs::v1::logs_service_client::LogsServiceClient::new(logs_channel);

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let database_max_connections = env::var("PLATFORM_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    let expected_issuer = env::var("JWT_EXPECTED_ISSUER")
        .unwrap_or_else(|_| "https://auth.wildon.local".to_string());
    let db = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .connect(&database_url)
        .await
        .expect("failed to connect platform-service db");
    tracing::info!("platform-service database connected");
    let redis = env::var("REDIS_URL")
        .ok()
        .and_then(|url| redis::Client::open(url).ok());

    let state = AppState::new(core_client, logs_client, db, expected_issuer, redis);
    let app = routes::router(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind platform listener");
    tracing::info!(address = %bind_addr, "platform http listening");
    axum::serve(listener, app)
        .await
        .expect("platform http server failed");
}
