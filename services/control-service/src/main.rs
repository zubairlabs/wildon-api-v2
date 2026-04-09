#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::state::AppState;
use config::grpc::connect_channel;
use ::middleware as shared_middleware;
use observability::init_tracing;
use sqlx::postgres::PgPoolOptions;
use std::{collections::HashSet, env, net::SocketAddr};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;

#[tokio::main]
async fn main() {
    init_tracing("control-service");

    let bind_addr = env::var("CONTROL_HTTP_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8084".to_string())
        .parse::<SocketAddr>()
        .expect("invalid CONTROL_HTTP_BIND_ADDR");
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://yugabyte@127.0.0.1:5433/wildon".to_string());
    let database_max_connections = env::var("CONTROL_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(10);
    let core_endpoint =
        env::var("CORE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50053".to_string());
    let billing_endpoint =
        env::var("BILLING_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50059".to_string());
    let logs_endpoint =
        env::var("LOGS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50054".to_string());
    let auth_endpoint =
        env::var("AUTH_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let users_endpoint =
        env::var("USERS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50057".to_string());
    let api_clients_endpoint = env::var("API_CLIENTS_GRPC_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:50058".to_string());
    let expected_issuer = env::var("JWT_EXPECTED_ISSUER")
        .unwrap_or_else(|_| "https://auth.wildon.local".to_string());
    let bootstrap_token = env::var("CONTROL_BOOTSTRAP_TOKEN").unwrap_or_default();
    let device_gateway_base_url = env::var("DEVICE_GATEWAY_INTERNAL_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9080".to_string());
    let device_gateway_internal_token = env::var("DEVICE_GATEWAY_INTERNAL_TOKEN")
        .unwrap_or_else(|_| "wildon-internal".to_string());
    let internal_web_token = env::var("CONTROL_INTERNAL_WEB_TOKEN").unwrap_or_default();
    let allowed_hosts_raw = env::var("CONTROL_ALLOWED_HOSTS").unwrap_or_else(|_| {
        "control-api.wildon.internal,control.wildon.local,localhost,127.0.0.1".to_string()
    });
    let allowed_hosts = parse_allowed_hosts(&allowed_hosts_raw);
    let db = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .connect(&database_url)
        .await
        .expect("failed to connect to control database");
    let redis = env::var("REDIS_URL")
        .ok()
        .and_then(|url| redis::Client::open(url).ok());
    let core_channel = connect_channel(&core_endpoint, "core-service")
        .await
        .expect("failed to connect core grpc endpoint");
    let core_client =
        contracts::wildon::core::v1::core_service_client::CoreServiceClient::new(core_channel);
    let billing_channel = connect_channel(&billing_endpoint, "billing-service")
        .await
        .expect("failed to connect billing grpc endpoint");
    let billing_client =
        contracts::wildon::billing::v1::billing_service_client::BillingServiceClient::new(
            billing_channel,
        );
    let logs_channel = connect_channel(&logs_endpoint, "logs-service")
        .await
        .expect("failed to connect logs grpc endpoint");
    let logs_client =
        contracts::wildon::logs::v1::logs_service_client::LogsServiceClient::new(logs_channel);
    let auth_channel = connect_channel(&auth_endpoint, "auth-service")
        .await
        .expect("failed to connect auth grpc endpoint");
    let auth_client =
        contracts::wildon::auth::v1::auth_service_client::AuthServiceClient::new(auth_channel);
    let users_channel = connect_channel(&users_endpoint, "users-service")
        .await
        .expect("failed to connect users grpc endpoint");
    let users_client =
        contracts::wildon::users::v1::users_service_client::UsersServiceClient::new(
            users_channel,
        );
    let api_clients_channel = connect_channel(&api_clients_endpoint, "api-clients-service")
        .await
        .expect("failed to connect api-clients grpc endpoint");
    let api_clients_client =
        contracts::wildon::api_clients::v1::api_clients_service_client::ApiClientsServiceClient::new(
            api_clients_channel,
        );

    let state = AppState::new(
        db,
        core_client,
        billing_client,
        logs_client,
        auth_client,
        users_client,
        api_clients_client,
        redis,
        expected_issuer,
        bootstrap_token,
        internal_web_token,
        allowed_hosts,
        device_gateway_base_url,
        device_gateway_internal_token,
    );
    let max_request_body_bytes = env::var("CONTROL_MAX_REQUEST_BODY_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(32 * 1024);
    let app = routes::router(state.clone())
        .layer(axum::middleware::from_fn(
            shared_middleware::enforce_json_request_shape,
        ))
        .layer(RequestBodyLimitLayer::new(max_request_body_bytes))
        .layer(axum::middleware::from_fn(
            shared_middleware::inject_request_id,
        ));

    // Nightly retention sweep — runs every 6 hours, purges gateway data older than configured retention
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 3600));
        loop {
            interval.tick().await;
            run_retention_sweep(&state.db).await;
        }
    });

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind control listener");
    tracing::info!(address = %bind_addr, "control http listening");
    axum::serve(listener, app)
        .await
        .expect("control http server failed");
}

async fn run_retention_sweep(db: &sqlx::PgPool) {
    // Read the configured retention days (default 30 if not set or parse fails)
    let retention_days: i32 = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT config FROM control_app.device_configuration WHERE singleton = true",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.get("connection_log_retention_days").and_then(|d| d.as_i64()))
    .map(|d| d.clamp(1, 3650) as i32)
    .unwrap_or(30);

    tracing::info!(retention_days, "running connection log retention sweep");

    // Record sweep start time
    let _ = sqlx::query(
        "INSERT INTO control_app.device_configuration (singleton, config, updated_by, updated_at)
         VALUES (TRUE, jsonb_build_object('last_swept_at', EXTRACT(EPOCH FROM NOW())::BIGINT), 'system', NOW())
         ON CONFLICT (singleton) DO UPDATE SET
             config = jsonb_set(control_app.device_configuration.config, '{last_swept_at}', to_jsonb(EXTRACT(EPOCH FROM NOW())::BIGINT), true),
             updated_at = NOW()",
    )
    .execute(db)
    .await;

    let cutoff = format!("{} days", retention_days);

    // Purge old packet logs
    match sqlx::query(
        "DELETE FROM device_gateway.device_packet_log WHERE received_at < NOW() - $1::INTERVAL",
    )
    .bind(&cutoff)
    .execute(db)
    .await
    {
        Ok(r) => tracing::info!(deleted = r.rows_affected(), "purged old packet logs"),
        Err(e) => tracing::warn!(error = %e, "failed to purge packet logs"),
    }

    // Purge old connection log entries
    match sqlx::query(
        "DELETE FROM device_gateway.device_connection_log WHERE connected_at < NOW() - $1::INTERVAL",
    )
    .bind(&cutoff)
    .execute(db)
    .await
    {
        Ok(r) => tracing::info!(deleted = r.rows_affected(), "purged old connection logs"),
        Err(e) => tracing::warn!(error = %e, "failed to purge connection logs"),
    }

    // Purge old telemetry
    match sqlx::query(
        "DELETE FROM device_gateway.device_telemetry WHERE received_at < NOW() - $1::INTERVAL",
    )
    .bind(&cutoff)
    .execute(db)
    .await
    {
        Ok(r) => tracing::info!(deleted = r.rows_affected(), "purged old telemetry"),
        Err(e) => tracing::warn!(error = %e, "failed to purge telemetry"),
    }

    // Purge old alarms
    match sqlx::query(
        "DELETE FROM device_gateway.device_alarms WHERE received_at < NOW() - $1::INTERVAL",
    )
    .bind(&cutoff)
    .execute(db)
    .await
    {
        Ok(r) => tracing::info!(deleted = r.rows_affected(), "purged old alarms"),
        Err(e) => tracing::warn!(error = %e, "failed to purge alarms"),
    }
}

fn parse_allowed_hosts(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(|host| host.to_ascii_lowercase())
        .collect()
}
