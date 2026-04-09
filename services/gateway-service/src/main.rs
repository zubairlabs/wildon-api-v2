#![allow(dead_code)]

mod clients;
mod error;
mod middleware;
mod routes;
mod routing;
mod state;

use crate::{
    clients::{
        bootstrap_api_clients_client, bootstrap_auth_client, bootstrap_billing_client,
        bootstrap_logs_client, bootstrap_public_client, bootstrap_users_client,
    },
    middleware::{
        audit_log, authorization_policy, call_counter, client_identity, csrf, jwt_validate,
        rate_limit, realm_enforce,
    },
    routing::service_map::ServiceMap,
    state::{AppState, ServiceStatus},
};
use ::middleware as shared_middleware;
use axum::{
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderName, HeaderValue, Method,
    },
    Router,
};
use futures_util::StreamExt;
use observability::init_tracing;
use serde::Deserialize;
use std::{env, net::SocketAddr, time::SystemTime, time::UNIX_EPOCH};
use tokio::net::TcpListener;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
};

const NATS_API_CLIENT_CHANGED_SUBJECT: &str = "api_client.changed";

#[derive(Debug, Deserialize)]
struct ApiClientChangedEvent {
    client_id: String,
}

#[tokio::main]
async fn main() {
    init_tracing("gateway-service");

    let bind_addr = env::var("GATEWAY_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()
        .expect("invalid GATEWAY_BIND_ADDR");

    let service_map = ServiceMap::from_env();
    let auth_client = bootstrap_auth_client(&service_map.auth_grpc)
        .await
        .expect("failed to connect to auth-service grpc endpoint");
    let api_clients_client = bootstrap_api_clients_client(&service_map.api_clients_grpc)
        .await
        .expect("failed to connect to api-clients-service grpc endpoint");
    let public_client = bootstrap_public_client(&service_map.public_grpc)
        .await
        .expect("failed to connect to public-service grpc endpoint");
    let users_client = bootstrap_users_client(&service_map.users_grpc)
        .await
        .expect("failed to connect to users-service grpc endpoint");
    let billing_client = bootstrap_billing_client(&service_map.billing_grpc)
        .await
        .expect("failed to connect to billing-service grpc endpoint");
    let logs_client = bootstrap_logs_client(&service_map.logs_grpc)
        .await
        .expect("failed to connect to logs-service grpc endpoint");

    let expected_issuer = env::var("JWT_EXPECTED_ISSUER")
        .unwrap_or_else(|_| "https://auth.wildon.local".to_string());
    let state = AppState::new(
        service_map,
        auth_client,
        public_client,
        users_client,
        api_clients_client,
        billing_client,
        logs_client,
        expected_issuer,
    );

    // Restore API metric baselines from Redis (survives restarts)
    state.restore_metrics_from_redis().await;

    // Spawn per-service jittered health probes
    spawn_service_health_probes(state.clone());

    // Spawn Redis metrics flush (every 60s)
    {
        let flush_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                flush_state.flush_metrics_to_redis().await;
            }
        });
    }

    spawn_api_client_cache_invalidator(state.clone())
        .await
        .expect("failed to start api client cache invalidator");

    let app = build_app(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind gateway listener");
    tracing::info!(address = %bind_addr, "gateway listening");
    axum::serve(listener, app)
        .await
        .expect("gateway server failed");
}

async fn spawn_api_client_cache_invalidator(state: AppState) -> Result<(), String> {
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let require_invalidation = env::var("GATEWAY_REQUIRE_API_CLIENT_INVALIDATION")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let client = match async_nats::connect(&nats_url).await {
        Ok(client) => client,
        Err(err) => {
            if require_invalidation {
                return Err(format!("connect nats for invalidation failed: {err}"));
            }
            tracing::error!(error = %err, "failed to connect to nats for api client cache invalidation");
            return Ok(());
        }
    };
    let subscriber = match client.subscribe(NATS_API_CLIENT_CHANGED_SUBJECT).await {
        Ok(subscriber) => subscriber,
        Err(err) => {
            if require_invalidation {
                return Err(format!("subscribe invalidation subject failed: {err}"));
            }
            tracing::error!(error = %err, "failed to subscribe to api client invalidation subject");
            return Ok(());
        }
    };

    tokio::spawn(async move {
        let mut subscriber = subscriber;

        tracing::info!(
            subject = NATS_API_CLIENT_CHANGED_SUBJECT,
            "gateway subscribed to api client invalidation stream"
        );

        while let Some(message) = subscriber.next().await {
            let payload = std::str::from_utf8(&message.payload).unwrap_or_default();
            match serde_json::from_str::<ApiClientChangedEvent>(payload) {
                Ok(event) if !event.client_id.trim().is_empty() => {
                    state.invalidate_client_cache(&event.client_id).await;
                }
                Ok(_) => {
                    state.clear_client_caches().await;
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        payload = payload,
                        "failed to parse api client invalidation event; clearing all client caches"
                    );
                    state.clear_client_caches().await;
                }
            }
        }

        tracing::warn!("api client invalidation subscription closed");
    });

    Ok(())
}

fn build_app(state: AppState) -> Router {
    let max_request_body_bytes = env::var("GATEWAY_MAX_REQUEST_BODY_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(32 * 1024);

    let mut app = routes::router(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            call_counter::record_call,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit::apply_rate_limit,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authorization_policy::enforce_authorization_policy,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            realm_enforce::enforce_realm,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            jwt_validate::validate_jwt,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            client_identity::validate_client,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf::enforce_csrf,
        ))
        .layer(axum::middleware::from_fn(
            shared_middleware::enforce_json_request_shape,
        ))
        .layer(RequestBodyLimitLayer::new(max_request_body_bytes))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit_log::audit_mutations,
        ))
        .layer(axum::middleware::from_fn(
            shared_middleware::inject_request_id,
        ));

    if !state.browser_allowed_origins.is_empty() {
        app = app.layer(build_cors_layer(&state));
    }

    app
}

fn spawn_service_health_probes(state: AppState) {
    let services: Vec<(&'static str, String)> = {
        let sm = &state.service_map;
        vec![
            ("auth-service", sm.auth_grpc.clone()),
            ("public-service", sm.public_grpc.clone()),
            ("users-service", sm.users_grpc.clone()),
            ("core-service", sm.core_grpc.clone()),
            ("billing-service", sm.billing_grpc.clone()),
            ("api-clients-service", sm.api_clients_grpc.clone()),
        ]
    };

    for (idx, (name, endpoint)) in services.into_iter().enumerate() {
        let state = state.clone();
        tokio::spawn(async move {
            // Jitter: spread probes by ~1s each to avoid thundering herd
            let jitter_ms = (idx as u64) * 1200
                + (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.subsec_millis() as u64)
                    .unwrap_or(0)
                    % 1000);
            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let checked_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                let status = probe_grpc_health(&endpoint).await;
                state
                    .set_service_health(
                        name,
                        ServiceStatus {
                            status: if status.is_ok() {
                                "UP".to_string()
                            } else {
                                "DOWN".to_string()
                            },
                            reason: status.err(),
                            checked_at,
                        },
                    )
                    .await;
            }
        });
    }
}

async fn probe_grpc_health(endpoint: &str) -> Result<(), String> {
    let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
        .map_err(|e| format!("invalid endpoint: {e}"))?
        .connect_lazy();
    let mut client = HealthClient::new(channel);
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.check(HealthCheckRequest {
            service: String::new(),
        }),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{}", e.message())),
        Err(_) => Err("health probe timed out".to_string()),
    }
}

fn build_cors_layer(state: &AppState) -> CorsLayer {
    let allowed_origins = state
        .browser_allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("x-client-id"),
            HeaderName::from_static("x-client-secret"),
            HeaderName::from_static("x-app-version"),
            HeaderName::from_static("x-csrf-token"),
            HeaderName::from_static("x-request-id"),
        ])
}
