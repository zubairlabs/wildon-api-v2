#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::state::AppState;
use config::grpc::{authorize_internal_request, load_server_tls_config, InternalAuthPolicy};
use contracts::wildon::logs::v1::{
    logs_service_server::{LogsService, LogsServiceServer},
    AuditLogRecord, GetAuditCountByEventRequest, GetAuditCountByEventResponse,
    GetAuditLogRequest, GetAuditLogResponse, HealthRequest, HealthResponse, IngestAuditRequest,
    IngestAuditResponse, ListAuditLogsRequest, ListAuditLogsResponse,
};
use observability::init_tracing;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::{env, net::SocketAddr};
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct LogsGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

#[tonic::async_trait]
impl LogsService for LogsGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "control-service",
                "gateway-service",
                "auth-service",
            ],
        )?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("missing")
            .to_string();

        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            request_id,
        }))
    }

    async fn ingest_audit(
        &self,
        request: Request<IngestAuditRequest>,
    ) -> Result<Response<IngestAuditResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "control-service",
                "gateway-service",
                "auth-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.event_id.is_empty() || payload.consumer.is_empty() {
            return Err(Status::invalid_argument(
                "event_id and consumer are required",
            ));
        }

        let result = sqlx::query(
            "INSERT INTO logs_app.audit_events
                 (event_id, consumer, user_id, action, payload_json, created_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, NOW())
             ON CONFLICT (event_id, consumer) DO NOTHING",
        )
        .bind(&payload.event_id)
        .bind(&payload.consumer)
        .bind(&payload.user_id)
        .bind(&payload.action)
        .bind(&payload.payload_json)
        .execute(&self.state.db)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "failed to insert audit event");
            Status::internal("database error")
        })?;

        let accepted = result.rows_affected() > 0;
        let duplicate = !accepted;

        let total_records: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM logs_app.audit_events",
        )
        .fetch_one(&self.state.db)
        .await
        .unwrap_or(0);

        Ok(Response::new(IngestAuditResponse {
            accepted,
            duplicate,
            total_records: total_records as u64,
        }))
    }

    async fn get_audit_count_by_event(
        &self,
        request: Request<GetAuditCountByEventRequest>,
    ) -> Result<Response<GetAuditCountByEventResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["control-service", "gateway-service"],
        )?;

        let event_id = request.into_inner().event_id;
        if event_id.is_empty() {
            return Err(Status::invalid_argument("event_id is required"));
        }

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM logs_app.audit_events WHERE event_id = $1",
        )
        .bind(&event_id)
        .fetch_one(&self.state.db)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "failed to count audit events");
            Status::internal("database error")
        })?;

        Ok(Response::new(GetAuditCountByEventResponse {
            count: count as u64,
        }))
    }

    async fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> Result<Response<GetAuditLogResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["control-service", "gateway-service"],
        )?;

        let event_id = request.into_inner().event_id;
        if event_id.trim().is_empty() {
            return Err(Status::invalid_argument("event_id is required"));
        }

        let row = sqlx::query(
            "SELECT event_id, consumer, user_id, action,
                    payload_json::TEXT AS payload_json,
                    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix
             FROM logs_app.audit_events
             WHERE event_id = $1
             LIMIT 1",
        )
        .bind(event_id.trim())
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "failed to fetch audit log");
            Status::internal("database error")
        })?
        .ok_or_else(|| Status::not_found("audit log not found"))?;

        let record = AuditLogRecord {
            event_id: row.get("event_id"),
            user_id: row.get("user_id"),
            action: row.get("action"),
            payload_json: row.get("payload_json"),
            consumer: row.get("consumer"),
            created_at: row.get::<i64, _>("created_at_unix"),
            canonical_event: None,
        };

        Ok(Response::new(GetAuditLogResponse { item: Some(record) }))
    }

    async fn list_audit_logs(
        &self,
        request: Request<ListAuditLogsRequest>,
    ) -> Result<Response<ListAuditLogsResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let limit = normalize_limit(payload.limit) as i64;
        let cursor = parse_cursor(&payload.cursor)?;

        let action_filter = non_empty(&payload.action);
        let consumer_filter = non_empty(&payload.consumer);
        let user_id_filter = non_empty(&payload.user_id);
        let from_unix = payload.from_unix;
        let to_unix = payload.to_unix;

        // Build the WHERE clause components. The cursor implements keyset pagination:
        // entries are sorted DESC by (created_at, event_id, consumer) and we want
        // rows that come AFTER the cursor item (i.e. strictly less than cursor in that order).
        let (cursor_ts, cursor_event_id, cursor_consumer) = match &cursor {
            Some(c) => (Some(c.created_at), Some(c.event_id.as_str()), Some(c.consumer.as_str())),
            None => (None, None, None),
        };

        let rows = sqlx::query(
            "SELECT event_id, consumer, user_id, action,
                    payload_json::TEXT AS payload_json,
                    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix
             FROM logs_app.audit_events
             WHERE ($1 = '' OR action = $1)
               AND ($2 = '' OR consumer = $2)
               AND ($3 = '' OR user_id = $3)
               AND ($4 <= 0 OR EXTRACT(EPOCH FROM created_at)::BIGINT >= $4)
               AND ($5 <= 0 OR EXTRACT(EPOCH FROM created_at)::BIGINT <= $5)
               AND (
                   $6::BIGINT IS NULL
                   OR EXTRACT(EPOCH FROM created_at)::BIGINT < $6
                   OR (EXTRACT(EPOCH FROM created_at)::BIGINT = $6 AND event_id < $7)
                   OR (EXTRACT(EPOCH FROM created_at)::BIGINT = $6 AND event_id = $7 AND consumer < $8)
               )
             ORDER BY created_at DESC, event_id DESC, consumer DESC
             LIMIT $9",
        )
        .bind(action_filter.unwrap_or(""))
        .bind(consumer_filter.unwrap_or(""))
        .bind(user_id_filter.unwrap_or(""))
        .bind(from_unix)
        .bind(to_unix)
        .bind(cursor_ts)
        .bind(cursor_event_id.unwrap_or(""))
        .bind(cursor_consumer.unwrap_or(""))
        .bind(limit + 1)
        .fetch_all(&self.state.db)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "failed to list audit logs");
            Status::internal("database error")
        })?;

        let has_more = rows.len() as i64 > limit;
        let items: Vec<AuditLogRecord> = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| AuditLogRecord {
                event_id: row.get("event_id"),
                user_id: row.get("user_id"),
                action: row.get("action"),
                payload_json: row.get("payload_json"),
                consumer: row.get("consumer"),
                created_at: row.get::<i64, _>("created_at_unix"),
                canonical_event: None,
            })
            .collect();

        let next_cursor = if has_more {
            items
                .last()
                .map(|item| format!("{}|{}|{}", item.created_at, item.event_id, item.consumer))
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Total matching rows (for the frontend stat cards)
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM logs_app.audit_events
             WHERE ($1 = '' OR action = $1)
               AND ($2 = '' OR consumer = $2)
               AND ($3 = '' OR user_id = $3)
               AND ($4 <= 0 OR EXTRACT(EPOCH FROM created_at)::BIGINT >= $4)
               AND ($5 <= 0 OR EXTRACT(EPOCH FROM created_at)::BIGINT <= $5)",
        )
        .bind(action_filter.unwrap_or(""))
        .bind(consumer_filter.unwrap_or(""))
        .bind(user_id_filter.unwrap_or(""))
        .bind(from_unix)
        .bind(to_unix)
        .fetch_one(&self.state.db)
        .await
        .unwrap_or(0);

        Ok(Response::new(ListAuditLogsResponse {
            items,
            next_cursor,
            has_more,
            total: total as u64,
        }))
    }
}

#[derive(Debug, Clone)]
struct AuditCursor {
    created_at: i64,
    event_id: String,
    consumer: String,
}

fn normalize_limit(limit: u32) -> usize {
    match limit {
        0 => 50,
        value => value.min(500) as usize,
    }
}

fn parse_cursor(raw: &str) -> Result<Option<AuditCursor>, Status> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let mut parts = value.splitn(3, '|');
    let Some(created_at_raw) = parts.next() else {
        return Err(Status::invalid_argument("invalid cursor"));
    };
    let Some(event_id_raw) = parts.next() else {
        return Err(Status::invalid_argument("invalid cursor"));
    };
    let Some(consumer_raw) = parts.next() else {
        return Err(Status::invalid_argument("invalid cursor"));
    };

    let created_at = created_at_raw
        .parse::<i64>()
        .map_err(|_| Status::invalid_argument("invalid cursor"))?;
    let event_id = event_id_raw.trim().to_string();
    let consumer = consumer_raw.trim().to_string();
    if event_id.is_empty() || consumer.is_empty() {
        return Err(Status::invalid_argument("invalid cursor"));
    }

    Ok(Some(AuditCursor {
        created_at,
        event_id,
        consumer,
    }))
}

fn non_empty(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

#[tokio::main]
async fn main() {
    init_tracing("logs-service");

    let grpc_addr = env::var("LOGS_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50054".to_string())
        .parse::<SocketAddr>()
        .expect("invalid LOGS_GRPC_BIND_ADDR");

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://yugabyte@127.0.0.1:5433/wildon".to_string());

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to logs database");

    let grpc = LogsGrpc {
        state: AppState { db },
        internal_auth: InternalAuthPolicy::from_env("logs-service"),
    };

    tracing::info!(address = %grpc_addr, "logs grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<LogsServiceServer<LogsGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply logs grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(LogsServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("logs grpc server failed");
}
