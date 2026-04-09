#![allow(dead_code)]

mod modules;
mod state;

use crate::state::AppState;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chrono::{DateTime, Utc};
use config::grpc::{authorize_internal_request, load_server_tls_config, InternalAuthPolicy};
use contracts::wildon::api_clients::v1::{
    api_clients_service_server::{ApiClientsService, ApiClientsServiceServer},
    ApiClient, ClientEnvironment, ClientEvent, ClientPolicy, ClientStatus, ClientType,
    CreateClientRequest, CreateClientResponse, GetClientByIdRequest, GetClientByIdResponse,
    GetClientByRefRequest, GetClientByRefResponse, GetClientPolicyRequest, GetClientPolicyResponse,
    HealthRequest, HealthResponse, ListClientEventsRequest, ListClientEventsResponse,
    ListClientsRequest, ListClientsResponse, ListRateLimitPoliciesRequest,
    ListRateLimitPoliciesResponse, RateLimitPolicy, RateLimitRouteOverride,
    RotateClientSecretRequest, RotateClientSecretResponse, SetClientStatusRequest,
    SetClientStatusResponse, UpdateClientRequest, UpdateClientResponse, UpsertClientRequest,
    UpsertClientResponse, ValidateClientRequest, ValidateClientResponse,
};
use observability::init_tracing;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{collections::BTreeMap, env, net::SocketAddr};
use tonic::{Request, Response, Status};
use uuid::Uuid;

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 200;
const LAST_USED_UPDATE_INTERVAL_SECONDS: i64 = 600;
const NATS_API_CLIENT_CHANGED_SUBJECT: &str = "api_client.changed";
const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

const CLIENT_SELECT_COLUMNS: &str = r#"
  c.id::text AS id,
  c.client_id,
  c.client_number,
  c.client_ref,
  c.display_name,
  COALESCE(c.description, '') AS description,
  c.platform,
  c.surface,
  c.environment,
  c.client_type,
  c.status,
  COALESCE(c.allowed_audiences, ARRAY[]::TEXT[]) AS allowed_audiences,
  COALESCE(c.allowed_origins, ARRAY[]::TEXT[]) AS allowed_origins,
  COALESCE(c.ip_allowlist, ARRAY[]::TEXT[]) AS ip_allowlist,
  c.require_mtls,
  c.is_version_enforced,
  COALESCE(c.min_app_version, '') AS min_app_version,
  COALESCE(c.max_app_version, '') AS max_app_version,
  c.user_rate_policy,
  c.client_safety_policy,
  c.rate_limit_profile,
  c.created_at,
  c.updated_at,
  c.last_used_at,
  COALESCE(c.created_by::text, '') AS created_by,
  COALESCE(c.updated_by::text, '') AS updated_by,
  COALESCE(c.notes, '') AS notes,
  EXISTS (
    SELECT 1
    FROM api_clients_app.api_client_secrets s
    WHERE s.client_pk = c.id
      AND s.status = 'active'
      AND (s.expires_at IS NULL OR s.expires_at > NOW())
  ) AS has_active_secret
"#;

#[derive(Clone)]
struct ApiClientsGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

#[derive(Debug, Clone)]
struct DbClientRecord {
    id: String,
    client_id: String,
    client_number: i64,
    client_ref: String,
    display_name: String,
    description: String,
    platform: String,
    surface: String,
    environment: String,
    client_type: String,
    status: String,
    allowed_audiences: Vec<String>,
    allowed_origins: Vec<String>,
    ip_allowlist: Vec<String>,
    require_mtls: bool,
    is_version_enforced: bool,
    min_app_version: String,
    max_app_version: String,
    user_rate_policy: String,
    client_safety_policy: String,
    rate_limit_profile: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    created_by: String,
    updated_by: String,
    notes: String,
    has_active_secret: bool,
}

#[derive(Debug, Clone)]
struct PolicyRule {
    scope: String,
    route_group: String,
    requests_per_min: u32,
}

#[tonic::async_trait]
impl ApiClientsService for ApiClientsGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "auth-service", "control-service"],
        )?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_string();

        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            request_id,
        }))
    }

    async fn validate_client(
        &self,
        request: Request<ValidateClientRequest>,
    ) -> Result<Response<ValidateClientResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "auth-service", "control-service"],
        )?;

        let payload = request.into_inner();
        let client_id = normalize_client_id(&payload.client_id)?;
        let Some(record) = fetch_client_by_client_id(&self.state.db, &client_id).await? else {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "client not found".to_string(),
                policy: None,
            }));
        };

        let policy = build_client_policy(&self.state.db, &record).await?;

        if record.status != "active" {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "client is not active".to_string(),
                policy: Some(policy),
            }));
        }

        let audience = payload.audience.trim().to_ascii_lowercase();
        if !audience.is_empty()
            && !record
                .allowed_audiences
                .iter()
                .any(|value| value.eq_ignore_ascii_case(&audience))
        {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "audience is not allowed for client".to_string(),
                policy: Some(policy),
            }));
        }

        let requested_env = payload.environment.trim().to_ascii_lowercase();
        if !requested_env.is_empty() && requested_env != record.environment {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "environment mismatch".to_string(),
                policy: Some(policy),
            }));
        }

        let requested_surface = payload.surface.trim().to_ascii_lowercase();
        if !requested_surface.is_empty() && requested_surface != record.surface {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "surface mismatch".to_string(),
                policy: Some(policy),
            }));
        }

        if record.is_version_enforced {
            if !record.min_app_version.trim().is_empty()
                && !is_version_at_least(
                    Some(payload.app_version.as_str()),
                    Some(record.min_app_version.as_str()),
                )
            {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "minimum app version requirement not met".to_string(),
                    policy: Some(policy),
                }));
            }

            if !record.max_app_version.trim().is_empty()
                && !is_version_at_most(
                    Some(payload.app_version.as_str()),
                    Some(record.max_app_version.as_str()),
                )
            {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "app version exceeds allowed maximum".to_string(),
                    policy: Some(policy),
                }));
            }
        }

        if !record.allowed_origins.is_empty() {
            let origin = payload.origin.trim().to_ascii_lowercase();
            if origin.is_empty()
                || !record
                    .allowed_origins
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&origin))
            {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "origin is not allowed for client".to_string(),
                    policy: Some(policy),
                }));
            }
        }

        if !record.ip_allowlist.is_empty() {
            let source_ip = payload.source_ip.trim();
            if source_ip.is_empty()
                || !record
                    .ip_allowlist
                    .iter()
                    .any(|candidate| candidate == source_ip)
            {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "source ip is not allowed for client".to_string(),
                    policy: Some(policy),
                }));
            }
        }

        if record.require_mtls && !payload.mtls_verified {
            return Ok(Response::new(ValidateClientResponse {
                valid: false,
                reason: "mTLS is required for this client".to_string(),
                policy: Some(policy),
            }));
        }

        if record.client_type == "confidential" {
            let provided_secret = payload.client_secret.trim();
            if provided_secret.is_empty() {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "client secret is required".to_string(),
                    policy: Some(policy),
                }));
            }
            let valid_secret =
                verify_active_secret(&self.state.db, &record.id, provided_secret).await?;
            if !valid_secret {
                return Ok(Response::new(ValidateClientResponse {
                    valid: false,
                    reason: "invalid client secret".to_string(),
                    policy: Some(policy),
                }));
            }
        }

        let _ = sqlx::query(
            "UPDATE api_clients_app.api_clients
             SET last_used_at = NOW()
             WHERE id = $1::UUID
               AND (
                 last_used_at IS NULL
                 OR last_used_at < NOW() - ($2 || ' seconds')::INTERVAL
               )",
        )
        .bind(&record.id)
        .bind(LAST_USED_UPDATE_INTERVAL_SECONDS)
        .execute(&self.state.db)
        .await;

        Ok(Response::new(ValidateClientResponse {
            valid: true,
            reason: "ok".to_string(),
            policy: Some(policy),
        }))
    }

    async fn get_client_policy(
        &self,
        request: Request<GetClientPolicyRequest>,
    ) -> Result<Response<GetClientPolicyResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "auth-service", "control-service"],
        )?;

        let payload = request.into_inner();
        let client_id = normalize_client_id(&payload.client_id)?;
        let Some(record) = fetch_client_by_client_id(&self.state.db, &client_id).await? else {
            return Err(Status::not_found("client not found"));
        };

        let policy = build_client_policy(&self.state.db, &record).await?;
        Ok(Response::new(GetClientPolicyResponse {
            policy: Some(policy),
        }))
    }

    async fn upsert_client(
        &self,
        request: Request<UpsertClientRequest>,
    ) -> Result<Response<UpsertClientResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let actor = actor_from_metadata(request.metadata());
        let payload = request.into_inner();
        let client_id = normalize_client_id(&payload.client_id)?;

        let environment = environment_from_proto(payload.environment)?;
        let client_type = client_type_from_proto(payload.client_type)?;
        let mut allowed_audiences = normalize_string_list(payload.allowed_audiences, true);
        if allowed_audiences.is_empty() {
            allowed_audiences.push("public".to_string());
        }
        let surface = derive_surface(&allowed_audiences, payload.rate_limit_profile.as_str());
        let (user_policy, client_policy_name) =
            policy_names_from_profile(payload.rate_limit_profile.as_str(), surface.as_str());

        ensure_policy_exists(&self.state.db, &user_policy, "user").await?;
        ensure_policy_exists(&self.state.db, &client_policy_name, "client").await?;

        let existing = fetch_client_by_client_id(&self.state.db, &client_id).await?;
        let id = if let Some(existing) = existing {
            sqlx::query(
                "UPDATE api_clients_app.api_clients
                 SET
                   client_type = $2,
                   environment = $3,
                   surface = $4,
                   allowed_audiences = $5,
                   rate_limit_profile = $6,
                   min_app_version = $7,
                   user_rate_policy = $8,
                   client_safety_policy = $9,
                   updated_by = $10::UUID,
                   updated_at = NOW()
                 WHERE id = $1::UUID",
            )
            .bind(&existing.id)
            .bind(&client_type)
            .bind(&environment)
            .bind(&surface)
            .bind(&allowed_audiences)
            .bind(payload.rate_limit_profile.trim())
            .bind(payload.min_app_version.trim())
            .bind(&user_policy)
            .bind(&client_policy_name)
            .bind(actor.as_deref().and_then(parse_uuid))
            .execute(&self.state.db)
            .await
            .map_err(|err| map_db_error(err, "update client failed"))?;
            existing.id
        } else {
            let inserted = insert_client_row(
                &self.state.db,
                &CreateClientRequest {
                    client_id: client_id.clone(),
                    display_name: client_id.clone(),
                    description: String::new(),
                    platform: "web".to_string(),
                    surface,
                    environment,
                    client_type: client_type_to_proto(&client_type),
                    status: ClientStatus::Active as i32,
                    allowed_audiences,
                    allowed_origins: Vec::new(),
                    ip_allowlist: Vec::new(),
                    require_mtls: false,
                    is_version_enforced: false,
                    min_app_version: payload.min_app_version,
                    max_app_version: String::new(),
                    user_rate_policy: user_policy,
                    client_safety_policy: client_policy_name,
                    created_by: actor.clone().unwrap_or_default(),
                    notes: "created by upsert compatibility".to_string(),
                },
            )
            .await?;
            inserted.id
        };

        let Some(record) = fetch_client_by_id(&self.state.db, &id).await? else {
            return Err(Status::internal("upserted client missing after write"));
        };

        insert_client_event(
            &self.state.db,
            &record.id,
            "client.upserted",
            actor.as_deref(),
            json!({
                "client_id": record.client_id,
                "rate_limit_profile": payload.rate_limit_profile,
            }),
        )
        .await?;
        publish_api_client_changed(&self.state, &record.client_id, "client.upserted").await?;

        let policy = build_client_policy(&self.state.db, &record).await?;
        Ok(Response::new(UpsertClientResponse {
            policy: Some(policy),
        }))
    }

    async fn set_client_status(
        &self,
        request: Request<SetClientStatusRequest>,
    ) -> Result<Response<SetClientStatusResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let actor = actor_from_metadata(request.metadata());
        let payload = request.into_inner();
        let client_id = normalize_client_id(&payload.client_id)?;
        let status = status_from_proto(payload.status)?;
        let existing = fetch_client_by_client_id(&self.state.db, &client_id).await?;
        let Some(existing) = existing else {
            return Err(Status::not_found("client not found"));
        };
        if existing.status == "revoked" && status != "revoked" {
            return Err(Status::failed_precondition(
                "revoked clients are permanent and cannot be reactivated",
            ));
        }

        let update = sqlx::query(
            "UPDATE api_clients_app.api_clients
             SET status = $2, updated_at = NOW(), updated_by = $3::UUID
             WHERE client_id = $1",
        )
        .bind(&client_id)
        .bind(&status)
        .bind(actor.as_deref().and_then(parse_uuid))
        .execute(&self.state.db)
        .await
        .map_err(|err| map_db_error(err, "set status failed"))?;

        if update.rows_affected() == 0 {
            return Err(Status::not_found("client not found"));
        }

        let Some(record) = fetch_client_by_client_id(&self.state.db, &client_id).await? else {
            return Err(Status::not_found("client not found"));
        };

        insert_client_event(
            &self.state.db,
            &record.id,
            "client.status_changed",
            actor.as_deref(),
            json!({ "status": record.status }),
        )
        .await?;
        publish_api_client_changed(&self.state, &record.client_id, "client.status_changed").await?;

        let policy = build_client_policy(&self.state.db, &record).await?;
        Ok(Response::new(SetClientStatusResponse {
            policy: Some(policy),
        }))
    }

    async fn list_clients(
        &self,
        request: Request<ListClientsRequest>,
    ) -> Result<Response<ListClientsResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let limit = normalize_limit(payload.limit);

        let status_filter = normalize_optional_filter(payload.status.as_str());
        let environment_filter = normalize_optional_filter(payload.environment.as_str());
        let surface_filter = normalize_optional_filter(payload.surface.as_str());
        let platform_filter = normalize_optional_filter(payload.platform.as_str());
        let client_type_filter = normalize_optional_filter(payload.client_type.as_str());
        let search_filter = payload.search.trim().to_string();
        let cursor = normalize_cursor(payload.cursor.as_str());

        let sql = format!(
            "SELECT {columns}
             FROM api_clients_app.api_clients c
             WHERE ($1 = '' OR c.status = $1)
               AND ($2 = '' OR c.environment = $2)
               AND ($3 = '' OR c.surface = $3)
               AND ($4 = '' OR c.platform = $4)
               AND ($5 = '' OR c.client_type = $5)
               AND ($6 = '' OR c.client_id ILIKE '%' || $6 || '%' OR c.display_name ILIKE '%' || $6 || '%' OR c.client_ref ILIKE '%' || $6 || '%')
               AND ($7 = '' OR c.client_ref > $7)
             ORDER BY c.client_number ASC
             LIMIT $8",
            columns = CLIENT_SELECT_COLUMNS
        );

        let rows = sqlx::query(&sql)
            .bind(&status_filter)
            .bind(&environment_filter)
            .bind(&surface_filter)
            .bind(&platform_filter)
            .bind(&client_type_filter)
            .bind(&search_filter)
            .bind(&cursor)
            .bind(i64::from(limit + 1))
            .fetch_all(&self.state.db)
            .await
            .map_err(|err| map_db_error(err, "list clients failed"))?;

        let mut items = rows
            .into_iter()
            .map(map_client_row)
            .collect::<Result<Vec<_>, _>>()?;

        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }

        let next_cursor = if has_more {
            items
                .last()
                .map(|item| item.client_ref.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        let count_query = "SELECT COUNT(*)
            FROM api_clients_app.api_clients c
            WHERE ($1 = '' OR c.status = $1)
              AND ($2 = '' OR c.environment = $2)
              AND ($3 = '' OR c.surface = $3)
              AND ($4 = '' OR c.platform = $4)
              AND ($5 = '' OR c.client_type = $5)
              AND ($6 = '' OR c.client_id ILIKE '%' || $6 || '%' OR c.display_name ILIKE '%' || $6 || '%' OR c.client_ref ILIKE '%' || $6 || '%')";

        let total: i64 = sqlx::query_scalar(count_query)
            .bind(&status_filter)
            .bind(&environment_filter)
            .bind(&surface_filter)
            .bind(&platform_filter)
            .bind(&client_type_filter)
            .bind(&search_filter)
            .fetch_one(&self.state.db)
            .await
            .map_err(|err| map_db_error(err, "count clients failed"))?;

        let response = ListClientsResponse {
            items: items
                .into_iter()
                .map(|record| api_client_from_record(&record))
                .collect(),
            next_cursor,
            has_more,
            total: total.max(0) as u64,
        };

        Ok(Response::new(response))
    }

    async fn get_client_by_id(
        &self,
        request: Request<GetClientByIdRequest>,
    ) -> Result<Response<GetClientByIdResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let id = normalize_uuid_text(payload.id.as_str(), "id")?;
        let Some(record) = fetch_client_by_id(&self.state.db, &id).await? else {
            return Err(Status::not_found("client not found"));
        };

        Ok(Response::new(GetClientByIdResponse {
            client: Some(api_client_from_record(&record)),
        }))
    }

    async fn get_client_by_ref(
        &self,
        request: Request<GetClientByRefRequest>,
    ) -> Result<Response<GetClientByRefResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let client_ref = normalize_cursor(payload.client_ref.as_str());
        if client_ref.is_empty() {
            return Err(Status::invalid_argument("client_ref is required"));
        }
        let Some(record) = fetch_client_by_ref(&self.state.db, &client_ref).await? else {
            return Err(Status::not_found("client not found"));
        };

        Ok(Response::new(GetClientByRefResponse {
            client: Some(api_client_from_record(&record)),
        }))
    }

    async fn create_client(
        &self,
        request: Request<CreateClientRequest>,
    ) -> Result<Response<CreateClientResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let actor = actor_from_metadata(request.metadata());
        let payload = request.into_inner();

        let created = insert_client_row(&self.state.db, &payload).await?;
        let secret_plaintext = if created.client_type == "confidential" {
            let generated = rotate_client_secret_impl(
                &self.state.db,
                &created.id,
                payload.created_by.as_str(),
                None,
                false,
            )
            .await?;
            generated.secret
        } else {
            String::new()
        };

        insert_client_event(
            &self.state.db,
            &created.id,
            "client.created",
            actor
                .as_deref()
                .or_else(|| non_empty(payload.created_by.as_str())),
            json!({
                "client_id": created.client_id,
                "client_ref": created.client_ref,
                "surface": created.surface,
                "environment": created.environment,
            }),
        )
        .await?;
        publish_api_client_changed(&self.state, &created.client_id, "client.created").await?;

        Ok(Response::new(CreateClientResponse {
            client: Some(api_client_from_record(&created)),
            secret_plaintext,
        }))
    }

    async fn update_client(
        &self,
        request: Request<UpdateClientRequest>,
    ) -> Result<Response<UpdateClientResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let actor = actor_from_metadata(request.metadata());
        let payload = request.into_inner();
        let id = normalize_uuid_text(payload.id.as_str(), "id")?;

        let Some(existing) = fetch_client_by_id(&self.state.db, &id).await? else {
            return Err(Status::not_found("client not found"));
        };

        let display_name = non_empty(payload.display_name.as_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| existing.display_name.clone());
        let description = payload.description.trim().to_string();
        let platform = normalize_platform(
            non_empty(payload.platform.as_str()).unwrap_or(existing.platform.as_str()),
        )?;
        let surface = normalize_surface(
            non_empty(payload.surface.as_str()).unwrap_or(existing.surface.as_str()),
        )?;
        let environment = normalize_environment(
            non_empty(payload.environment.as_str()).unwrap_or(existing.environment.as_str()),
        )?;

        let client_type = if payload.client_type == ClientType::Unspecified as i32 {
            existing.client_type.clone()
        } else {
            client_type_from_proto(payload.client_type)?
        };

        let allowed_audiences = if payload.allowed_audiences.is_empty() {
            existing.allowed_audiences.clone()
        } else {
            normalize_audiences(payload.allowed_audiences)?
        };

        let allowed_origins = if payload.allowed_origins.is_empty() {
            existing.allowed_origins.clone()
        } else {
            normalize_string_list(payload.allowed_origins, true)
        };

        let ip_allowlist = if payload.ip_allowlist.is_empty() {
            existing.ip_allowlist.clone()
        } else {
            normalize_string_list(payload.ip_allowlist, false)
        };

        let user_rate_policy = non_empty(payload.user_rate_policy.as_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| existing.user_rate_policy.clone());
        let client_safety_policy = non_empty(payload.client_safety_policy.as_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| existing.client_safety_policy.clone());

        ensure_policy_exists(&self.state.db, &user_rate_policy, "user").await?;
        ensure_policy_exists(&self.state.db, &client_safety_policy, "client").await?;

        sqlx::query(
            "UPDATE api_clients_app.api_clients
             SET
               display_name = $2,
               description = $3,
               platform = $4,
               surface = $5,
               environment = $6,
               client_type = $7,
               allowed_audiences = $8,
               allowed_origins = $9,
               ip_allowlist = $10,
               require_mtls = $11,
               is_version_enforced = $12,
               min_app_version = $13,
               max_app_version = $14,
               user_rate_policy = $15,
               client_safety_policy = $16,
               updated_by = $17::UUID,
               notes = $18,
               updated_at = NOW()
             WHERE id = $1::UUID",
        )
        .bind(&id)
        .bind(display_name)
        .bind(description)
        .bind(platform)
        .bind(surface)
        .bind(environment)
        .bind(&client_type)
        .bind(allowed_audiences)
        .bind(allowed_origins)
        .bind(ip_allowlist)
        .bind(payload.require_mtls)
        .bind(payload.is_version_enforced)
        .bind(payload.min_app_version.trim())
        .bind(payload.max_app_version.trim())
        .bind(user_rate_policy)
        .bind(client_safety_policy)
        .bind(
            non_empty(payload.updated_by.as_str())
                .or_else(|| actor.as_deref())
                .and_then(parse_uuid),
        )
        .bind(payload.notes.trim())
        .execute(&self.state.db)
        .await
        .map_err(|err| map_db_error(err, "update client failed"))?;

        if client_type == "public" {
            let _ = sqlx::query(
                "UPDATE api_clients_app.api_client_secrets
                 SET status = 'revoked', revoked_at = NOW(), rotated_at = NOW()
                 WHERE client_pk = $1::UUID AND status = 'active'",
            )
            .bind(&id)
            .execute(&self.state.db)
            .await;
        }

        let Some(updated) = fetch_client_by_id(&self.state.db, &id).await? else {
            return Err(Status::internal("updated client missing after write"));
        };

        insert_client_event(
            &self.state.db,
            &updated.id,
            "client.updated",
            actor
                .as_deref()
                .or_else(|| non_empty(payload.updated_by.as_str())),
            json!({
                "client_id": updated.client_id,
                "surface": updated.surface,
                "environment": updated.environment,
                "user_rate_policy": updated.user_rate_policy,
                "client_safety_policy": updated.client_safety_policy,
            }),
        )
        .await?;
        publish_api_client_changed(&self.state, &updated.client_id, "client.updated").await?;

        Ok(Response::new(UpdateClientResponse {
            client: Some(api_client_from_record(&updated)),
        }))
    }

    async fn rotate_client_secret(
        &self,
        request: Request<RotateClientSecretRequest>,
    ) -> Result<Response<RotateClientSecretResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let actor = actor_from_metadata(request.metadata());
        let payload = request.into_inner();
        let id = normalize_uuid_text(payload.id.as_str(), "id")?;
        let rotated_by = non_empty(payload.rotated_by.as_str()).or_else(|| actor.as_deref());

        let expires_at = if payload.expires_at_unix > 0 {
            Some(
                DateTime::<Utc>::from_timestamp(payload.expires_at_unix, 0)
                    .ok_or_else(|| Status::invalid_argument("expires_at_unix is invalid"))?,
            )
        } else {
            None
        };

        let result = rotate_client_secret_impl(
            &self.state.db,
            &id,
            rotated_by.unwrap_or(""),
            expires_at,
            true,
        )
        .await?;
        let Some(updated) = fetch_client_by_id(&self.state.db, &id).await? else {
            return Err(Status::internal(
                "updated client missing after secret rotation",
            ));
        };

        insert_client_event(
            &self.state.db,
            &updated.id,
            "client.secret_rotated",
            rotated_by,
            json!({
                "client_id": updated.client_id,
                "secret_version": result.secret_version,
                "expires_at_unix": expires_at.map(|value| value.timestamp()),
            }),
        )
        .await?;
        publish_api_client_changed(&self.state, &updated.client_id, "client.secret_rotated")
            .await?;

        Ok(Response::new(RotateClientSecretResponse {
            client: Some(api_client_from_record(&updated)),
            secret_version: result.secret_version,
            secret_plaintext: result.secret,
        }))
    }

    async fn list_client_events(
        &self,
        request: Request<ListClientEventsRequest>,
    ) -> Result<Response<ListClientEventsResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let client_id = normalize_client_id(&payload.client_id)?;
        let limit = normalize_limit(payload.limit);
        let cursor = normalize_cursor(payload.cursor.as_str());

        let sql = "SELECT e.event_id::text AS event_id,
                          c.client_id,
                          e.event_type,
                          COALESCE(e.actor_user_id::text, '') AS actor_user_id,
                          e.payload_json::text AS payload_json,
                          e.created_at
                   FROM api_clients_app.api_client_events e
                   INNER JOIN api_clients_app.api_clients c ON c.id = e.client_pk
                   WHERE c.client_id = $1
                     AND ($2 = '' OR e.event_id::text < $2)
                   ORDER BY e.created_at DESC, e.event_id DESC
                   LIMIT $3";

        let rows = sqlx::query(sql)
            .bind(&client_id)
            .bind(&cursor)
            .bind(i64::from(limit + 1))
            .fetch_all(&self.state.db)
            .await
            .map_err(|err| map_db_error(err, "list client events failed"))?;

        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let created_at: DateTime<Utc> = row
                .try_get("created_at")
                .map_err(|err| Status::internal(format!("decode event row failed: {err}")))?;
            items.push(ClientEvent {
                event_id: row
                    .try_get("event_id")
                    .map_err(|err| Status::internal(format!("decode event_id failed: {err}")))?,
                client_id: row
                    .try_get("client_id")
                    .map_err(|err| Status::internal(format!("decode client_id failed: {err}")))?,
                event_type: row
                    .try_get("event_type")
                    .map_err(|err| Status::internal(format!("decode event_type failed: {err}")))?,
                actor_user_id: row.try_get("actor_user_id").map_err(|err| {
                    Status::internal(format!("decode actor_user_id failed: {err}"))
                })?,
                payload_json: row.try_get("payload_json").map_err(|err| {
                    Status::internal(format!("decode payload_json failed: {err}"))
                })?,
                created_at: created_at.timestamp(),
            });
        }

        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| item.event_id.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        Ok(Response::new(ListClientEventsResponse {
            items,
            next_cursor,
            has_more,
        }))
    }

    async fn list_rate_limit_policies(
        &self,
        request: Request<ListRateLimitPoliciesRequest>,
    ) -> Result<Response<ListRateLimitPoliciesResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        let scope_filter = normalize_optional_filter(payload.scope.as_str());

        let rows = sqlx::query(
            "SELECT policy_name, scope, route_group,
                    COALESCE(requests_per_min, 0) AS requests_per_min,
                    COALESCE(requests_per_hour, 0) AS requests_per_hour,
                    COALESCE(burst, 0) AS burst,
                    created_at
             FROM api_clients_app.rate_limit_policies
             WHERE enabled = TRUE
               AND ($1 = '' OR scope = $1)
             ORDER BY scope ASC, policy_name ASC, route_group ASC",
        )
        .bind(&scope_filter)
        .fetch_all(&self.state.db)
        .await
        .map_err(|err| map_db_error(err, "list rate policies failed"))?;

        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let created_at: DateTime<Utc> = row.try_get("created_at").map_err(|err| {
                Status::internal(format!("decode rate policy created_at failed: {err}"))
            })?;
            let requests_per_min: i32 = row.try_get("requests_per_min").map_err(|err| {
                Status::internal(format!("decode requests_per_min failed: {err}"))
            })?;
            let requests_per_hour: i32 = row.try_get("requests_per_hour").map_err(|err| {
                Status::internal(format!("decode requests_per_hour failed: {err}"))
            })?;
            let burst: i32 = row
                .try_get("burst")
                .map_err(|err| Status::internal(format!("decode burst failed: {err}")))?;

            items.push(RateLimitPolicy {
                name: row
                    .try_get("policy_name")
                    .map_err(|err| Status::internal(format!("decode policy_name failed: {err}")))?,
                scope: row
                    .try_get("scope")
                    .map_err(|err| Status::internal(format!("decode scope failed: {err}")))?,
                route_group: row
                    .try_get("route_group")
                    .map_err(|err| Status::internal(format!("decode route_group failed: {err}")))?,
                requests_per_min: requests_per_min.max(0) as u32,
                requests_per_hour: requests_per_hour.max(0) as u32,
                burst: burst.max(0) as u32,
                created_at: created_at.timestamp(),
            });
        }

        Ok(Response::new(ListRateLimitPoliciesResponse { items }))
    }
}

#[derive(Debug)]
struct RotateSecretResult {
    secret_version: u32,
    secret: String,
}

async fn insert_client_row(
    db: &PgPool,
    payload: &CreateClientRequest,
) -> Result<DbClientRecord, Status> {
    let client_id = normalize_client_id(&payload.client_id)?;
    let display_name = non_empty(payload.display_name.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| Status::invalid_argument("display_name is required"))?;
    let description = payload.description.trim().to_string();
    let platform = normalize_platform(payload.platform.as_str())?;
    let surface = normalize_surface(payload.surface.as_str())?;
    let environment = normalize_environment(payload.environment.as_str())?;
    let client_type = client_type_from_proto(payload.client_type)?;
    let status = status_from_proto(payload.status)?;

    let mut allowed_audiences = normalize_audiences(payload.allowed_audiences.clone())?;
    if allowed_audiences.is_empty() {
        allowed_audiences.push(surface.clone());
    }

    let allowed_origins = normalize_string_list(payload.allowed_origins.clone(), true);
    let ip_allowlist = normalize_string_list(payload.ip_allowlist.clone(), false);

    let user_rate_policy = non_empty(payload.user_rate_policy.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| Status::invalid_argument("user_rate_policy is required"))?;
    let client_safety_policy = non_empty(payload.client_safety_policy.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| Status::invalid_argument("client_safety_policy is required"))?;

    ensure_policy_exists(db, &user_rate_policy, "user").await?;
    ensure_policy_exists(db, &client_safety_policy, "client").await?;

    let created_by = non_empty(payload.created_by.as_str()).and_then(parse_uuid);
    let id = Uuid::new_v4().to_string();

    let mut tx = db
        .begin()
        .await
        .map_err(|err| map_db_error(err, "begin create client transaction failed"))?;

    let client_number: i64 =
        sqlx::query_scalar("SELECT nextval('api_clients_app.client_number_seq')::BIGINT")
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| map_db_error(err, "reserve client_number failed"))?;

    let client_ref = format_client_ref(client_number);

    sqlx::query(
        "INSERT INTO api_clients_app.api_clients (
            id,
            client_id,
            client_number,
            client_ref,
            display_name,
            description,
            platform,
            surface,
            environment,
            client_type,
            status,
            allowed_audiences,
            allowed_origins,
            ip_allowlist,
            require_mtls,
            is_version_enforced,
            min_app_version,
            max_app_version,
            user_rate_policy,
            client_safety_policy,
            rate_limit_profile,
            created_by,
            updated_by,
            notes,
            created_at,
            updated_at
         ) VALUES (
            $1::UUID,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13,
            $14,
            $15,
            $16,
            $17,
            $18,
            $19,
            $20,
            $21,
            $22::UUID,
            $22::UUID,
            $23,
            NOW(),
            NOW()
         )",
    )
    .bind(&id)
    .bind(&client_id)
    .bind(client_number)
    .bind(&client_ref)
    .bind(display_name)
    .bind(description)
    .bind(platform)
    .bind(&surface)
    .bind(environment)
    .bind(client_type)
    .bind(status)
    .bind(allowed_audiences)
    .bind(allowed_origins)
    .bind(ip_allowlist)
    .bind(payload.require_mtls)
    .bind(payload.is_version_enforced)
    .bind(payload.min_app_version.trim())
    .bind(payload.max_app_version.trim())
    .bind(&user_rate_policy)
    .bind(&client_safety_policy)
    .bind(default_profile_for_surface(&surface))
    .bind(created_by)
    .bind(payload.notes.trim())
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_error(err, "create client failed"))?;

    tx.commit()
        .await
        .map_err(|err| map_db_error(err, "commit create client transaction failed"))?;

    let Some(record) = fetch_client_by_id(db, &id).await? else {
        return Err(Status::internal("created client missing after write"));
    };
    Ok(record)
}

async fn rotate_client_secret_impl(
    db: &PgPool,
    id: &str,
    actor: &str,
    expires_at: Option<DateTime<Utc>>,
    require_confidential_client: bool,
) -> Result<RotateSecretResult, Status> {
    let Some(record) = fetch_client_by_id(db, id).await? else {
        return Err(Status::not_found("client not found"));
    };

    if require_confidential_client && record.client_type != "confidential" {
        return Err(Status::failed_precondition(
            "secret rotation is supported only for confidential clients",
        ));
    }

    let secret = generate_secret();
    let secret_hash = hash_secret(&secret)?;
    let actor_uuid = parse_uuid(actor);

    let mut tx = db
        .begin()
        .await
        .map_err(|err| map_db_error(err, "begin rotate secret transaction failed"))?;

    sqlx::query(
        "UPDATE api_clients_app.api_client_secrets
         SET status = 'revoked', revoked_at = NOW(), rotated_at = NOW(), revoked_by = $2::UUID
         WHERE client_pk = $1::UUID
           AND status = 'active'",
    )
    .bind(id)
    .bind(actor_uuid)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_error(err, "revoke previous active secret failed"))?;

    let next_version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(secret_version), 0) + 1
         FROM api_clients_app.api_client_secrets
         WHERE client_pk = $1::UUID",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_error(err, "compute secret version failed"))?;

    sqlx::query(
        "INSERT INTO api_clients_app.api_client_secrets (
            client_pk,
            secret_version,
            secret_hash,
            status,
            created_by,
            expires_at,
            created_at,
            rotated_at
         ) VALUES (
            $1::UUID,
            $2,
            $3,
            'active',
            $4::UUID,
            $5,
            NOW(),
            NOW()
         )",
    )
    .bind(id)
    .bind(next_version)
    .bind(secret_hash)
    .bind(actor_uuid)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_error(err, "insert rotated secret failed"))?;

    tx.commit()
        .await
        .map_err(|err| map_db_error(err, "commit rotate secret transaction failed"))?;

    Ok(RotateSecretResult {
        secret_version: next_version.max(1) as u32,
        secret,
    })
}

async fn verify_active_secret(
    db: &PgPool,
    client_id: &str,
    provided_secret: &str,
) -> Result<bool, Status> {
    let row = sqlx::query(
        "SELECT secret_hash, expires_at
         FROM api_clients_app.api_client_secrets
         WHERE client_pk = $1::UUID
           AND status = 'active'
         ORDER BY secret_version DESC
         LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(|err| map_db_error(err, "lookup active secret failed"))?;

    let Some(row) = row else {
        return Ok(false);
    };

    let expires_at: Option<DateTime<Utc>> = row
        .try_get("expires_at")
        .map_err(|err| Status::internal(format!("decode secret expires_at failed: {err}")))?;
    if expires_at.is_some_and(|value| value <= Utc::now()) {
        return Ok(false);
    }

    let secret_hash: String = row
        .try_get("secret_hash")
        .map_err(|err| Status::internal(format!("decode secret hash failed: {err}")))?;

    Ok(verify_secret(provided_secret, &secret_hash))
}

async fn ensure_policy_exists(db: &PgPool, policy_name: &str, scope: &str) -> Result<(), Status> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1
         FROM api_clients_app.rate_limit_policy_registry r
         WHERE r.policy_name = $1
           AND r.scope = $2
           AND r.is_deprecated = FALSE
           AND EXISTS (
             SELECT 1
             FROM api_clients_app.rate_limit_policies p
             WHERE p.policy_name = r.policy_name
               AND p.scope = r.scope
               AND p.enabled = TRUE
           )
         LIMIT 1",
    )
    .bind(policy_name)
    .bind(scope)
    .fetch_optional(db)
    .await
    .map_err(|err| map_db_error(err, "lookup rate policy failed"))?;

    if exists.is_none() {
        return Err(Status::invalid_argument(format!(
            "rate policy '{policy_name}' for scope '{scope}' was not found"
        )));
    }

    Ok(())
}

fn normalize_limit(limit: u32) -> u32 {
    match limit {
        0 => DEFAULT_LIST_LIMIT,
        value => value.min(MAX_LIST_LIMIT),
    }
}

fn normalize_optional_filter(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn normalize_cursor(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

fn normalize_string_list(items: Vec<String>, lower_case: bool) -> Vec<String> {
    let mut values = items
        .into_iter()
        .map(|item| {
            if lower_case {
                item.trim().to_ascii_lowercase()
            } else {
                item.trim().to_string()
            }
        })
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn normalize_audiences(items: Vec<String>) -> Result<Vec<String>, Status> {
    let values = normalize_string_list(items, true);
    for audience in &values {
        if !matches!(audience.as_str(), "public" | "platform" | "control") {
            return Err(Status::invalid_argument(format!(
                "unsupported audience '{audience}'"
            )));
        }
    }
    Ok(values)
}

fn normalize_client_id(raw: &str) -> Result<String, Status> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(Status::invalid_argument("client_id is required"));
    }
    if value.len() < 3 || value.len() > 128 {
        return Err(Status::invalid_argument(
            "client_id length must be between 3 and 128",
        ));
    }
    if value.starts_with('-') || value.ends_with('-') {
        return Err(Status::invalid_argument(
            "client_id cannot start or end with '-'",
        ));
    }
    if value
        .chars()
        .any(|ch| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'))
    {
        return Err(Status::invalid_argument(
            "client_id must use [a-z0-9-] format",
        ));
    }
    Ok(value)
}

fn normalize_platform(raw: &str) -> Result<String, Status> {
    let value = raw.trim().to_ascii_lowercase();
    if matches!(
        value.as_str(),
        "android" | "ios" | "web" | "backend" | "internal" | "firmware"
    ) {
        Ok(value)
    } else {
        Err(Status::invalid_argument(format!(
            "unsupported platform '{value}'"
        )))
    }
}

fn normalize_surface(raw: &str) -> Result<String, Status> {
    let value = raw.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "public" | "platform" | "control") {
        Ok(value)
    } else {
        Err(Status::invalid_argument(format!(
            "unsupported surface '{value}'"
        )))
    }
}

fn normalize_environment(raw: &str) -> Result<String, Status> {
    let value = raw.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "dev" | "staging" | "prod") {
        Ok(value)
    } else {
        Err(Status::invalid_argument(format!(
            "unsupported environment '{value}'"
        )))
    }
}

fn normalize_uuid_text(raw: &str, field: &str) -> Result<String, Status> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    Uuid::parse_str(value)
        .map(|id| id.to_string())
        .map_err(|_| Status::invalid_argument(format!("{field} must be a UUID")))
}

fn parse_uuid(raw: &str) -> Option<Uuid> {
    Uuid::parse_str(raw.trim()).ok()
}

fn actor_from_metadata(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("x-auth-sub")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn non_empty(raw: &str) -> Option<&str> {
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn format_client_ref(client_number: i64) -> String {
    format!("CLT-{:0>6}", client_number.max(0))
}

fn default_profile_for_surface(surface: &str) -> &'static str {
    match surface {
        "control" => "control_v1",
        "platform" => "platform_v1",
        _ => "public_mobile_v1",
    }
}

fn derive_surface(allowed_audiences: &[String], profile: &str) -> String {
    if allowed_audiences
        .iter()
        .any(|audience| audience == "control")
    {
        return "control".to_string();
    }
    if allowed_audiences
        .iter()
        .any(|audience| audience == "platform")
    {
        return "platform".to_string();
    }
    if profile.eq_ignore_ascii_case("control_v1") {
        return "control".to_string();
    }
    if profile.eq_ignore_ascii_case("platform_v1") {
        return "platform".to_string();
    }
    "public".to_string()
}

fn policy_names_from_profile(profile: &str, surface: &str) -> (String, String) {
    match (surface, profile) {
        ("control", _) => (
            "user_control_v1".to_string(),
            "client_control_medium".to_string(),
        ),
        ("platform", _) => (
            "user_platform_v1".to_string(),
            "client_platform_medium".to_string(),
        ),
        (_, "platform_v1") => (
            "user_platform_v1".to_string(),
            "client_platform_medium".to_string(),
        ),
        (_, "control_v1") => (
            "user_control_v1".to_string(),
            "client_control_medium".to_string(),
        ),
        _ => (
            "user_public_v1".to_string(),
            "client_mobile_prod_high".to_string(),
        ),
    }
}

fn client_type_from_proto(value: i32) -> Result<String, Status> {
    match ClientType::try_from(value).unwrap_or(ClientType::Unspecified) {
        ClientType::Public => Ok("public".to_string()),
        ClientType::Confidential => Ok("confidential".to_string()),
        ClientType::Unspecified => Err(Status::invalid_argument("client_type is required")),
    }
}

fn client_type_to_proto(value: &str) -> i32 {
    if value.eq_ignore_ascii_case("confidential") {
        ClientType::Confidential as i32
    } else {
        ClientType::Public as i32
    }
}

fn status_from_proto(value: i32) -> Result<String, Status> {
    match ClientStatus::try_from(value).unwrap_or(ClientStatus::Unspecified) {
        ClientStatus::Active => Ok("active".to_string()),
        ClientStatus::Disabled | ClientStatus::Suspended => Ok("suspended".to_string()),
        ClientStatus::Deprecated | ClientStatus::Revoked => Ok("revoked".to_string()),
        ClientStatus::Unspecified => Ok("active".to_string()),
    }
}

fn status_to_proto(value: &str) -> i32 {
    match value {
        "active" => ClientStatus::Active as i32,
        "suspended" => ClientStatus::Suspended as i32,
        "revoked" => ClientStatus::Revoked as i32,
        _ => ClientStatus::Unspecified as i32,
    }
}

fn environment_from_proto(value: i32) -> Result<String, Status> {
    match ClientEnvironment::try_from(value).unwrap_or(ClientEnvironment::Unspecified) {
        ClientEnvironment::Dev => Ok("dev".to_string()),
        ClientEnvironment::Staging => Ok("staging".to_string()),
        ClientEnvironment::Prod => Ok("prod".to_string()),
        ClientEnvironment::Unspecified => Err(Status::invalid_argument("environment is required")),
    }
}

fn environment_to_proto(value: &str) -> i32 {
    match value {
        "dev" => ClientEnvironment::Dev as i32,
        "staging" => ClientEnvironment::Staging as i32,
        "prod" => ClientEnvironment::Prod as i32,
        _ => ClientEnvironment::Unspecified as i32,
    }
}

fn map_client_row(row: sqlx::postgres::PgRow) -> Result<DbClientRecord, Status> {
    Ok(DbClientRecord {
        id: row
            .try_get("id")
            .map_err(|err| Status::internal(format!("decode client id failed: {err}")))?,
        client_id: row
            .try_get("client_id")
            .map_err(|err| Status::internal(format!("decode client_id failed: {err}")))?,
        client_number: row
            .try_get::<i64, _>("client_number")
            .map_err(|err| Status::internal(format!("decode client_number failed: {err}")))?,
        client_ref: row
            .try_get("client_ref")
            .map_err(|err| Status::internal(format!("decode client_ref failed: {err}")))?,
        display_name: row
            .try_get("display_name")
            .map_err(|err| Status::internal(format!("decode display_name failed: {err}")))?,
        description: row
            .try_get("description")
            .map_err(|err| Status::internal(format!("decode description failed: {err}")))?,
        platform: row
            .try_get("platform")
            .map_err(|err| Status::internal(format!("decode platform failed: {err}")))?,
        surface: row
            .try_get("surface")
            .map_err(|err| Status::internal(format!("decode surface failed: {err}")))?,
        environment: row
            .try_get("environment")
            .map_err(|err| Status::internal(format!("decode environment failed: {err}")))?,
        client_type: row
            .try_get("client_type")
            .map_err(|err| Status::internal(format!("decode client_type failed: {err}")))?,
        status: row
            .try_get("status")
            .map_err(|err| Status::internal(format!("decode status failed: {err}")))?,
        allowed_audiences: row
            .try_get("allowed_audiences")
            .map_err(|err| Status::internal(format!("decode allowed_audiences failed: {err}")))?,
        allowed_origins: row
            .try_get("allowed_origins")
            .map_err(|err| Status::internal(format!("decode allowed_origins failed: {err}")))?,
        ip_allowlist: row
            .try_get("ip_allowlist")
            .map_err(|err| Status::internal(format!("decode ip_allowlist failed: {err}")))?,
        require_mtls: row
            .try_get("require_mtls")
            .map_err(|err| Status::internal(format!("decode require_mtls failed: {err}")))?,
        is_version_enforced: row
            .try_get("is_version_enforced")
            .map_err(|err| Status::internal(format!("decode is_version_enforced failed: {err}")))?,
        min_app_version: row
            .try_get("min_app_version")
            .map_err(|err| Status::internal(format!("decode min_app_version failed: {err}")))?,
        max_app_version: row
            .try_get("max_app_version")
            .map_err(|err| Status::internal(format!("decode max_app_version failed: {err}")))?,
        user_rate_policy: row
            .try_get("user_rate_policy")
            .map_err(|err| Status::internal(format!("decode user_rate_policy failed: {err}")))?,
        client_safety_policy: row.try_get("client_safety_policy").map_err(|err| {
            Status::internal(format!("decode client_safety_policy failed: {err}"))
        })?,
        rate_limit_profile: row
            .try_get("rate_limit_profile")
            .map_err(|err| Status::internal(format!("decode rate_limit_profile failed: {err}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|err| Status::internal(format!("decode created_at failed: {err}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|err| Status::internal(format!("decode updated_at failed: {err}")))?,
        last_used_at: row
            .try_get("last_used_at")
            .map_err(|err| Status::internal(format!("decode last_used_at failed: {err}")))?,
        created_by: row
            .try_get("created_by")
            .map_err(|err| Status::internal(format!("decode created_by failed: {err}")))?,
        updated_by: row
            .try_get("updated_by")
            .map_err(|err| Status::internal(format!("decode updated_by failed: {err}")))?,
        notes: row
            .try_get("notes")
            .map_err(|err| Status::internal(format!("decode notes failed: {err}")))?,
        has_active_secret: row
            .try_get("has_active_secret")
            .map_err(|err| Status::internal(format!("decode has_active_secret failed: {err}")))?,
    })
}

fn api_client_from_record(record: &DbClientRecord) -> ApiClient {
    ApiClient {
        id: record.id.clone(),
        client_id: record.client_id.clone(),
        client_number: record.client_number.max(0) as u64,
        client_ref: record.client_ref.clone(),
        display_name: record.display_name.clone(),
        description: record.description.clone(),
        platform: record.platform.clone(),
        surface: record.surface.clone(),
        environment: record.environment.clone(),
        client_type: client_type_to_proto(&record.client_type),
        status: status_to_proto(&record.status),
        allowed_audiences: record.allowed_audiences.clone(),
        allowed_origins: record.allowed_origins.clone(),
        ip_allowlist: record.ip_allowlist.clone(),
        require_mtls: record.require_mtls,
        is_version_enforced: record.is_version_enforced,
        min_app_version: record.min_app_version.clone(),
        max_app_version: record.max_app_version.clone(),
        user_rate_policy: record.user_rate_policy.clone(),
        client_safety_policy: record.client_safety_policy.clone(),
        created_at: record.created_at.timestamp(),
        updated_at: record.updated_at.timestamp(),
        last_used_at: record
            .last_used_at
            .map(|value| value.timestamp())
            .unwrap_or_default(),
        created_by: record.created_by.clone(),
        updated_by: record.updated_by.clone(),
        notes: record.notes.clone(),
        has_active_secret: record.has_active_secret,
    }
}

async fn build_client_policy(db: &PgPool, record: &DbClientRecord) -> Result<ClientPolicy, Status> {
    let (default_user_rpm, default_client_rpm, route_overrides) =
        resolve_policy_limits(db, record).await?;

    Ok(ClientPolicy {
        client_id: record.client_id.clone(),
        client_type: client_type_to_proto(&record.client_type),
        status: status_to_proto(&record.status),
        environment: environment_to_proto(&record.environment),
        allowed_audiences: record.allowed_audiences.clone(),
        rate_limit_profile: record.rate_limit_profile.clone(),
        min_app_version: record.min_app_version.clone(),
        default_user_rpm,
        default_client_rpm,
        route_overrides,
        surface: record.surface.clone(),
        is_version_enforced: record.is_version_enforced,
        max_app_version: record.max_app_version.clone(),
        allowed_origins: record.allowed_origins.clone(),
        ip_allowlist: record.ip_allowlist.clone(),
        require_mtls: record.require_mtls,
        user_rate_policy: record.user_rate_policy.clone(),
        client_safety_policy: record.client_safety_policy.clone(),
        has_active_secret: record.has_active_secret,
    })
}

async fn resolve_policy_limits(
    db: &PgPool,
    record: &DbClientRecord,
) -> Result<(u32, u32, Vec<RateLimitRouteOverride>), Status> {
    let rows = sqlx::query(
        "SELECT scope, route_group, COALESCE(requests_per_min, 0) AS requests_per_min
         FROM api_clients_app.rate_limit_policies
         WHERE enabled = TRUE
           AND ((scope = 'user' AND policy_name = $1) OR (scope = 'client' AND policy_name = $2))",
    )
    .bind(&record.user_rate_policy)
    .bind(&record.client_safety_policy)
    .fetch_all(db)
    .await
    .map_err(|err| map_db_error(err, "resolve policy limits failed"))?;

    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let requests_per_min: i32 = row
            .try_get("requests_per_min")
            .map_err(|err| Status::internal(format!("decode requests_per_min failed: {err}")))?;
        parsed.push(PolicyRule {
            scope: row
                .try_get::<String, _>("scope")
                .map_err(|err| Status::internal(format!("decode scope failed: {err}")))?,
            route_group: row
                .try_get::<String, _>("route_group")
                .map_err(|err| Status::internal(format!("decode route_group failed: {err}")))?,
            requests_per_min: requests_per_min.max(0) as u32,
        });
    }

    let (fallback_user_rpm, fallback_client_rpm) =
        fallback_limits_from_profile(record.rate_limit_profile.as_str());

    let mut user_default = fallback_user_rpm;
    let mut client_default = fallback_client_rpm;
    let mut route_groups = BTreeMap::<String, (u32, u32)>::new();

    for rule in parsed {
        if !rule.route_group.eq_ignore_ascii_case("default") {
            let entry = route_groups
                .entry(rule.route_group.to_ascii_lowercase())
                .or_insert((0, 0));
            if rule.scope.eq_ignore_ascii_case("user") {
                entry.0 = rule.requests_per_min;
            } else if rule.scope.eq_ignore_ascii_case("client") {
                entry.1 = rule.requests_per_min;
            }
            continue;
        }

        if rule.scope.eq_ignore_ascii_case("user") {
            user_default = rule.requests_per_min;
        } else if rule.scope.eq_ignore_ascii_case("client") {
            client_default = rule.requests_per_min;
        }
    }

    let route_overrides = route_groups
        .into_iter()
        .map(
            |(route_group, (user_rpm, client_rpm))| RateLimitRouteOverride {
                route_id: format!("group:{route_group}"),
                user_rpm,
                client_rpm,
                enabled: true,
            },
        )
        .collect::<Vec<_>>();

    Ok((user_default, client_default, route_overrides))
}

fn fallback_limits_from_profile(profile_name: &str) -> (u32, u32) {
    match profile_name {
        "platform_v1" => (80, 3000),
        "control_v1" => (60, 1200),
        _ => (120, 10000),
    }
}

async fn fetch_client_by_client_id(
    db: &PgPool,
    client_id: &str,
) -> Result<Option<DbClientRecord>, Status> {
    let sql = format!(
        "SELECT {columns}
         FROM api_clients_app.api_clients c
         WHERE c.client_id = $1
         LIMIT 1",
        columns = CLIENT_SELECT_COLUMNS
    );

    let row = sqlx::query(&sql)
        .bind(client_id)
        .fetch_optional(db)
        .await
        .map_err(|err| map_db_error(err, "load client by client_id failed"))?;

    row.map(map_client_row).transpose()
}

async fn fetch_client_by_id(db: &PgPool, id: &str) -> Result<Option<DbClientRecord>, Status> {
    let sql = format!(
        "SELECT {columns}
         FROM api_clients_app.api_clients c
         WHERE c.id = $1::UUID
         LIMIT 1",
        columns = CLIENT_SELECT_COLUMNS
    );

    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|err| map_db_error(err, "load client by id failed"))?;

    row.map(map_client_row).transpose()
}

async fn fetch_client_by_ref(
    db: &PgPool,
    client_ref: &str,
) -> Result<Option<DbClientRecord>, Status> {
    let sql = format!(
        "SELECT {columns}
         FROM api_clients_app.api_clients c
         WHERE c.client_ref = $1
         LIMIT 1",
        columns = CLIENT_SELECT_COLUMNS
    );

    let row = sqlx::query(&sql)
        .bind(client_ref)
        .fetch_optional(db)
        .await
        .map_err(|err| map_db_error(err, "load client by ref failed"))?;

    row.map(map_client_row).transpose()
}

async fn insert_client_event(
    db: &PgPool,
    client_id: &str,
    event_type: &str,
    actor_user_id: Option<&str>,
    payload: serde_json::Value,
) -> Result<(), Status> {
    sqlx::query(
        "INSERT INTO api_clients_app.api_client_events (
            client_pk,
            event_type,
            actor_user_id,
            payload_json,
            created_at
         ) VALUES (
            $1::UUID,
            $2,
            $3::UUID,
            $4::JSONB,
            NOW()
         )",
    )
    .bind(client_id)
    .bind(event_type)
    .bind(actor_user_id.and_then(parse_uuid))
    .bind(payload)
    .execute(db)
    .await
    .map_err(|err| map_db_error(err, "insert client event failed"))?;

    Ok(())
}

async fn publish_api_client_changed(
    state: &AppState,
    client_id: &str,
    event_type: &str,
) -> Result<(), Status> {
    let payload = json!({
        "client_id": client_id,
        "event_type": event_type,
        "occurred_at": Utc::now().timestamp(),
    })
    .to_string();

    let Some(nats) = &state.nats else {
        tracing::warn!(
            client_id = client_id,
            event_type = event_type,
            "skipping api client invalidation publish because NATS is unavailable"
        );
        return Ok(());
    };

    nats.publish(NATS_API_CLIENT_CHANGED_SUBJECT, payload.into())
        .await
        .map_err(|err| Status::internal(format!("publish api_client.changed failed: {err}")))
}

fn map_db_error(err: sqlx::Error, context: &str) -> Status {
    if let sqlx::Error::Database(db_err) = &err {
        if db_err.code().as_deref() == Some("23505") {
            return Status::already_exists(format!("{context}: duplicate key"));
        }
    }
    Status::internal(format!("{context}: {err}"))
}

fn generate_secret() -> String {
    let raw = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect::<String>()
        .to_ascii_uppercase();

    let mut parts = Vec::new();
    let mut start = 0;
    while start < raw.len() {
        let end = (start + 6).min(raw.len());
        parts.push(raw[start..end].to_string());
        start = end;
    }

    parts.join("-")
}

fn hash_secret(secret: &str) -> Result<String, Status> {
    let salt = SaltString::generate(&mut OsRng);
    argon2id()?
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| Status::internal(format!("secret hashing failed: {err}")))
}

fn verify_secret(secret: &str, secret_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(secret_hash) else {
        return false;
    };
    let Ok(argon2) = argon2id() else {
        return false;
    };
    argon2
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_ok()
}

fn argon2id() -> Result<Argon2<'static>, Status> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|err| Status::internal(format!("argon2 params error: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn is_version_at_least(provided: Option<&str>, minimum: Option<&str>) -> bool {
    let Some(minimum) = minimum else {
        return true;
    };
    let Some(provided) = provided else {
        return false;
    };

    let provided_parts = parse_version_parts(provided);
    let minimum_parts = parse_version_parts(minimum);
    let max_len = provided_parts.len().max(minimum_parts.len());

    for idx in 0..max_len {
        let p = *provided_parts.get(idx).unwrap_or(&0);
        let m = *minimum_parts.get(idx).unwrap_or(&0);
        if p > m {
            return true;
        }
        if p < m {
            return false;
        }
    }

    true
}

fn is_version_at_most(provided: Option<&str>, maximum: Option<&str>) -> bool {
    let Some(maximum) = maximum else {
        return true;
    };
    let Some(provided) = provided else {
        return false;
    };

    let provided_parts = parse_version_parts(provided);
    let maximum_parts = parse_version_parts(maximum);
    let max_len = provided_parts.len().max(maximum_parts.len());

    for idx in 0..max_len {
        let p = *provided_parts.get(idx).unwrap_or(&0);
        let m = *maximum_parts.get(idx).unwrap_or(&0);
        if p < m {
            return true;
        }
        if p > m {
            return false;
        }
    }

    true
}

fn parse_version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|chunk| chunk.trim().parse::<u64>().unwrap_or(0))
        .collect()
}

#[tokio::main]
async fn main() {
    init_tracing("api-clients-service");

    let grpc_addr = env::var("API_CLIENTS_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50058".to_string())
        .parse::<SocketAddr>()
        .expect("invalid API_CLIENTS_GRPC_BIND_ADDR");

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://yugabyte@127.0.0.1:5433/wildon".to_string());
    let max_connections = env::var("API_CLIENTS_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(10);
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let require_invalidation = env::var("API_CLIENTS_REQUIRE_NATS_INVALIDATION")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    let db = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await
        .expect("failed to connect to api-clients database");
    let nats = match async_nats::connect(&nats_url).await {
        Ok(client) => Some(client),
        Err(err) => {
            if require_invalidation {
                panic!("failed to connect to nats for api-clients invalidation events: {err}");
            }
            tracing::error!(
                error = %err,
                "failed to connect to nats for api-clients invalidation events; continuing without invalidation publish"
            );
            None
        }
    };

    let grpc = ApiClientsGrpc {
        state: AppState::new(db, nats),
        internal_auth: InternalAuthPolicy::from_env("api-clients-service"),
    };

    tracing::info!(address = %grpc_addr, "api-clients grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ApiClientsServiceServer<ApiClientsGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply api-clients grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(ApiClientsServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("api-clients grpc server failed");
}
