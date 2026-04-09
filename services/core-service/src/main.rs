#![allow(dead_code)]

mod domain;
mod modules;
mod routes;
mod state;

use crate::{
    modules::{ai, jobs, notifications},
    state::{AppState, FeatureFlagState},
};
use chrono::Utc;
use config::grpc::{
    authorize_internal_request, connect_channel, inject_internal_metadata, load_server_tls_config,
    metadata_value, InternalAuthPolicy,
};
use contracts::wildon::core::v1::{
    core_service_server::{CoreService, CoreServiceServer},
    EnqueueJobRequest, EnqueueJobResponse, FeatureFlag, GenerateAiTextRequest,
    GenerateAiTextResponse, GetFeatureFlagRequest, GetFeatureFlagResponse, GetJobRequest,
    GetJobResponse, HealthRequest, HealthResponse, IngestBillingWebhookRequest,
    IngestBillingWebhookResponse, JobRecord, NotificationChannel as ProtoNotificationChannel,
    RecordUsageRequest, RecordUsageResponse, ResolveEntitlementRequest, ResolveEntitlementResponse,
    SendNotificationRequest, SendNotificationResponse, SetFeatureFlagRequest,
    SetFeatureFlagResponse,
};
use observability::init_tracing;
use provider_clients::{NotificationChannel, ProviderError};
use std::{env, net::SocketAddr, time::Instant};
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct CoreGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

impl CoreGrpc {
    fn to_feature_flag_proto(flag: &FeatureFlagState) -> FeatureFlag {
        FeatureFlag {
            key: flag.key.clone(),
            enabled: flag.enabled,
            updated_by: flag.updated_by.clone(),
            reason: flag.reason.clone(),
            updated_at: flag.updated_at,
        }
    }

    fn to_job_proto(job: &jobs::JobRecordData) -> JobRecord {
        JobRecord {
            job_id: job.job_id.clone(),
            job_type: job.job_type.clone(),
            payload_json: job.payload_json.clone(),
            status: job.status as i32,
            idempotency_key: job.idempotency_key.clone(),
            error_message: job.error_message.clone(),
            created_at: job.created_at,
            updated_at: job.updated_at,
        }
    }
}

#[tonic::async_trait]
impl CoreService for CoreGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("missing")
            .to_string();

        let status = self.state.service_states.overall_status().await;

        Ok(Response::new(HealthResponse {
            status: status.to_string(),
            request_id,
        }))
    }

    async fn set_feature_flag(
        &self,
        request: Request<SetFeatureFlagRequest>,
    ) -> Result<Response<SetFeatureFlagResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        if payload.key.trim().is_empty() {
            return Err(Status::invalid_argument("key is required"));
        }

        let key = payload.key.trim().to_string();
        let updated_at = Utc::now().timestamp();
        let flag = FeatureFlagState {
            key: key.clone(),
            enabled: payload.enabled,
            updated_by: if payload.updated_by.trim().is_empty() {
                "control-service".to_string()
            } else {
                payload.updated_by
            },
            reason: payload.reason,
            updated_at,
        };

        let mut feature_flags = self.state.feature_flags.lock().await;
        feature_flags.insert(key.clone(), flag.clone());

        Ok(Response::new(SetFeatureFlagResponse {
            flag: Some(Self::to_feature_flag_proto(&flag)),
        }))
    }

    async fn resolve_entitlement(
        &self,
        request: Request<ResolveEntitlementRequest>,
    ) -> Result<Response<ResolveEntitlementResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "public-service",
                "platform-service",
                "control-service",
            ],
        )?;

        let payload = request.into_inner();
        let response = {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut billing_request = Request::new(
                contracts::wildon::billing::v1::ResolveEntitlementRequest {
                    user_id: payload.user_id,
                    feature_key: payload.feature_key,
                },
            );
            inject_internal_metadata(
                &mut billing_request,
                "core-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            billing_client
                .resolve_entitlement(billing_request)
                .await
                .map_err(|err| Status::internal(format!("billing entitlement error: {err}")))?
                .into_inner()
        };

        Ok(Response::new(ResolveEntitlementResponse {
            allowed: response.allowed,
            plan: response.plan,
            reason: response.reason,
        }))
    }

    async fn record_usage(
        &self,
        request: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "public-service",
                "platform-service",
                "control-service",
            ],
        )?;

        let payload = request.into_inner();
        let response = {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut usage_request =
                Request::new(contracts::wildon::billing::v1::RecordUsageRequest {
                    user_id: payload.user_id,
                    metric: payload.metric,
                    amount: payload.amount,
                });
            inject_internal_metadata(
                &mut usage_request,
                "core-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            billing_client
                .record_usage(usage_request)
                .await
                .map_err(|err| Status::internal(format!("billing usage error: {err}")))?
                .into_inner()
        };

        Ok(Response::new(RecordUsageResponse {
            total: response.total,
        }))
    }

    async fn ingest_billing_webhook(
        &self,
        request: Request<IngestBillingWebhookRequest>,
    ) -> Result<Response<IngestBillingWebhookResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "billing-service", "control-service"],
        )?;

        let payload = request.into_inner();
        let response = {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut webhook_request = Request::new(
                contracts::wildon::billing::v1::IngestBillingWebhookRequest {
                    provider: payload.provider,
                    event_id: payload.event_id,
                    user_id: payload.user_id,
                    amount_cents: payload.amount_cents,
                    currency: payload.currency,
                    signature: payload.signature,
                    payload_json: payload.payload_json,
                },
            );
            inject_internal_metadata(
                &mut webhook_request,
                "core-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            billing_client
                .ingest_billing_webhook(webhook_request)
                .await
                .map_err(|err| Status::internal(format!("billing webhook error: {err}")))?
                .into_inner()
        };

        Ok(Response::new(IngestBillingWebhookResponse {
            accepted: response.accepted,
            duplicate: response.duplicate,
            invoice_id: response.invoice_id,
            reason: response.reason,
        }))
    }

    async fn get_feature_flag(
        &self,
        request: Request<GetFeatureFlagRequest>,
    ) -> Result<Response<GetFeatureFlagResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let key = request.into_inner().key;
        if key.trim().is_empty() {
            return Err(Status::invalid_argument("key is required"));
        }

        let feature_flags = self.state.feature_flags.lock().await;
        let flag = feature_flags
            .get(key.trim())
            .ok_or_else(|| Status::not_found("feature flag not found"))?;

        Ok(Response::new(GetFeatureFlagResponse {
            flag: Some(Self::to_feature_flag_proto(flag)),
        }))
    }

    async fn send_notification(
        &self,
        request: Request<SendNotificationRequest>,
    ) -> Result<Response<SendNotificationResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty()
            || payload.destination.trim().is_empty()
            || payload.message.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "user_id, destination, and message are required",
            ));
        }

        let channel = match ProtoNotificationChannel::try_from(payload.channel)
            .unwrap_or(ProtoNotificationChannel::Unspecified)
        {
            ProtoNotificationChannel::Email => NotificationChannel::Email,
            ProtoNotificationChannel::Sms => NotificationChannel::Sms,
            ProtoNotificationChannel::Push => NotificationChannel::Push,
            ProtoNotificationChannel::Unspecified => {
                return Err(Status::invalid_argument("channel is required"));
            }
        };

        let outcome = notifications::deliver_with_failover(
            channel,
            &payload.destination,
            &payload.subject,
            &payload.message,
            self.state.sendgrid.as_ref(),
            self.state.twilio.as_ref(),
            self.state.fcm.as_ref(),
        );

        Ok(Response::new(SendNotificationResponse {
            delivered: outcome.delivered,
            provider_used: outcome.provider_used,
            attempted_providers: outcome.attempted_providers,
            failure_reason: outcome.failure_reason,
        }))
    }

    async fn generate_ai_text(
        &self,
        request: Request<GenerateAiTextRequest>,
    ) -> Result<Response<GenerateAiTextResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "public-service",
                "platform-service",
                "control-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() || payload.prompt.trim().is_empty() {
            return Err(Status::invalid_argument("user_id and prompt are required"));
        }

        let max_tokens = if payload.max_tokens == 0 {
            128
        } else {
            payload.max_tokens
        };

        let completion =
            match ai::generate_text(self.state.openai.as_ref(), &payload.prompt, max_tokens) {
                Ok(result) => result,
                Err(ProviderError::Misconfigured(_)) => provider_clients::AiCompletion {
                    text: format!(
                        "local-fallback: {}",
                        payload.prompt.chars().take(80).collect::<String>()
                    ),
                    prompt_tokens: std::cmp::max((payload.prompt.len() / 4) as u32, 1),
                    completion_tokens: 32,
                    cost_micros: 0,
                    model: "local-fallback".to_string(),
                },
                Err(err) => return Err(Status::internal(format!("ai generation failed: {err}"))),
            };

        Ok(Response::new(GenerateAiTextResponse {
            text: completion.text,
            prompt_tokens: completion.prompt_tokens,
            completion_tokens: completion.completion_tokens,
            cost_micros: completion.cost_micros,
            model: completion.model,
        }))
    }

    async fn enqueue_job(
        &self,
        request: Request<EnqueueJobRequest>,
    ) -> Result<Response<EnqueueJobResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let payload = request.into_inner();
        if payload.job_type.trim().is_empty() {
            return Err(Status::invalid_argument("job_type is required"));
        }

        let idempotency_key = if payload.idempotency_key.trim().is_empty() {
            format!("auto-{}", Uuid::new_v4())
        } else {
            payload.idempotency_key
        };

        {
            let idempotency = self.state.job_idempotency.lock().await;
            if let Some(existing_id) = idempotency.get(&idempotency_key) {
                let jobs = self.state.jobs.lock().await;
                let existing = jobs
                    .get(existing_id)
                    .ok_or_else(|| Status::internal("idempotency map points to missing job"))?;
                return Ok(Response::new(EnqueueJobResponse {
                    job: Some(Self::to_job_proto(existing)),
                    duplicate: true,
                }));
            }
        }

        let mut job =
            jobs::JobRecordData::new(&payload.job_type, &payload.payload_json, &idempotency_key);
        job.status = contracts::wildon::core::v1::JobStatus::Done;
        job.updated_at = Utc::now().timestamp();

        {
            let mut jobs_map = self.state.jobs.lock().await;
            jobs_map.insert(job.job_id.clone(), job.clone());
        }
        {
            let mut idempotency = self.state.job_idempotency.lock().await;
            idempotency.insert(idempotency_key, job.job_id.clone());
        }

        Ok(Response::new(EnqueueJobResponse {
            job: Some(Self::to_job_proto(&job)),
            duplicate: false,
        }))
    }

    async fn get_job(
        &self,
        request: Request<GetJobRequest>,
    ) -> Result<Response<GetJobResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let job_id = request.into_inner().job_id;
        if job_id.trim().is_empty() {
            return Err(Status::invalid_argument("job_id is required"));
        }

        let jobs = self.state.jobs.lock().await;
        let job = jobs
            .get(job_id.trim())
            .ok_or_else(|| Status::not_found("job not found"))?;

        Ok(Response::new(GetJobResponse {
            job: Some(Self::to_job_proto(job)),
        }))
    }
}

#[tokio::main]
async fn main() {
    init_tracing("core-service");

    let grpc_addr = env::var("CORE_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50053".to_string())
        .parse::<SocketAddr>()
        .expect("invalid CORE_GRPC_BIND_ADDR");
    let storage_endpoint =
        env::var("STORAGE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());
    let export_endpoint =
        env::var("EXPORT_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50056".to_string());
    let billing_endpoint =
        env::var("BILLING_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50059".to_string());
    let storage_client =
        storage_sdk::StorageSdkClient::connect_as(storage_endpoint, "core-service")
            .await
            .expect("failed to connect storage grpc endpoint");
    let export_client = export_sdk::ExportSdkClient::connect_as(export_endpoint, "core-service")
        .await
        .expect("failed to connect export grpc endpoint");
    let billing_channel = connect_channel(&billing_endpoint, "billing-service")
        .await
        .expect("failed to connect billing grpc endpoint");
    let billing_client =
        contracts::wildon::billing::v1::billing_service_client::BillingServiceClient::new(
            billing_channel,
        );
    let state = AppState::new(storage_client, export_client, billing_client);

    // Spawn background dependency health probe
    {
        let probe_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                probe_dependencies(&probe_state).await;
            }
        });
    }

    let grpc = CoreGrpc {
        state,
        internal_auth: InternalAuthPolicy::from_env("core-service"),
    };

    tracing::info!(address = %grpc_addr, "core grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<CoreServiceServer<CoreGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply core grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(CoreServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("core grpc server failed");
}

async fn probe_dependencies(state: &AppState) {
    use modules::states::{now_unix_seconds, DependencyHealth};

    // Probe storage-service
    {
        let t = Instant::now();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            state.storage_client.lock().await.health(None).await
        })
        .await;
        let latency_ms = t.elapsed().as_millis() as i64;
        let health = match result {
            Ok(Ok(_)) => DependencyHealth {
                name: "storage-service".to_string(),
                status: "UP".to_string(),
                latency_ms,
                last_ok_at: Some(now_unix_seconds()),
                error: None,
            },
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "storage-service health probe failed");
                DependencyHealth {
                    name: "storage-service".to_string(),
                    status: "DOWN".to_string(),
                    latency_ms,
                    last_ok_at: None,
                    error: Some(e.to_string()),
                }
            }
            Err(_) => {
                tracing::warn!("storage-service health probe timed out");
                DependencyHealth {
                    name: "storage-service".to_string(),
                    status: "DOWN".to_string(),
                    latency_ms,
                    last_ok_at: None,
                    error: Some("health probe timed out".to_string()),
                }
            }
        };
        state.service_states.set("storage-service", health).await;
    }

    // Probe export-service
    {
        let t = Instant::now();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            state.export_client.lock().await.health(None).await
        })
        .await;
        let latency_ms = t.elapsed().as_millis() as i64;
        let health = match result {
            Ok(Ok(_)) => DependencyHealth {
                name: "export-service".to_string(),
                status: "UP".to_string(),
                latency_ms,
                last_ok_at: Some(now_unix_seconds()),
                error: None,
            },
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "export-service health probe failed");
                DependencyHealth {
                    name: "export-service".to_string(),
                    status: "DOWN".to_string(),
                    latency_ms,
                    last_ok_at: None,
                    error: Some(e.to_string()),
                }
            }
            Err(_) => {
                tracing::warn!("export-service health probe timed out");
                DependencyHealth {
                    name: "export-service".to_string(),
                    status: "DOWN".to_string(),
                    latency_ms,
                    last_ok_at: None,
                    error: Some("health probe timed out".to_string()),
                }
            }
        };
        state.service_states.set("export-service", health).await;
    }
}
