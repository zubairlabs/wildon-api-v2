#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::{
    modules::{delivery, generators, jobs},
    state::{AppState, ExportJobRecord},
};
use chrono::Utc;
use config::grpc::{authorize_internal_request, load_server_tls_config, InternalAuthPolicy};
use contracts::wildon::export::v1::{
    export_service_server::{ExportService, ExportServiceServer},
    CreateExportJobRequest, CreateExportJobResponse, DownloadExportRequest, DownloadExportResponse,
    ExportJobStatus, GetExportJobRequest, GetExportJobResponse, HealthRequest, HealthResponse,
    RetryExportJobRequest, RetryExportJobResponse,
};
use contracts::wildon::storage::v1::{
    CompleteUploadRequest, CreateDownloadUrlRequest, GetObjectMetadataRequest, ObjectStatus,
};
use observability::init_tracing;
use std::{collections::HashMap, env, net::SocketAddr};
use tokio::sync::mpsc;
use tonic::{Code, Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct ExportGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

#[tonic::async_trait]
impl ExportService for ExportGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "core-service",
                "gateway-service",
                "control-service",
            ],
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

    async fn create_export_job(
        &self,
        request: Request<CreateExportJobRequest>,
    ) -> Result<Response<CreateExportJobResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["public-service", "core-service", "gateway-service"],
        )?;

        let payload = request.into_inner();
        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let format = jobs::parse_export_format(&payload.format)
            .map_err(|message| Status::invalid_argument(message.to_string()))?;
        let export_kind = if payload.export_kind.trim().is_empty() {
            "profile".to_string()
        } else {
            payload.export_kind
        };
        let idempotency_key = if payload.idempotency_key.trim().is_empty() {
            format!("auto-{}", Uuid::new_v4())
        } else {
            payload.idempotency_key
        };

        if let Some(existing_job_id) = {
            let idempotency = self.state.idempotency.lock().await;
            idempotency.get(&idempotency_key).cloned()
        } {
            let jobs = self.state.jobs.lock().await;
            let existing = jobs
                .get(&existing_job_id)
                .ok_or_else(|| Status::internal("idempotency index points to missing job"))?;
            return Ok(Response::new(CreateExportJobResponse {
                job: Some(existing.to_proto()),
                duplicate: true,
            }));
        }

        let now = Utc::now().timestamp();
        let job_id = Uuid::new_v4().to_string();
        let artifact_key = delivery::artifact_key(&payload.user_id, &job_id, &format);
        let job = ExportJobRecord {
            job_id: job_id.clone(),
            user_id: payload.user_id,
            export_kind,
            format,
            status: ExportJobStatus::Queued,
            artifact_key,
            idempotency_key: idempotency_key.clone(),
            error_message: String::new(),
            created_at: now,
            updated_at: now,
            completed_at: 0,
        };

        {
            let mut jobs = self.state.jobs.lock().await;
            jobs.insert(job_id.clone(), job.clone());
        }
        {
            let mut idempotency = self.state.idempotency.lock().await;
            idempotency.insert(idempotency_key, job_id.clone());
        }
        self.state
            .queue_tx
            .send(job_id)
            .await
            .map_err(|_| Status::internal("export worker queue unavailable"))?;

        Ok(Response::new(CreateExportJobResponse {
            job: Some(job.to_proto()),
            duplicate: false,
        }))
    }

    async fn get_export_job(
        &self,
        request: Request<GetExportJobRequest>,
    ) -> Result<Response<GetExportJobResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "core-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let job_id = request.into_inner().job_id;
        if job_id.is_empty() {
            return Err(Status::invalid_argument("job_id is required"));
        }

        let jobs = self.state.jobs.lock().await;
        let job = jobs
            .get(&job_id)
            .ok_or_else(|| Status::not_found("export job not found"))?;

        Ok(Response::new(GetExportJobResponse {
            job: Some(job.to_proto()),
        }))
    }

    async fn download_export(
        &self,
        request: Request<DownloadExportRequest>,
    ) -> Result<Response<DownloadExportResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "core-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.job_id.is_empty() {
            return Err(Status::invalid_argument("job_id is required"));
        }

        let job = {
            let jobs = self.state.jobs.lock().await;
            jobs.get(&payload.job_id)
                .cloned()
                .ok_or_else(|| Status::not_found("export job not found"))?
        };

        if !matches!(job.status, ExportJobStatus::Completed) {
            return Err(Status::failed_precondition(
                "export is not completed and cannot be downloaded yet",
            ));
        }

        let mut storage_client = self.state.storage_client.lock().await;
        let storage_response = storage_client
            .create_download_url(CreateDownloadUrlRequest {
                object_key: job.artifact_key.clone(),
                expires_in_seconds: payload.expires_in_seconds,
            })
            .await
            .map_err(|err| Status::internal(format!("storage download url error: {err}")))?;

        Ok(Response::new(DownloadExportResponse {
            job_id: payload.job_id,
            artifact_key: job.artifact_key,
            download_url: storage_response.download_url,
            expires_at: storage_response.expires_at,
        }))
    }

    async fn retry_export_job(
        &self,
        request: Request<RetryExportJobRequest>,
    ) -> Result<Response<RetryExportJobResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "public-service",
                "core-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let job_id = request.into_inner().job_id;
        if job_id.is_empty() {
            return Err(Status::invalid_argument("job_id is required"));
        }

        let job = {
            let mut jobs = self.state.jobs.lock().await;
            let job = jobs
                .get_mut(&job_id)
                .ok_or_else(|| Status::not_found("export job not found"))?;

            if !matches!(job.status, ExportJobStatus::Completed) {
                job.status = ExportJobStatus::Queued;
                job.error_message.clear();
                job.updated_at = Utc::now().timestamp();
            }
            job.clone()
        };

        if !matches!(job.status, ExportJobStatus::Completed) {
            self.state
                .queue_tx
                .send(job_id)
                .await
                .map_err(|_| Status::internal("export worker queue unavailable"))?;
        }

        Ok(Response::new(RetryExportJobResponse {
            job: Some(job.to_proto()),
        }))
    }
}

async fn run_worker(state: AppState, mut queue_rx: mpsc::Receiver<String>) {
    while let Some(job_id) = queue_rx.recv().await {
        process_job(state.clone(), job_id).await;
    }
}

async fn process_job(state: AppState, job_id: String) {
    let job = {
        let mut jobs = state.jobs.lock().await;
        let Some(job) = jobs.get_mut(&job_id) else {
            return;
        };

        if matches!(job.status, ExportJobStatus::Completed) {
            return;
        }

        job.status = ExportJobStatus::Running;
        job.error_message.clear();
        job.updated_at = Utc::now().timestamp();
        job.clone()
    };

    let object_exists = {
        let mut storage_client = state.storage_client.lock().await;
        match storage_client
            .get_object_metadata(GetObjectMetadataRequest {
                object_key: job.artifact_key.clone(),
            })
            .await
        {
            Ok(response) => response
                .metadata
                .map(|metadata| metadata.status == ObjectStatus::Available as i32)
                .unwrap_or(false),
            Err(status) if status.code() == Code::NotFound => false,
            Err(status) => {
                mark_failed(
                    &state,
                    &job.job_id,
                    format!("storage metadata lookup failed: {status}"),
                )
                .await;
                return;
            }
        }
    };

    if object_exists {
        mark_completed(&state, &job.job_id).await;
        return;
    }

    let generated_at = Utc::now().timestamp();
    let csv = generators::csv::render_export_csv(&job.user_id, &job.export_kind, generated_at);
    let content_length = csv.len() as u64;
    let checksum = format!("len-{content_length}");
    let tags = HashMap::from([
        ("export_job_id".to_string(), job.job_id.clone()),
        ("export_kind".to_string(), job.export_kind.clone()),
    ]);

    let complete_result = {
        let mut storage_client = state.storage_client.lock().await;
        storage_client
            .complete_upload(CompleteUploadRequest {
                object_key: job.artifact_key.clone(),
                content_type: "text/csv".to_string(),
                content_length,
                checksum,
                tags,
            })
            .await
    };

    match complete_result {
        Ok(_) => mark_completed(&state, &job.job_id).await,
        Err(status) => {
            mark_failed(
                &state,
                &job.job_id,
                format!("storage complete_upload failed: {status}"),
            )
            .await
        }
    }
}

async fn mark_completed(state: &AppState, job_id: &str) {
    let now = Utc::now().timestamp();
    let mut jobs = state.jobs.lock().await;
    if let Some(job) = jobs.get_mut(job_id) {
        job.status = ExportJobStatus::Completed;
        job.error_message.clear();
        job.updated_at = now;
        job.completed_at = now;
    }
}

async fn mark_failed(state: &AppState, job_id: &str, message: String) {
    let mut jobs = state.jobs.lock().await;
    if let Some(job) = jobs.get_mut(job_id) {
        job.status = ExportJobStatus::Failed;
        job.error_message = message;
        job.updated_at = Utc::now().timestamp();
    }
}

#[tokio::main]
async fn main() {
    init_tracing("export-service");

    let grpc_addr = env::var("EXPORT_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50056".to_string())
        .parse::<SocketAddr>()
        .expect("invalid EXPORT_GRPC_BIND_ADDR");
    let storage_endpoint =
        env::var("STORAGE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());

    let storage_client =
        storage_sdk::StorageSdkClient::connect_as(storage_endpoint.clone(), "export-service")
            .await
            .expect("failed to connect storage grpc endpoint");
    let (queue_tx, queue_rx) = mpsc::channel(256);
    let state = AppState::new(queue_tx, storage_client);

    let worker_state = state.clone();
    tokio::spawn(async move {
        run_worker(worker_state, queue_rx).await;
    });

    let grpc = ExportGrpc {
        state,
        internal_auth: InternalAuthPolicy::from_env("export-service"),
    };
    tracing::info!(
        address = %grpc_addr,
        storage_endpoint = %storage_endpoint,
        "export grpc listening"
    );
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ExportServiceServer<ExportGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply export grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(ExportServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("export grpc server failed");
}
