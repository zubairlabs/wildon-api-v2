#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::{
    modules::{downloads, metadata, processing, signed_urls, uploads},
    state::{AppState, StorageConfig, StoredObject},
};
use chrono::Utc;
use config::grpc::{authorize_internal_request, load_server_tls_config, InternalAuthPolicy};
use contracts::wildon::storage::v1::{
    storage_service_server::{StorageService, StorageServiceServer},
    CompleteUploadRequest, CompleteUploadResponse, CreateDownloadUrlRequest,
    CreateDownloadUrlResponse, CreateProfilePhotoDownloadUrlRequest,
    CreateProfilePhotoDownloadUrlResponse, CreateProfilePhotoUploadTicketRequest,
    CreateProfilePhotoUploadTicketResponse, CreateUploadUrlRequest, CreateUploadUrlResponse,
    GetObjectMetadataRequest, GetObjectMetadataResponse, HealthRequest, HealthResponse,
    ObjectStatus,
};
use observability::init_tracing;
use std::{collections::HashMap, env, net::SocketAddr};
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct StorageGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

#[tonic::async_trait]
impl StorageService for StorageGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "export-service",
                "users-service",
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

    async fn create_upload_url(
        &self,
        request: Request<CreateUploadUrlRequest>,
    ) -> Result<Response<CreateUploadUrlResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "export-service",
                "users-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.owner_id.is_empty() {
            return Err(Status::invalid_argument("owner_id is required"));
        }

        let content_type = processing::normalized_content_type(&payload.content_type);
        let expires_in_seconds = if payload.expires_in_seconds <= 0 {
            self.state.config.default_url_ttl_seconds
        } else {
            payload.expires_in_seconds
        };
        let now = Utc::now().timestamp();
        let expires_at = now + expires_in_seconds;
        let object_key = uploads::build_object_key(&payload.owner_id, &payload.filename);

        let mut objects = self.state.objects.lock().await;
        objects.insert(
            object_key.clone(),
            StoredObject {
                object_key: object_key.clone(),
                content_type: content_type.clone(),
                content_length: payload.content_length,
                tags: payload.tags,
                checksum: String::new(),
                status: ObjectStatus::Pending,
                created_at: now,
                updated_at: now,
            },
        );

        let upload_url =
            signed_urls::build_signed_url(&self.state.config, "PUT", &object_key, expires_at);
        let mut required_headers = HashMap::new();
        required_headers.insert("content-type".to_string(), content_type);

        Ok(Response::new(CreateUploadUrlResponse {
            object_key,
            upload_url,
            method: "PUT".to_string(),
            expires_at,
            required_headers,
        }))
    }

    async fn complete_upload(
        &self,
        request: Request<CompleteUploadRequest>,
    ) -> Result<Response<CompleteUploadResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "export-service",
                "users-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.object_key.is_empty() {
            return Err(Status::invalid_argument("object_key is required"));
        }

        let now = Utc::now().timestamp();
        let content_type = processing::normalized_content_type(&payload.content_type);
        let mut objects = self.state.objects.lock().await;
        let entry = objects
            .entry(payload.object_key.clone())
            .or_insert_with(|| StoredObject {
                object_key: payload.object_key.clone(),
                content_type: content_type.clone(),
                content_length: payload.content_length,
                tags: HashMap::new(),
                checksum: payload.checksum.clone(),
                status: ObjectStatus::Pending,
                created_at: now,
                updated_at: now,
            });

        if !payload.content_type.is_empty() {
            entry.content_type = content_type;
        }
        if payload.content_length > 0 {
            entry.content_length = payload.content_length;
        }
        if !payload.checksum.is_empty() {
            entry.checksum = payload.checksum;
        }
        metadata::merge_tags(&mut entry.tags, payload.tags);
        entry.status = ObjectStatus::Available;
        entry.updated_at = now;

        Ok(Response::new(CompleteUploadResponse {
            accepted: true,
            metadata: Some(entry.to_proto()),
        }))
    }

    async fn create_download_url(
        &self,
        request: Request<CreateDownloadUrlRequest>,
    ) -> Result<Response<CreateDownloadUrlResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "export-service",
                "users-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.object_key.is_empty() {
            return Err(Status::invalid_argument("object_key is required"));
        }

        let expires_in_seconds = if payload.expires_in_seconds <= 0 {
            self.state.config.default_url_ttl_seconds
        } else {
            payload.expires_in_seconds
        };
        let expires_at = Utc::now().timestamp() + expires_in_seconds;

        let objects = self.state.objects.lock().await;
        let object = objects
            .get(&payload.object_key)
            .ok_or_else(|| Status::not_found("object metadata not found"))?;

        if !downloads::can_create_download(object.status) {
            return Err(Status::failed_precondition(
                "object is not available for download",
            ));
        }

        let download_url = signed_urls::build_signed_url(
            &self.state.config,
            "GET",
            &payload.object_key,
            expires_at,
        );

        Ok(Response::new(CreateDownloadUrlResponse {
            object_key: payload.object_key,
            download_url,
            method: "GET".to_string(),
            expires_at,
        }))
    }

    async fn get_object_metadata(
        &self,
        request: Request<GetObjectMetadataRequest>,
    ) -> Result<Response<GetObjectMetadataResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "export-service",
                "users-service",
            ],
        )?;

        let object_key = request.into_inner().object_key;
        if object_key.is_empty() {
            return Err(Status::invalid_argument("object_key is required"));
        }

        let objects = self.state.objects.lock().await;
        let metadata = objects
            .get(&object_key)
            .ok_or_else(|| Status::not_found("object metadata not found"))?;

        Ok(Response::new(GetObjectMetadataResponse {
            metadata: Some(metadata.to_proto()),
        }))
    }

    async fn create_profile_photo_upload_ticket(
        &self,
        request: Request<CreateProfilePhotoUploadTicketRequest>,
    ) -> Result<Response<CreateProfilePhotoUploadTicketResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["users-service"])?;

        let payload = request.into_inner();
        if payload.owner_id.trim().is_empty() {
            return Err(Status::invalid_argument("owner_id is required"));
        }
        if Uuid::parse_str(payload.owner_id.trim()).is_err() {
            return Err(Status::invalid_argument("owner_id must be a valid UUID"));
        }

        let (content_type, extension) =
            processing::profile_photo_content_type_to_extension(payload.content_type.as_str())
                .ok_or_else(|| {
                    Status::invalid_argument(
                        "content_type must be one of image/jpeg, image/png, image/webp",
                    )
                })?;
        if payload.content_length == 0
            || payload.content_length > self.state.config.profile_photo_max_bytes
        {
            return Err(Status::invalid_argument(format!(
                "content_length must be between 1 and {} bytes",
                self.state.config.profile_photo_max_bytes
            )));
        }

        let expires_in_seconds = if payload.expires_in_seconds <= 0 {
            self.state.config.profile_photo_signed_url_ttl_seconds
        } else {
            payload.expires_in_seconds.min(
                self.state
                    .config
                    .profile_photo_signed_url_ttl_seconds
                    .max(1),
            )
        };
        let now = Utc::now().timestamp();
        let expires_at = now + expires_in_seconds;
        let object_key = uploads::build_profile_photo_object_key(&payload.owner_id, extension);

        let mut objects = self.state.objects.lock().await;
        objects.insert(
            object_key.clone(),
            StoredObject {
                object_key: object_key.clone(),
                content_type: content_type.to_string(),
                content_length: payload.content_length,
                tags: HashMap::from([
                    ("source".to_string(), "users-service".to_string()),
                    ("owner_id".to_string(), payload.owner_id.clone()),
                    ("asset_kind".to_string(), "profile_photo".to_string()),
                ]),
                checksum: String::new(),
                status: ObjectStatus::Pending,
                created_at: now,
                updated_at: now,
            },
        );

        let upload_url =
            signed_urls::build_signed_url(&self.state.config, "PUT", &object_key, expires_at);
        let mut required_headers = HashMap::new();
        required_headers.insert("content-type".to_string(), content_type.to_string());
        required_headers.insert(
            "content-length".to_string(),
            payload.content_length.to_string(),
        );

        Ok(Response::new(CreateProfilePhotoUploadTicketResponse {
            object_key,
            upload_url,
            method: "PUT".to_string(),
            expires_at,
            required_headers,
            content_type: content_type.to_string(),
            max_bytes: self.state.config.profile_photo_max_bytes,
        }))
    }

    async fn create_profile_photo_download_url(
        &self,
        request: Request<CreateProfilePhotoDownloadUrlRequest>,
    ) -> Result<Response<CreateProfilePhotoDownloadUrlResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["users-service"])?;

        let payload = request.into_inner();
        if payload.owner_id.trim().is_empty() {
            return Err(Status::invalid_argument("owner_id is required"));
        }
        if payload.object_key.trim().is_empty() {
            return Err(Status::invalid_argument("object_key is required"));
        }
        if Uuid::parse_str(payload.owner_id.trim()).is_err() {
            return Err(Status::invalid_argument("owner_id must be a valid UUID"));
        }

        let prefix = format!("users/{}/profile/", payload.owner_id.trim());
        if !payload.object_key.starts_with(prefix.as_str()) {
            return Err(Status::permission_denied(
                "object_key does not belong to owner_id profile namespace",
            ));
        }

        let expires_in_seconds = if payload.expires_in_seconds <= 0 {
            self.state.config.profile_photo_signed_url_ttl_seconds
        } else {
            payload.expires_in_seconds.min(
                self.state
                    .config
                    .profile_photo_signed_url_ttl_seconds
                    .max(1),
            )
        };
        let expires_at = Utc::now().timestamp() + expires_in_seconds;

        let objects = self.state.objects.lock().await;
        let object = objects
            .get(&payload.object_key)
            .ok_or_else(|| Status::not_found("object metadata not found"))?;
        if !matches!(
            object.status,
            ObjectStatus::Pending | ObjectStatus::Available
        ) {
            return Err(Status::failed_precondition(
                "object is not available for profile download",
            ));
        }

        let download_url = signed_urls::build_signed_url(
            &self.state.config,
            "GET",
            &payload.object_key,
            expires_at,
        );

        Ok(Response::new(CreateProfilePhotoDownloadUrlResponse {
            object_key: payload.object_key,
            download_url,
            method: "GET".to_string(),
            expires_at,
        }))
    }
}

#[tokio::main]
async fn main() {
    init_tracing("storage-service");

    let grpc_addr = env::var("STORAGE_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50055".to_string())
        .parse::<SocketAddr>()
        .expect("invalid STORAGE_GRPC_BIND_ADDR");

    let config = StorageConfig::from_env();
    let grpc = StorageGrpc {
        state: AppState::new(config.clone()),
        internal_auth: InternalAuthPolicy::from_env("storage-service"),
    };

    tracing::info!(
        address = %grpc_addr,
        endpoint = %config.endpoint,
        region = %config.region,
        bucket = %config.bucket,
        "storage grpc listening"
    );
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<StorageServiceServer<StorageGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply storage grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(StorageServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("storage grpc server failed");
}
