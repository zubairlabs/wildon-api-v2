#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::{
    modules::{dashboard, devices, users},
    state::AppState,
};
use chrono_tz::Tz;
use config::grpc::{
    authorize_internal_request, connect_channel, inject_internal_metadata, load_server_tls_config,
    metadata_value, InternalAuthPolicy,
};
use contracts::wildon::{
    billing::v1::{GetSubscriptionRequest, RecordUsageRequest, ResolveEntitlementRequest},
    export::v1::{
        CreateExportJobRequest as ExportCreateExportJobRequest, DownloadExportRequest,
        ExportJobStatus, GetExportJobRequest as ExportGetExportJobRequest,
    },
    logs::v1::{
        AuditAccessPurpose, AuditActorType, AuditAuthMechanism, AuditDataSensitivityLevel,
        AuditResult,
    },
    public::v1::{
        public_service_server::{PublicService, PublicServiceServer},
        CreateDeviceRequest, CreateDeviceResponse, CreateExportJobRequest, CreateExportJobResponse,
        CreateMediaUploadTicketRequest, CreateMediaUploadTicketResponse, Device,
        GetDashboardSummaryRequest, GetDashboardSummaryResponse, GetExportJobRequest,
        GetExportJobResponse, GetProfileRequest, GetProfileResponse, HealthRequest, HealthResponse,
        ListDevicesRequest, ListDevicesResponse,
        UpdateProfileRequest, UpdateProfileResponse, UserProfile,
    },
    storage::v1::CreateUploadUrlRequest as StorageCreateUploadUrlRequest,
    users::v1::GetUserSettingsRequest as UsersGetUserSettingsRequest,
};
use event_bus::EventEnvelope;
use logs_sdk::AuditEventBuilder;
use observability::init_tracing;
use serde_json::json;
use std::{collections::HashMap, env, net::SocketAddr};
use tonic::{Code, Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct PublicGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

impl PublicGrpc {
    fn to_proto_profile(profile: &users::UserProfileData) -> UserProfile {
        UserProfile {
            user_id: profile.user_id.clone(),
            email: profile.email.clone(),
            display_name: profile.display_name.clone(),
            updated_at: profile.updated_at,
            timezone: profile.timezone.clone(),
            first_name: profile.first_name.clone(),
            last_name: profile.last_name.clone(),
            middle_name: profile.middle_name.clone(),
            preferred_name: profile.preferred_name.clone(),
            full_name: profile.full_name(),
        }
    }

    fn to_proto_device(device: devices::DeviceData) -> Device {
        Device {
            device_id: device.device_id,
            platform: device.platform,
            nickname: device.nickname,
            created_at: device.created_at,
        }
    }
}

fn export_status_label(status: ExportJobStatus) -> String {
    match status {
        ExportJobStatus::Queued => "queued",
        ExportJobStatus::Running => "running",
        ExportJobStatus::Completed => "completed",
        ExportJobStatus::Failed => "failed",
        ExportJobStatus::Unspecified => "unspecified",
    }
    .to_string()
}

fn actor_context_from_request(
    caller: &str,
    auth_sub: Option<&str>,
    auth_role: Option<&str>,
) -> (AuditActorType, String, String, AuditAuthMechanism) {
    if let Some(auth_sub) = auth_sub.filter(|value| !value.trim().is_empty()) {
        return (
            AuditActorType::User,
            auth_sub.to_string(),
            auth_role.unwrap_or("user").to_string(),
            AuditAuthMechanism::Jwt,
        );
    }

    let actor_type = match caller {
        "platform-service" => AuditActorType::Support,
        "control-service" => AuditActorType::InternalService,
        _ => AuditActorType::System,
    };
    (
        actor_type,
        caller.to_string(),
        caller.to_string(),
        AuditAuthMechanism::MtlsInternal,
    )
}

fn access_purpose_from_request(value: Option<&str>) -> AuditAccessPurpose {
    match value.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "audit" => AuditAccessPurpose::Audit,
        "support" => AuditAccessPurpose::Support,
        "debugging" => AuditAccessPurpose::Debugging,
        "system" => AuditAccessPurpose::System,
        _ => AuditAccessPurpose::Treatment,
    }
}

fn non_empty_trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_timezone(timezone: &str) -> Result<String, Status> {
    let candidate = timezone.trim();
    if candidate.is_empty() {
        return Ok("UTC".to_string());
    }

    candidate
        .parse::<Tz>()
        .map(|tz| tz.to_string())
        .map_err(|_| Status::invalid_argument("timezone must be a valid IANA timezone"))
}

fn normalize_pagination_limit(limit: u32) -> usize {
    const DEFAULT_LIMIT: u32 = 50;
    const MAX_LIMIT: u32 = 200;

    let bounded = if limit == 0 {
        DEFAULT_LIMIT
    } else {
        limit.min(MAX_LIMIT)
    };
    bounded as usize
}

fn parse_pagination_cursor(cursor: &str) -> Result<usize, Status> {
    let trimmed = cursor.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| Status::invalid_argument("cursor must be an unsigned integer offset"))
}

fn enforce_subject_ownership(
    caller: &str,
    auth_sub: Option<&str>,
    requested_user_id: &str,
) -> Result<(), Status> {
    if caller == "gateway-service" {
        let Some(auth_sub) = auth_sub else {
            return Err(Status::unauthenticated("missing x-auth-sub metadata"));
        };
        if auth_sub != requested_user_id {
            return Err(Status::permission_denied(
                "resource ownership mismatch for requested user_id",
            ));
        }
    }
    Ok(())
}

fn derive_display_name_from_settings(
    full_name: &str,
    username: &str,
    email: &str,
    user_id: &str,
) -> String {
    let full_name = full_name.trim();
    if !full_name.is_empty() {
        return full_name.to_string();
    }

    let username = username.trim();
    if !username.is_empty() {
        return username.to_string();
    }

    let email = email.trim();
    if !email.is_empty() {
        return email.split('@').next().unwrap_or(email).trim().to_string();
    }

    user_id.to_string()
}

async fn hydrate_profile_from_users_service(
    state: &AppState,
    user_id: &str,
    request_id: Option<&str>,
    traceparent: Option<&str>,
) -> Result<Option<users::UserProfileData>, Status> {
    let mut users_client = state.users_client.lock().await;
    let mut settings_request = Request::new(UsersGetUserSettingsRequest {
        user_id: user_id.to_string(),
    });
    inject_internal_metadata(
        &mut settings_request,
        "public-service",
        request_id,
        traceparent,
    )?;

    let settings_response = match users_client.get_user_settings(settings_request).await {
        Ok(response) => response.into_inner(),
        Err(err) if err.code() == Code::NotFound => return Ok(None),
        Err(err) => {
            return Err(Status::internal(format!(
                "users-service get_user_settings failed: {err}"
            )));
        }
    };

    let Some(settings) = settings_response.settings else {
        return Ok(None);
    };

    let display_name = if settings.display_name.trim().is_empty() {
        derive_display_name_from_settings(
            settings.full_name.as_str(),
            settings.username.as_str(),
            settings.email.as_str(),
            user_id,
        )
    } else {
        settings.display_name.clone()
    };
    let timezone = normalize_timezone(settings.timezone.as_str())?;

    Ok(Some(users::UserProfileData {
        user_id: user_id.to_string(),
        email: settings.email,
        first_name: settings.first_name,
        last_name: settings.last_name,
        middle_name: settings.middle_name,
        preferred_name: settings.preferred_name,
        display_name,
        timezone,
        updated_at: settings.settings_updated_at,
    }))
}

#[tonic::async_trait]
impl PublicService for PublicGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
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

    async fn get_dashboard_summary(
        &self,
        request: Request<GetDashboardSummaryRequest>,
    ) -> Result<Response<GetDashboardSummaryResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let subscription = {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut subscription_request = Request::new(GetSubscriptionRequest {
                user_id: payload.user_id.clone(),
            });
            inject_internal_metadata(
                &mut subscription_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            billing_client.get_subscription(subscription_request).await
        };

        let (subscription_plan, subscription_status) = match subscription {
            Ok(response) => {
                let details = response.into_inner();
                let plan = if details.plan.is_empty() {
                    "free".to_string()
                } else {
                    details.plan
                };
                let status = if details.status.is_empty() {
                    "inactive".to_string()
                } else {
                    details.status
                };
                (plan, status)
            }
            Err(err) => {
                tracing::warn!(error = %err, "billing get_subscription failed for dashboard summary");
                ("free".to_string(), "inactive".to_string())
            }
        };

        let summary = {
            let data = self.state.data.lock().await;
            dashboard::build_summary(
                &data,
                &payload.user_id,
                &subscription_plan,
                &subscription_status,
            )
        };

        Ok(Response::new(GetDashboardSummaryResponse {
            user_id: summary.user_id,
            devices_count: summary.devices_count,
            trips_count: summary.trips_count,
            media_count: summary.media_count,
            subscription_plan: summary.subscription_plan,
            subscription_status: summary.subscription_status,
            ai_usage_total: summary.ai_usage_total,
            generated_at: summary.generated_at,
        }))
    }

    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let auth_role = metadata_value(&request, "x-auth-role");
        let auth_session_id = metadata_value(&request, "x-auth-session-id");
        let access_purpose = metadata_value(&request, "x-access-purpose");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let existing = {
            let data = self.state.data.lock().await;
            users::get_profile(&data.profiles, &payload.user_id).cloned()
        };
        let profile = if let Some(profile) = existing {
            profile
        } else {
            let Some(hydrated) = hydrate_profile_from_users_service(
                &self.state,
                &payload.user_id,
                request_id.as_deref(),
                traceparent.as_deref(),
            )
            .await?
            else {
                return Err(Status::not_found("profile not found"));
            };

            {
                let mut data = self.state.data.lock().await;
                data.profiles
                    .insert(payload.user_id.clone(), hydrated.clone());
            }
            hydrated
        };

        let (actor_type, actor_id, actor_role, auth_mechanism) = actor_context_from_request(
            caller.as_str(),
            auth_sub.as_deref(),
            auth_role.as_deref(),
        );
        let mut audit_request = Request::new(
            AuditEventBuilder::new("public-service", "care.member.view", "user_profile", &payload.user_id)
                .actor(actor_type, actor_id, actor_role, auth_mechanism)
                .resource_owner_id(payload.user_id.clone())
                .context(
                    request_id.as_deref(),
                    traceparent.as_deref(),
                    auth_session_id.as_deref(),
                    None,
                    None,
                    Some("GET"),
                    Some("/v1/users/me"),
                    Some(200),
                    access_purpose_from_request(access_purpose.as_deref()),
                )
                .result(AuditResult::Success)
                .sensitivity(AuditDataSensitivityLevel::Phi)
                .metadata_value(json!({
                    "caller": caller,
                    "resource_type": "user_profile",
                    "resource_id": payload.user_id,
                }))
                .into_ingest_request(),
        );
        inject_internal_metadata(
            &mut audit_request,
            "public-service",
            request_id.as_deref(),
            traceparent.as_deref(),
        )?;
        let mut logs_client = self.state.logs_client.lock().await;
        let _ = logs_client.ingest_audit(audit_request).await;

        Ok(Response::new(GetProfileResponse {
            profile: Some(Self::to_proto_profile(&profile)),
        }))
    }

    async fn update_profile(
        &self,
        request: Request<UpdateProfileRequest>,
    ) -> Result<Response<UpdateProfileResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let auth_role = metadata_value(&request, "x-auth-role");
        let auth_session_id = metadata_value(&request, "x-auth-session-id");
        let access_purpose = metadata_value(&request, "x-access-purpose");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        let first_name = non_empty_trimmed(&payload.first_name);
        let last_name = non_empty_trimmed(&payload.last_name);
        let middle_name = non_empty_trimmed(&payload.middle_name);
        let preferred_name = non_empty_trimmed(&payload.preferred_name);
        let display_name = non_empty_trimmed(&payload.display_name);
        let timezone = if payload.timezone.trim().is_empty() {
            None
        } else {
            Some(normalize_timezone(payload.timezone.as_str())?)
        };
        if first_name.is_none()
            && last_name.is_none()
            && middle_name.is_none()
            && preferred_name.is_none()
            && display_name.is_none()
            && timezone.is_none()
        {
            return Err(Status::invalid_argument(
                "at least one profile field is required",
            ));
        }

        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let profile_present = {
            let data = self.state.data.lock().await;
            data.profiles.contains_key(&payload.user_id)
        };
        if !profile_present {
            if let Some(hydrated) = hydrate_profile_from_users_service(
                &self.state,
                &payload.user_id,
                request_id.as_deref(),
                traceparent.as_deref(),
            )
            .await?
            {
                let mut data = self.state.data.lock().await;
                data.profiles.insert(payload.user_id.clone(), hydrated);
            }
        }

        let feature_key = if payload.feature_key.is_empty() {
            "profile_write".to_string()
        } else {
            payload.feature_key
        };

        let entitlement = {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut entitlement_request = Request::new(ResolveEntitlementRequest {
                user_id: payload.user_id.clone(),
                feature_key: feature_key.clone(),
            });
            inject_internal_metadata(
                &mut entitlement_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            billing_client
                .resolve_entitlement(entitlement_request)
                .await
                .map_err(|err| Status::internal(format!("billing entitlement error: {err}")))?
                .into_inner()
        };

        if !entitlement.allowed {
            return Err(Status::permission_denied(entitlement.reason));
        }

        let event_id = if payload.idempotency_key.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            payload.idempotency_key.clone()
        };

        let profile = {
            let mut data = self.state.data.lock().await;
            let profile = users::update_profile(
                &mut data.profiles,
                &payload.user_id,
                first_name.as_deref(),
                last_name.as_deref(),
                middle_name.as_deref(),
                preferred_name.as_deref(),
                display_name.as_deref(),
                timezone.as_deref(),
            )
            .ok_or_else(|| Status::not_found("profile not found"))?;

            let payload_json = json!({
                "user_id": payload.user_id,
                "display_name": display_name,
                "timezone": timezone,
                "feature_key": feature_key,
            })
            .to_string();

            let envelope = EventEnvelope::with_event_id(
                event_id.clone(),
                "profile.updated",
                profile.user_id.clone(),
                payload_json,
            )
            .with_producer("public-service")
            .with_schema_version(1)
            .with_trace_context(request_id.clone(), traceparent.clone());
            data.outbox.enqueue("public.profile", envelope);
            profile
        };

        let audit = {
            let (actor_type, actor_id, actor_role, auth_mechanism) = actor_context_from_request(
                caller.as_str(),
                auth_sub.as_deref(),
                auth_role.as_deref(),
            );
            let mut logs_client = self.state.logs_client.lock().await;
            let mut audit_request = Request::new(
                AuditEventBuilder::new("public-service", "care.member.update", "user_profile", &profile.user_id)
                    .event_id(event_id.clone())
                    .actor(actor_type, actor_id, actor_role, auth_mechanism)
                    .resource_owner_id(profile.user_id.clone())
                    .context(
                        request_id.as_deref(),
                        traceparent.as_deref(),
                        auth_session_id.as_deref(),
                        None,
                        None,
                        Some("PATCH"),
                        Some("/v1/users/me"),
                        Some(200),
                        access_purpose_from_request(access_purpose.as_deref()),
                    )
                    .result(AuditResult::Success)
                    .sensitivity(AuditDataSensitivityLevel::Phi)
                    .after_json(Some(
                        &json!({
                            "display_name": profile.display_name,
                            "timezone": profile.timezone,
                        })
                        .to_string(),
                    ))
                    .metadata_value(json!({
                        "feature_key": feature_key,
                    }))
                    .into_ingest_request(),
            );
            inject_internal_metadata(
                &mut audit_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            logs_client
                .ingest_audit(audit_request)
                .await
                .map_err(|err| Status::internal(format!("logs ingestion error: {err}")))?
                .into_inner()
        };

        if audit.accepted {
            let mut data = self.state.data.lock().await;
            data.outbox.mark_delivered(&event_id);
        }

        {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut usage_request = Request::new(RecordUsageRequest {
                user_id: profile.user_id.clone(),
                metric: "profile.update".to_string(),
                amount: 1,
            });
            let _ = inject_internal_metadata(
                &mut usage_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            );
            let _ = billing_client.record_usage(usage_request).await;
        }

        Ok(Response::new(UpdateProfileResponse {
            profile: Some(Self::to_proto_profile(&profile)),
            event_published: audit.accepted,
            event_duplicate: audit.duplicate,
        }))
    }

    async fn create_device(
        &self,
        request: Request<CreateDeviceRequest>,
    ) -> Result<Response<CreateDeviceResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() || payload.platform.is_empty() {
            return Err(Status::invalid_argument(
                "user_id and platform are required",
            ));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let device = {
            let mut data = self.state.data.lock().await;
            devices::create_device(
                &mut data.devices,
                &payload.user_id,
                &payload.platform,
                &payload.nickname,
            )
        };

        {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut usage_request = Request::new(RecordUsageRequest {
                user_id: payload.user_id,
                metric: "device.create".to_string(),
                amount: 1,
            });
            let _ = inject_internal_metadata(
                &mut usage_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            );
            let _ = billing_client.record_usage(usage_request).await;
        }

        Ok(Response::new(CreateDeviceResponse {
            device: Some(Self::to_proto_device(device)),
        }))
    }

    async fn list_devices(
        &self,
        request: Request<ListDevicesRequest>,
    ) -> Result<Response<ListDevicesResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;
        let limit = normalize_pagination_limit(payload.limit);
        let cursor = parse_pagination_cursor(payload.cursor.as_str())?;

        let data = self.state.data.lock().await;
        let mut devices = devices::list_devices(&data.devices, &payload.user_id);
        devices.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.device_id.cmp(&left.device_id))
        });

        let window_end = cursor.saturating_add(limit).saturating_add(1);
        let end = window_end.min(devices.len());
        let mut page_items = if cursor >= devices.len() {
            Vec::new()
        } else {
            devices[cursor..end].to_vec()
        };
        let has_more = page_items.len() > limit;
        if has_more {
            page_items.truncate(limit);
        }
        let next_cursor = if has_more {
            cursor.saturating_add(limit).to_string()
        } else {
            String::new()
        };

        let devices = page_items.into_iter().map(Self::to_proto_device).collect();

        Ok(Response::new(ListDevicesResponse {
            devices,
            next_cursor,
            has_more,
        }))
    }

    async fn create_media_upload_ticket(
        &self,
        request: Request<CreateMediaUploadTicketRequest>,
    ) -> Result<Response<CreateMediaUploadTicketResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let filename = if payload.filename.trim().is_empty() {
            "upload.bin".to_string()
        } else {
            payload.filename
        };

        let ticket = {
            let mut storage_client = self.state.storage_client.lock().await;
            storage_client
                .create_upload_url(StorageCreateUploadUrlRequest {
                    owner_id: payload.user_id.clone(),
                    filename,
                    content_type: payload.content_type,
                    content_length: payload.content_length,
                    expires_in_seconds: 900,
                    tags: HashMap::from([
                        ("source".to_string(), "public-service".to_string()),
                        ("owner_id".to_string(), payload.user_id.clone()),
                    ]),
                })
                .await
                .map_err(|err| Status::internal(format!("storage upload ticket error: {err}")))?
        };

        {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut usage_request = Request::new(RecordUsageRequest {
                user_id: payload.user_id,
                metric: "media.upload_ticket".to_string(),
                amount: 1,
            });
            let _ = inject_internal_metadata(
                &mut usage_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            );
            let _ = billing_client.record_usage(usage_request).await;
        }

        Ok(Response::new(CreateMediaUploadTicketResponse {
            object_key: ticket.object_key,
            upload_url: ticket.upload_url,
            method: ticket.method,
            expires_at: ticket.expires_at,
        }))
    }

    async fn create_export_job(
        &self,
        request: Request<CreateExportJobRequest>,
    ) -> Result<Response<CreateExportJobResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let auth_role = metadata_value(&request, "x-auth-role");
        let auth_session_id = metadata_value(&request, "x-auth-session-id");
        let access_purpose = metadata_value(&request, "x-access-purpose");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let export_job = {
            let mut export_client = self.state.export_client.lock().await;
            export_client
                .create_export_job(ExportCreateExportJobRequest {
                    user_id: payload.user_id.clone(),
                    export_kind: payload.export_kind,
                    format: payload.format,
                    idempotency_key: payload.idempotency_key,
                })
                .await
                .map_err(|err| Status::internal(format!("export create job error: {err}")))?
        };

        let job = export_job
            .job
            .ok_or_else(|| Status::internal("missing export job payload"))?;
        let status_enum =
            ExportJobStatus::try_from(job.status).unwrap_or(ExportJobStatus::Unspecified);

        {
            let (actor_type, actor_id, actor_role, auth_mechanism) = actor_context_from_request(
                caller.as_str(),
                auth_sub.as_deref(),
                auth_role.as_deref(),
            );
            let mut logs_client = self.state.logs_client.lock().await;
            let mut audit_request = Request::new(
                AuditEventBuilder::new("public-service", "audit.export", "export_job", &job.job_id)
                    .actor(actor_type, actor_id, actor_role, auth_mechanism)
                    .resource_owner_id(payload.user_id.clone())
                    .context(
                        request_id.as_deref(),
                        traceparent.as_deref(),
                        auth_session_id.as_deref(),
                        None,
                        None,
                        Some("POST"),
                        Some("/v1/exports"),
                        Some(200),
                        access_purpose_from_request(access_purpose.as_deref()),
                    )
                    .result(AuditResult::Success)
                    .sensitivity(AuditDataSensitivityLevel::Critical)
                    .metadata_value(json!({
                        "export_kind": job.export_kind,
                        "status": export_status_label(status_enum),
                    }))
                    .into_ingest_request(),
            );
            inject_internal_metadata(
                &mut audit_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            let _ = logs_client.ingest_audit(audit_request).await;
        }

        {
            let mut billing_client = self.state.billing_client.lock().await;
            let mut usage_request = Request::new(RecordUsageRequest {
                user_id: payload.user_id,
                metric: "export.create".to_string(),
                amount: 1,
            });
            let _ = inject_internal_metadata(
                &mut usage_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            );
            let _ = billing_client.record_usage(usage_request).await;
        }

        Ok(Response::new(CreateExportJobResponse {
            job_id: job.job_id,
            status: export_status_label(status_enum),
            artifact_key: job.artifact_key,
            duplicate: export_job.duplicate,
        }))
    }

    async fn get_export_job(
        &self,
        request: Request<GetExportJobRequest>,
    ) -> Result<Response<GetExportJobResponse>, Status> {
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let auth_role = metadata_value(&request, "x-auth-role");
        let auth_session_id = metadata_value(&request, "x-auth-session-id");
        let access_purpose = metadata_value(&request, "x-access-purpose");
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "gateway-service",
                "control-service",
                "platform-service",
                "core-service",
            ],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");

        let payload = request.into_inner();
        if payload.user_id.is_empty() || payload.job_id.is_empty() {
            return Err(Status::invalid_argument("user_id and job_id are required"));
        }
        enforce_subject_ownership(caller.as_str(), auth_sub.as_deref(), &payload.user_id)?;

        let export_job = {
            let mut export_client = self.state.export_client.lock().await;
            export_client
                .get_export_job(ExportGetExportJobRequest {
                    job_id: payload.job_id.clone(),
                })
                .await
                .map_err(|err| Status::internal(format!("export get job error: {err}")))?
        };

        let job = export_job
            .job
            .ok_or_else(|| Status::internal("missing export job payload"))?;
        if job.user_id != payload.user_id {
            return Err(Status::permission_denied(
                "export job does not belong to requested user",
            ));
        }

        let status_enum =
            ExportJobStatus::try_from(job.status).unwrap_or(ExportJobStatus::Unspecified);
        let mut download_url = String::new();
        let mut download_expires_at = 0;

        if matches!(status_enum, ExportJobStatus::Completed) {
            let download = {
                let mut export_client = self.state.export_client.lock().await;
                export_client
                    .download_export(DownloadExportRequest {
                        job_id: payload.job_id.clone(),
                        expires_in_seconds: 900,
                    })
                    .await
                    .map_err(|err| Status::internal(format!("export download url error: {err}")))?
            };
            download_url = download.download_url;
            download_expires_at = download.expires_at;
        }

        {
            let (actor_type, actor_id, actor_role, auth_mechanism) = actor_context_from_request(
                caller.as_str(),
                auth_sub.as_deref(),
                auth_role.as_deref(),
            );
            let action = if download_url.is_empty() {
                "audit.view"
            } else {
                "audit.export"
            };
            let mut logs_client = self.state.logs_client.lock().await;
            let mut audit_request = Request::new(
                AuditEventBuilder::new("public-service", action, "export_job", &job.job_id)
                    .actor(actor_type, actor_id, actor_role, auth_mechanism)
                    .resource_owner_id(payload.user_id.clone())
                    .context(
                        request_id.as_deref(),
                        traceparent.as_deref(),
                        auth_session_id.as_deref(),
                        None,
                        None,
                        Some("GET"),
                        Some("/v1/exports/:job_id"),
                        Some(200),
                        access_purpose_from_request(access_purpose.as_deref()),
                    )
                    .result(AuditResult::Success)
                    .sensitivity(AuditDataSensitivityLevel::Critical)
                    .metadata_value(json!({
                        "status": export_status_label(status_enum),
                        "download_ready": !download_url.is_empty(),
                    }))
                    .into_ingest_request(),
            );
            inject_internal_metadata(
                &mut audit_request,
                "public-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            )?;
            let _ = logs_client.ingest_audit(audit_request).await;
        }

        Ok(Response::new(GetExportJobResponse {
            job_id: job.job_id,
            status: export_status_label(status_enum),
            artifact_key: job.artifact_key,
            download_url,
            download_expires_at,
            error_message: job.error_message,
        }))
    }
}

#[tokio::main]
async fn main() {
    init_tracing("public-service");

    let grpc_addr = env::var("PUBLIC_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50052".to_string())
        .parse::<SocketAddr>()
        .expect("invalid PUBLIC_GRPC_BIND_ADDR");

    let billing_endpoint =
        env::var("BILLING_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50059".to_string());
    let logs_endpoint =
        env::var("LOGS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50054".to_string());
    let users_endpoint =
        env::var("USERS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50057".to_string());
    let storage_endpoint =
        env::var("STORAGE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());
    let export_endpoint =
        env::var("EXPORT_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50056".to_string());

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
    let users_channel = connect_channel(&users_endpoint, "users-service")
        .await
        .expect("failed to connect users grpc endpoint");
    let users_client =
        contracts::wildon::users::v1::users_service_client::UsersServiceClient::new(
            users_channel,
        );
    let storage_client =
        storage_sdk::StorageSdkClient::connect_as(storage_endpoint, "public-service")
            .await
            .expect("failed to connect storage grpc endpoint");
    let export_client = export_sdk::ExportSdkClient::connect_as(export_endpoint, "public-service")
        .await
        .expect("failed to connect export grpc endpoint");

    let grpc = PublicGrpc {
        state: AppState::new(
            billing_client,
            logs_client,
            users_client,
            storage_client,
            export_client,
        ),
        internal_auth: InternalAuthPolicy::from_env("public-service"),
    };

    tracing::info!(address = %grpc_addr, "public grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<PublicServiceServer<PublicGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply public grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(PublicServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("public grpc server failed");
}
