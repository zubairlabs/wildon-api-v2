#![allow(dead_code)]

mod modules;
mod state;

use crate::{
    modules::{permissions, roles, scopes, users::UserRecordData},
    state::AppState,
};
use chrono::Utc;
use chrono_tz::Tz;
use config::grpc::{
    authorize_internal_request, load_server_tls_config, metadata_value, InternalAuthPolicy,
};
use contracts::wildon::{
    storage::v1::{
        CreateProfilePhotoDownloadUrlRequest as StorageCreateProfilePhotoDownloadUrlRequest,
        CreateProfilePhotoUploadTicketRequest as StorageCreateProfilePhotoUploadTicketRequest,
        GetObjectMetadataRequest as StorageGetObjectMetadataRequest,
    },
    users::v1::{
        users_service_server::{UsersService, UsersServiceServer},
        BumpPermRevisionRequest, BumpPermRevisionResponse, CreateProfilePhotoDownloadUrlRequest,
        CreateProfilePhotoDownloadUrlResponse, CreateProfilePhotoUploadTicketRequest,
        CreateProfilePhotoUploadTicketResponse, CreateUserRequest, CreateUserResponse,
        DisableUserRequest, DisableUserResponse, GetUserAuthStateRequest, GetUserAuthStateResponse,
        GetUserSettingsRequest, GetUserSettingsResponse, HealthRequest, HealthResponse,
        UpdateUserNotificationSettingsRequest, UpdateUserNotificationSettingsResponse,
        UpdateUserRolesRequest, UpdateUserRolesResponse, UpdateUserScopesRequest,
        UpdateUserScopesResponse, UpdateUserSettingsRequest, UpdateUserSettingsResponse,
        UserNotificationSettings, UserRecord, UserSettings,
    },
};
use observability::init_tracing;
use sqlx::{postgres::PgPoolOptions, Row};
use std::{env, net::SocketAddr};
use storage_sdk::StorageSdkClient;
use tonic::{Request, Response, Status};
use uuid::Uuid;

const PROFILE_PHOTO_MAX_BYTES: u64 = 5 * 1024 * 1024;
const PROFILE_PHOTO_SIGNED_URL_TTL_SECONDS: i64 = 300;

#[derive(Clone)]
struct UsersGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

impl UsersGrpc {
    fn to_proto(user: &UserRecordData) -> UserRecord {
        UserRecord {
            user_id: user.user_id.clone(),
            email: user.email.clone(),
            status: user.status.clone(),
            roles: user.roles.clone(),
            scopes: user.scopes.clone(),
            perm_rev: user.perm_rev,
            created_at: user.created_at,
            updated_at: user.updated_at,
            account_number: user.account_number.clone().unwrap_or_default(),
        }
    }

    async fn ensure_user_exists(&self, user_id: Uuid) -> Result<(), Status> {
        let row = sqlx::query("SELECT 1 FROM users_app.users WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.state.db)
            .await
            .map_err(|err| Status::internal(format!("db users lookup failed: {err}")))?;
        if row.is_none() {
            return Err(Status::not_found("user not found"));
        }
        Ok(())
    }

    async fn load_user_roles(&self, user_id: Uuid) -> Result<Vec<String>, Status> {
        let rows = sqlx::query(
            "SELECT role
             FROM users_app.role_assignments
             WHERE user_id = $1
             ORDER BY role ASC",
        )
        .bind(user_id)
        .fetch_all(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db role lookup failed: {err}")))?;

        let mut roles = rows
            .into_iter()
            .map(|row| row.get::<String, _>("role"))
            .collect::<Vec<_>>();
        if roles.is_empty() {
            roles.push("user".to_string());
        }
        Ok(roles::normalize_roles(roles))
    }

    async fn load_user_scopes(&self, user_id: Uuid) -> Result<Vec<String>, Status> {
        let rows = sqlx::query(
            "SELECT scope
             FROM users_app.user_scope_assignments
             WHERE user_id = $1
             ORDER BY scope ASC",
        )
        .bind(user_id)
        .fetch_all(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db scope lookup failed: {err}")))?;

        Ok(scopes::normalize_scopes(
            rows.into_iter()
                .map(|row| row.get::<String, _>("scope"))
                .collect(),
        ))
    }

    async fn load_user_from_db(&self, user_id: Uuid) -> Result<Option<UserRecordData>, Status> {
        let row = sqlx::query(
            "SELECT
                user_id::text AS user_id,
                email,
                status,
                perm_rev,
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at,
                account_number
             FROM users_app.users
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db user lookup failed: {err}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let roles = self.load_user_roles(user_id).await?;
        let scopes = self.load_user_scopes(user_id).await?;
        Ok(Some(UserRecordData {
            user_id: row.get("user_id"),
            email: row.get("email"),
            status: row.get("status"),
            roles,
            scopes,
            perm_rev: row.get("perm_rev"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            account_number: row.get("account_number"),
        }))
    }

    async fn ensure_user_cached(&self, user_id: &str) -> Result<(), Status> {
        {
            let users = self.state.users.lock().await;
            if users.contains_key(user_id) {
                return Ok(());
            }
        }

        let user_uuid = parse_user_uuid(user_id)?;
        let loaded = self
            .load_user_from_db(user_uuid)
            .await?
            .ok_or_else(|| Status::not_found("user not found"))?;

        let mut users = self.state.users.lock().await;
        users.entry(user_id.to_string()).or_insert(loaded);
        Ok(())
    }

    async fn replace_role_assignments(
        &self,
        user_id: Uuid,
        roles: &[String],
    ) -> Result<(), Status> {
        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db role tx begin failed: {err}")))?;

        sqlx::query("DELETE FROM users_app.role_assignments WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db role delete failed: {err}")))?;

        for role in roles {
            sqlx::query(
                "INSERT INTO users_app.role_assignments (user_id, role)
                 VALUES ($1, $2)
                 ON CONFLICT (user_id, role) DO NOTHING",
            )
            .bind(user_id)
            .bind(role)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db role insert failed: {err}")))?;
        }

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db role tx commit failed: {err}")))?;
        Ok(())
    }

    async fn replace_scope_assignments(
        &self,
        user_id: Uuid,
        scopes: &[String],
    ) -> Result<(), Status> {
        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db scope tx begin failed: {err}")))?;

        sqlx::query("DELETE FROM users_app.user_scope_assignments WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db scope delete failed: {err}")))?;

        for scope in scopes {
            sqlx::query(
                "INSERT INTO users_app.user_scope_assignments (user_id, scope)
                 VALUES ($1, $2)
                 ON CONFLICT (user_id, scope) DO NOTHING",
            )
            .bind(user_id)
            .bind(scope)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db scope insert failed: {err}")))?;
        }

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db scope tx commit failed: {err}")))?;
        Ok(())
    }

    async fn persist_auth_state(
        &self,
        user_id: Uuid,
        status: Option<&str>,
        perm_rev: i64,
    ) -> Result<(), Status> {
        sqlx::query(
            "UPDATE users_app.users
             SET status = COALESCE($2, status),
                 perm_rev = $3,
                 updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(status)
        .bind(perm_rev)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db auth state update failed: {err}")))?;
        Ok(())
    }

    async fn ensure_notification_settings_row(&self, user_id: Uuid) -> Result<(), Status> {
        sqlx::query(
            "INSERT INTO users_app.user_notification_settings (user_id)
             VALUES ($1)
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user_id)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db notification upsert failed: {err}")))?;
        Ok(())
    }

    async fn load_user_settings(&self, user_id: Uuid) -> Result<UserSettings, Status> {
        self.ensure_notification_settings_row(user_id).await?;

        let user_row = sqlx::query(
            "SELECT
                user_id::text AS user_id,
                email,
                COALESCE(full_name, '') AS full_name,
                COALESCE(username, '') AS username,
                COALESCE(phone, '') AS phone,
                COALESCE(profile_photo_object_key, '') AS profile_photo_object_key,
                COALESCE(bio, '') AS bio,
                language,
                timezone,
                date_format,
                clock_format,
                distance_unit,
                temperature_unit,
                settings_version,
                EXTRACT(EPOCH FROM settings_updated_at)::BIGINT AS settings_updated_at,
                COALESCE(account_number, '') AS account_number,
                COALESCE(first_name, '') AS first_name,
                COALESCE(last_name, '') AS last_name,
                COALESCE(middle_name, '') AS middle_name,
                COALESCE(preferred_name, '') AS preferred_name,
                COALESCE(display_name, '') AS display_name
             FROM users_app.users
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db settings lookup failed: {err}")))?
        .ok_or_else(|| Status::not_found("user not found"))?;

        let notification_row = sqlx::query(
            "SELECT
                push_new_photo_captured,
                push_species_detected,
                push_device_offline,
                push_low_battery,
                push_storage_full,
                push_subscription_renewal_reminder,
                push_trip_activity_updates,
                email_new_photo_captured,
                email_species_detected,
                email_device_offline,
                email_low_battery,
                email_storage_full,
                email_subscription_renewal_reminder,
                email_trip_activity_updates,
                EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at
             FROM users_app.user_notification_settings
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db notification lookup failed: {err}")))?
        .ok_or_else(|| Status::internal("notification settings row missing"))?;

        let notifications =
            UserNotificationSettings {
                push_new_photo_captured: notification_row
                    .try_get("push_new_photo_captured")
                    .map_err(|err| {
                        Status::internal(format!("decode push_new_photo_captured failed: {err}"))
                    })?,
                push_species_detected: notification_row.try_get("push_species_detected").map_err(
                    |err| Status::internal(format!("decode push_species_detected failed: {err}")),
                )?,
                push_device_offline: notification_row.try_get("push_device_offline").map_err(
                    |err| Status::internal(format!("decode push_device_offline failed: {err}")),
                )?,
                push_low_battery: notification_row
                    .try_get("push_low_battery")
                    .map_err(|err| {
                        Status::internal(format!("decode push_low_battery failed: {err}"))
                    })?,
                push_storage_full: notification_row.try_get("push_storage_full").map_err(
                    |err| Status::internal(format!("decode push_storage_full failed: {err}")),
                )?,
                push_subscription_renewal_reminder: notification_row
                    .try_get("push_subscription_renewal_reminder")
                    .map_err(|err| {
                        Status::internal(format!(
                            "decode push_subscription_renewal_reminder failed: {err}"
                        ))
                    })?,
                push_trip_activity_updates: notification_row
                    .try_get("push_trip_activity_updates")
                    .map_err(|err| {
                        Status::internal(format!("decode push_trip_activity_updates failed: {err}"))
                    })?,
                email_new_photo_captured: notification_row
                    .try_get("email_new_photo_captured")
                    .map_err(|err| {
                        Status::internal(format!("decode email_new_photo_captured failed: {err}"))
                    })?,
                email_species_detected: notification_row
                    .try_get("email_species_detected")
                    .map_err(|err| {
                        Status::internal(format!("decode email_species_detected failed: {err}"))
                    })?,
                email_device_offline: notification_row.try_get("email_device_offline").map_err(
                    |err| Status::internal(format!("decode email_device_offline failed: {err}")),
                )?,
                email_low_battery: notification_row.try_get("email_low_battery").map_err(
                    |err| Status::internal(format!("decode email_low_battery failed: {err}")),
                )?,
                email_storage_full: notification_row.try_get("email_storage_full").map_err(
                    |err| Status::internal(format!("decode email_storage_full failed: {err}")),
                )?,
                email_subscription_renewal_reminder: notification_row
                    .try_get("email_subscription_renewal_reminder")
                    .map_err(|err| {
                        Status::internal(format!(
                            "decode email_subscription_renewal_reminder failed: {err}"
                        ))
                    })?,
                email_trip_activity_updates: notification_row
                    .try_get("email_trip_activity_updates")
                    .map_err(|err| {
                        Status::internal(format!(
                            "decode email_trip_activity_updates failed: {err}"
                        ))
                    })?,
                updated_at: notification_row.try_get("updated_at").map_err(|err| {
                    Status::internal(format!("decode notification updated_at failed: {err}"))
                })?,
            };

        Ok(UserSettings {
            user_id: user_row
                .try_get("user_id")
                .map_err(|err| Status::internal(format!("decode user_id failed: {err}")))?,
            email: user_row
                .try_get("email")
                .map_err(|err| Status::internal(format!("decode email failed: {err}")))?,
            full_name: user_row
                .try_get("full_name")
                .map_err(|err| Status::internal(format!("decode full_name failed: {err}")))?,
            username: user_row
                .try_get("username")
                .map_err(|err| Status::internal(format!("decode username failed: {err}")))?,
            phone: user_row
                .try_get("phone")
                .map_err(|err| Status::internal(format!("decode phone failed: {err}")))?,
            profile_photo_object_key: user_row.try_get("profile_photo_object_key").map_err(
                |err| Status::internal(format!("decode profile_photo_object_key failed: {err}")),
            )?,
            bio: user_row
                .try_get("bio")
                .map_err(|err| Status::internal(format!("decode bio failed: {err}")))?,
            language: user_row
                .try_get("language")
                .map_err(|err| Status::internal(format!("decode language failed: {err}")))?,
            timezone: user_row
                .try_get("timezone")
                .map_err(|err| Status::internal(format!("decode timezone failed: {err}")))?,
            date_format: user_row
                .try_get("date_format")
                .map_err(|err| Status::internal(format!("decode date_format failed: {err}")))?,
            clock_format: user_row
                .try_get("clock_format")
                .map_err(|err| Status::internal(format!("decode clock_format failed: {err}")))?,
            distance_unit: user_row
                .try_get("distance_unit")
                .map_err(|err| Status::internal(format!("decode distance_unit failed: {err}")))?,
            temperature_unit: user_row.try_get("temperature_unit").map_err(|err| {
                Status::internal(format!("decode temperature_unit failed: {err}"))
            })?,
            settings_version: user_row.try_get("settings_version").map_err(|err| {
                Status::internal(format!("decode settings_version failed: {err}"))
            })?,
            settings_updated_at: user_row.try_get("settings_updated_at").map_err(|err| {
                Status::internal(format!("decode settings_updated_at failed: {err}"))
            })?,
            notifications: Some(notifications),
            account_number: user_row
                .try_get::<Option<String>, _>("account_number")
                .unwrap_or(None)
                .unwrap_or_default(),
            first_name: user_row
                .try_get("first_name")
                .map_err(|err| Status::internal(format!("decode first_name failed: {err}")))?,
            last_name: user_row
                .try_get("last_name")
                .map_err(|err| Status::internal(format!("decode last_name failed: {err}")))?,
            middle_name: user_row
                .try_get("middle_name")
                .map_err(|err| Status::internal(format!("decode middle_name failed: {err}")))?,
            preferred_name: user_row
                .try_get("preferred_name")
                .map_err(|err| Status::internal(format!("decode preferred_name failed: {err}")))?,
            display_name: user_row
                .try_get("display_name")
                .map_err(|err| Status::internal(format!("decode display_name failed: {err}")))?,
        })
    }
}

#[tonic::async_trait]
impl UsersService for UsersGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "auth-service",
                "public-service",
                "control-service",
                "gateway-service",
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

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["auth-service", "public-service", "control-service"],
        )?;

        let payload = request.into_inner();
        if payload.email.trim().is_empty() {
            return Err(Status::invalid_argument("email is required"));
        }

        let user_id = if payload.user_id.trim().is_empty() {
            Uuid::new_v4().to_string()
        } else {
            payload.user_id
        };
        let user_uuid = parse_user_uuid(user_id.as_str())?;

        let first_name = if payload.first_name.trim().is_empty() {
            None
        } else {
            Some(payload.first_name.trim().to_string())
        };
        let last_name = if payload.last_name.trim().is_empty() {
            None
        } else {
            Some(payload.last_name.trim().to_string())
        };
        let middle_name = if payload.middle_name.trim().is_empty() {
            None
        } else {
            Some(payload.middle_name.trim().to_string())
        };

        sqlx::query(
            "INSERT INTO users_app.users (
                user_id,
                email,
                status,
                perm_rev,
                timezone,
                first_name,
                last_name,
                middle_name,
                created_at,
                updated_at,
                settings_updated_at
             ) VALUES ($1, $2, 'active', 1, 'UTC', $3, $4, $5, NOW(), NOW(), NOW())
             ON CONFLICT (user_id)
             DO UPDATE
             SET email = EXCLUDED.email,
                 first_name = COALESCE(EXCLUDED.first_name, users_app.users.first_name),
                 last_name = COALESCE(EXCLUDED.last_name, users_app.users.last_name),
                 middle_name = COALESCE(EXCLUDED.middle_name, users_app.users.middle_name),
                 updated_at = NOW()",
        )
        .bind(user_uuid)
        .bind(payload.email.as_str())
        .bind(&first_name)
        .bind(&last_name)
        .bind(&middle_name)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db create_user upsert failed: {err}")))?;
        sqlx::query(
            "INSERT INTO users_app.role_assignments (user_id, role)
             VALUES ($1, 'user')
             ON CONFLICT (user_id, role) DO NOTHING",
        )
        .bind(user_uuid)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db default role upsert failed: {err}")))?;
        self.ensure_notification_settings_row(user_uuid).await?;

        let mut users = self.state.users.lock().await;
        let user = users
            .entry(user_id.clone())
            .or_insert_with(|| UserRecordData::new(user_id.clone(), payload.email));

        Ok(Response::new(CreateUserResponse {
            user: Some(Self::to_proto(user)),
        }))
    }

    async fn get_user_auth_state(
        &self,
        request: Request<GetUserAuthStateRequest>,
    ) -> Result<Response<GetUserAuthStateResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "auth-service",
                "gateway-service",
                "control-service",
                "public-service",
            ],
        )?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        self.ensure_user_cached(payload.user_id.trim()).await?;

        let users = self.state.users.lock().await;
        let user = users
            .get(payload.user_id.trim())
            .ok_or_else(|| Status::not_found("user not found"))?;

        Ok(Response::new(GetUserAuthStateResponse {
            user_id: user.user_id.clone(),
            status: user.status.clone(),
            roles: user.roles.clone(),
            perm_rev: user.perm_rev,
            scopes: user.scopes.clone(),
        }))
    }

    async fn update_user_roles(
        &self,
        request: Request<UpdateUserRolesRequest>,
    ) -> Result<Response<UpdateUserRolesResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        self.ensure_user_cached(payload.user_id.trim()).await?;

        let normalized = roles::normalize_roles(payload.roles);
        if normalized.is_empty() {
            return Err(Status::invalid_argument("roles are required"));
        }
        let user_uuid = parse_user_uuid(payload.user_id.trim())?;
        self.replace_role_assignments(user_uuid, &normalized)
            .await?;

        let mut users = self.state.users.lock().await;
        let user = users
            .get_mut(payload.user_id.trim())
            .ok_or_else(|| Status::not_found("user not found"))?;
        user.roles = normalized.clone();
        user.perm_rev = permissions::bump_perm_rev(user.perm_rev);
        user.updated_at = Utc::now().timestamp();
        let perm_rev = user.perm_rev;
        drop(users);
        self.persist_auth_state(user_uuid, None, perm_rev).await?;

        Ok(Response::new(UpdateUserRolesResponse {
            user_id: payload.user_id,
            roles: normalized,
            perm_rev,
        }))
    }

    async fn update_user_scopes(
        &self,
        request: Request<UpdateUserScopesRequest>,
    ) -> Result<Response<UpdateUserScopesResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        self.ensure_user_cached(payload.user_id.trim()).await?;

        let normalized = scopes::normalize_scopes(payload.scopes);
        let user_uuid = parse_user_uuid(payload.user_id.trim())?;
        self.replace_scope_assignments(user_uuid, &normalized)
            .await?;

        let mut users = self.state.users.lock().await;
        let user = users
            .get_mut(payload.user_id.trim())
            .ok_or_else(|| Status::not_found("user not found"))?;
        user.scopes = normalized.clone();
        user.perm_rev = permissions::bump_perm_rev(user.perm_rev);
        user.updated_at = Utc::now().timestamp();
        let perm_rev = user.perm_rev;
        drop(users);
        self.persist_auth_state(user_uuid, None, perm_rev).await?;

        Ok(Response::new(UpdateUserScopesResponse {
            user_id: payload.user_id,
            scopes: normalized,
            perm_rev,
        }))
    }

    async fn disable_user(
        &self,
        request: Request<DisableUserRequest>,
    ) -> Result<Response<DisableUserResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        self.ensure_user_cached(payload.user_id.trim()).await?;
        let user_uuid = parse_user_uuid(payload.user_id.trim())?;

        let mut users = self.state.users.lock().await;
        let user = users
            .get_mut(payload.user_id.trim())
            .ok_or_else(|| Status::not_found("user not found"))?;
        user.status = "disabled".to_string();
        user.perm_rev = permissions::bump_perm_rev(user.perm_rev);
        user.updated_at = Utc::now().timestamp();
        let status = user.status.clone();
        let perm_rev = user.perm_rev;
        drop(users);
        self.persist_auth_state(user_uuid, Some(status.as_str()), perm_rev)
            .await?;

        Ok(Response::new(DisableUserResponse {
            user_id: payload.user_id,
            status,
            perm_rev,
        }))
    }

    async fn bump_perm_revision(
        &self,
        request: Request<BumpPermRevisionRequest>,
    ) -> Result<Response<BumpPermRevisionResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["control-service", "auth-service"],
        )?;

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        self.ensure_user_cached(payload.user_id.trim()).await?;

        let mut users = self.state.users.lock().await;
        let user = users
            .get_mut(payload.user_id.trim())
            .ok_or_else(|| Status::not_found("user not found"))?;
        user.perm_rev = permissions::bump_perm_rev(user.perm_rev);
        user.updated_at = Utc::now().timestamp();
        let user_uuid = parse_user_uuid(payload.user_id.trim())?;
        let perm_rev = user.perm_rev;
        drop(users);
        self.persist_auth_state(user_uuid, None, perm_rev).await?;

        Ok(Response::new(BumpPermRevisionResponse {
            user_id: payload.user_id,
            perm_rev,
        }))
    }

    async fn get_user_settings(
        &self,
        request: Request<GetUserSettingsRequest>,
    ) -> Result<Response<GetUserSettingsResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "public-service"],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(
            caller.as_str(),
            auth_sub.as_deref(),
            payload.user_id.as_str(),
        )?;
        let user_uuid = parse_user_uuid(payload.user_id.as_str())?;

        let settings = self.load_user_settings(user_uuid).await?;
        Ok(Response::new(GetUserSettingsResponse {
            settings: Some(settings),
        }))
    }

    async fn update_user_settings(
        &self,
        request: Request<UpdateUserSettingsRequest>,
    ) -> Result<Response<UpdateUserSettingsResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(
            caller.as_str(),
            auth_sub.as_deref(),
            payload.user_id.as_str(),
        )?;
        let user_uuid = parse_user_uuid(payload.user_id.as_str())?;
        self.ensure_user_exists(user_uuid).await?;

        let has_full_name = payload.full_name.is_some();
        let has_username = payload.username.is_some();
        let has_phone = payload.phone.is_some();
        let has_profile_photo_object_key = payload.profile_photo_object_key.is_some();
        let has_bio = payload.bio.is_some();
        let has_language = payload.language.is_some();
        let has_timezone = payload.timezone.is_some();
        let has_date_format = payload.date_format.is_some();
        let has_clock_format = payload.clock_format.is_some();
        let has_distance_unit = payload.distance_unit.is_some();
        let has_temperature_unit = payload.temperature_unit.is_some();
        let has_first_name = payload.first_name.is_some();
        let has_last_name = payload.last_name.is_some();
        let has_middle_name = payload.middle_name.is_some();
        let has_preferred_name = payload.preferred_name.is_some();
        let has_display_name = payload.display_name.is_some();

        if !has_full_name
            && !has_username
            && !has_phone
            && !has_profile_photo_object_key
            && !has_bio
            && !has_language
            && !has_timezone
            && !has_date_format
            && !has_clock_format
            && !has_distance_unit
            && !has_temperature_unit
            && !has_first_name
            && !has_last_name
            && !has_middle_name
            && !has_preferred_name
            && !has_display_name
        {
            return Err(Status::invalid_argument("no settings fields provided"));
        }

        let full_name = normalize_nullable_text(payload.full_name, "full_name", 120)?;
        let username = normalize_username(payload.username)?;
        let phone = normalize_phone(payload.phone)?;
        let profile_photo_object_key =
            normalize_profile_photo_object_key(payload.profile_photo_object_key, &payload.user_id)?;
        let bio = normalize_nullable_text(payload.bio, "bio", 512)?;
        let language = normalize_language(payload.language)?;
        let timezone = normalize_timezone(payload.timezone)?;
        let date_format = normalize_date_format(payload.date_format)?;
        let clock_format = normalize_clock_format(payload.clock_format)?;
        let distance_unit = normalize_distance_unit(payload.distance_unit)?;
        let temperature_unit = normalize_temperature_unit(payload.temperature_unit)?;
        let first_name = normalize_nullable_text(payload.first_name, "first_name", 80)?;
        let last_name = normalize_nullable_text(payload.last_name, "last_name", 80)?;
        let middle_name = normalize_nullable_text(payload.middle_name, "middle_name", 80)?;
        let preferred_name = normalize_nullable_text(payload.preferred_name, "preferred_name", 80)?;
        let display_name_val = normalize_nullable_text(payload.display_name, "display_name", 80)?;

        if has_profile_photo_object_key {
            if let Some(object_key) = profile_photo_object_key.as_deref() {
                let metadata_response = {
                    let mut storage_client = self.state.storage_client.lock().await;
                    storage_client
                        .get_object_metadata(StorageGetObjectMetadataRequest {
                            object_key: object_key.to_string(),
                        })
                        .await
                }
                .map_err(|err| {
                    Status::invalid_argument(format!(
                        "profile_photo_object_key metadata lookup failed: {err}"
                    ))
                })?;

                let metadata = metadata_response.metadata.ok_or_else(|| {
                    Status::invalid_argument("profile_photo_object_key metadata is missing")
                })?;
                if profile_photo_content_type_to_extension(metadata.content_type.as_str()).is_none()
                {
                    return Err(Status::invalid_argument(
                        "profile_photo_object_key content_type is not allowed",
                    ));
                }
                if metadata.content_length == 0 || metadata.content_length > PROFILE_PHOTO_MAX_BYTES
                {
                    return Err(Status::invalid_argument(
                        "profile_photo_object_key content_length is out of allowed range",
                    ));
                }
            }
        }

        let update_result = sqlx::query(
            "UPDATE users_app.users
             SET
               full_name = CASE WHEN $2 THEN $3 ELSE full_name END,
               username = CASE WHEN $4 THEN $5 ELSE username END,
               phone = CASE WHEN $6 THEN $7 ELSE phone END,
               profile_photo_object_key = CASE WHEN $8 THEN $9 ELSE profile_photo_object_key END,
               bio = CASE WHEN $10 THEN $11 ELSE bio END,
               language = CASE WHEN $12 THEN $13 ELSE language END,
               timezone = CASE WHEN $14 THEN $15 ELSE timezone END,
               date_format = CASE WHEN $16 THEN $17 ELSE date_format END,
               clock_format = CASE WHEN $18 THEN $19 ELSE clock_format END,
               distance_unit = CASE WHEN $20 THEN $21 ELSE distance_unit END,
               temperature_unit = CASE WHEN $22 THEN $23 ELSE temperature_unit END,
               first_name = CASE WHEN $24 THEN $25 ELSE first_name END,
               last_name = CASE WHEN $26 THEN $27 ELSE last_name END,
               middle_name = CASE WHEN $28 THEN $29 ELSE middle_name END,
               preferred_name = CASE WHEN $30 THEN $31 ELSE preferred_name END,
               display_name = CASE WHEN $32 THEN $33 ELSE display_name END,
               settings_version = settings_version + 1,
               settings_updated_at = NOW(),
               updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_uuid)
        .bind(has_full_name)
        .bind(full_name)
        .bind(has_username)
        .bind(username)
        .bind(has_phone)
        .bind(phone)
        .bind(has_profile_photo_object_key)
        .bind(profile_photo_object_key)
        .bind(has_bio)
        .bind(bio)
        .bind(has_language)
        .bind(language)
        .bind(has_timezone)
        .bind(timezone)
        .bind(has_date_format)
        .bind(date_format)
        .bind(has_clock_format)
        .bind(clock_format)
        .bind(has_distance_unit)
        .bind(distance_unit)
        .bind(has_temperature_unit)
        .bind(temperature_unit)
        .bind(has_first_name)
        .bind(first_name)
        .bind(has_last_name)
        .bind(last_name)
        .bind(has_middle_name)
        .bind(middle_name)
        .bind(has_preferred_name)
        .bind(preferred_name)
        .bind(has_display_name)
        .bind(display_name_val)
        .execute(&self.state.db)
        .await;

        match update_result {
            Ok(result) => {
                if result.rows_affected() == 0 {
                    return Err(Status::not_found("user not found"));
                }
            }
            Err(err) => {
                if is_unique_violation(&err) {
                    return Err(Status::already_exists("username is already in use"));
                }
                return Err(Status::internal(format!(
                    "db update settings failed: {err}"
                )));
            }
        }

        let settings = self.load_user_settings(user_uuid).await?;
        Ok(Response::new(UpdateUserSettingsResponse {
            settings: Some(settings),
        }))
    }

    async fn update_user_notification_settings(
        &self,
        request: Request<UpdateUserNotificationSettingsRequest>,
    ) -> Result<Response<UpdateUserNotificationSettingsResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(
            caller.as_str(),
            auth_sub.as_deref(),
            payload.user_id.as_str(),
        )?;
        let user_uuid = parse_user_uuid(payload.user_id.as_str())?;
        self.ensure_user_exists(user_uuid).await?;
        self.ensure_notification_settings_row(user_uuid).await?;

        let has_push_new_photo_captured = payload.push_new_photo_captured.is_some();
        let has_push_species_detected = payload.push_species_detected.is_some();
        let has_push_device_offline = payload.push_device_offline.is_some();
        let has_push_low_battery = payload.push_low_battery.is_some();
        let has_push_storage_full = payload.push_storage_full.is_some();
        let has_push_subscription_renewal_reminder =
            payload.push_subscription_renewal_reminder.is_some();
        let has_push_trip_activity_updates = payload.push_trip_activity_updates.is_some();
        let has_email_new_photo_captured = payload.email_new_photo_captured.is_some();
        let has_email_species_detected = payload.email_species_detected.is_some();
        let has_email_device_offline = payload.email_device_offline.is_some();
        let has_email_low_battery = payload.email_low_battery.is_some();
        let has_email_storage_full = payload.email_storage_full.is_some();
        let has_email_subscription_renewal_reminder =
            payload.email_subscription_renewal_reminder.is_some();
        let has_email_trip_activity_updates = payload.email_trip_activity_updates.is_some();

        if !has_push_new_photo_captured
            && !has_push_species_detected
            && !has_push_device_offline
            && !has_push_low_battery
            && !has_push_storage_full
            && !has_push_subscription_renewal_reminder
            && !has_push_trip_activity_updates
            && !has_email_new_photo_captured
            && !has_email_species_detected
            && !has_email_device_offline
            && !has_email_low_battery
            && !has_email_storage_full
            && !has_email_subscription_renewal_reminder
            && !has_email_trip_activity_updates
        {
            return Err(Status::invalid_argument(
                "no notification settings fields provided",
            ));
        }

        sqlx::query(
            "UPDATE users_app.user_notification_settings
             SET
               push_new_photo_captured = CASE WHEN $2 THEN $3 ELSE push_new_photo_captured END,
               push_species_detected = CASE WHEN $4 THEN $5 ELSE push_species_detected END,
               push_device_offline = CASE WHEN $6 THEN $7 ELSE push_device_offline END,
               push_low_battery = CASE WHEN $8 THEN $9 ELSE push_low_battery END,
               push_storage_full = CASE WHEN $10 THEN $11 ELSE push_storage_full END,
               push_subscription_renewal_reminder = CASE WHEN $12 THEN $13 ELSE push_subscription_renewal_reminder END,
               push_trip_activity_updates = CASE WHEN $14 THEN $15 ELSE push_trip_activity_updates END,
               email_new_photo_captured = CASE WHEN $16 THEN $17 ELSE email_new_photo_captured END,
               email_species_detected = CASE WHEN $18 THEN $19 ELSE email_species_detected END,
               email_device_offline = CASE WHEN $20 THEN $21 ELSE email_device_offline END,
               email_low_battery = CASE WHEN $22 THEN $23 ELSE email_low_battery END,
               email_storage_full = CASE WHEN $24 THEN $25 ELSE email_storage_full END,
               email_subscription_renewal_reminder = CASE WHEN $26 THEN $27 ELSE email_subscription_renewal_reminder END,
               email_trip_activity_updates = CASE WHEN $28 THEN $29 ELSE email_trip_activity_updates END,
               updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_uuid)
        .bind(has_push_new_photo_captured)
        .bind(payload.push_new_photo_captured.unwrap_or(false))
        .bind(has_push_species_detected)
        .bind(payload.push_species_detected.unwrap_or(false))
        .bind(has_push_device_offline)
        .bind(payload.push_device_offline.unwrap_or(false))
        .bind(has_push_low_battery)
        .bind(payload.push_low_battery.unwrap_or(false))
        .bind(has_push_storage_full)
        .bind(payload.push_storage_full.unwrap_or(false))
        .bind(has_push_subscription_renewal_reminder)
        .bind(payload.push_subscription_renewal_reminder.unwrap_or(false))
        .bind(has_push_trip_activity_updates)
        .bind(payload.push_trip_activity_updates.unwrap_or(false))
        .bind(has_email_new_photo_captured)
        .bind(payload.email_new_photo_captured.unwrap_or(false))
        .bind(has_email_species_detected)
        .bind(payload.email_species_detected.unwrap_or(false))
        .bind(has_email_device_offline)
        .bind(payload.email_device_offline.unwrap_or(false))
        .bind(has_email_low_battery)
        .bind(payload.email_low_battery.unwrap_or(false))
        .bind(has_email_storage_full)
        .bind(payload.email_storage_full.unwrap_or(false))
        .bind(has_email_subscription_renewal_reminder)
        .bind(payload.email_subscription_renewal_reminder.unwrap_or(false))
        .bind(has_email_trip_activity_updates)
        .bind(payload.email_trip_activity_updates.unwrap_or(false))
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db update notification settings failed: {err}")))?;

        sqlx::query(
            "UPDATE users_app.users
             SET settings_version = settings_version + 1,
                 settings_updated_at = NOW(),
                 updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_uuid)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db update settings version failed: {err}")))?;

        let settings = self.load_user_settings(user_uuid).await?;
        Ok(Response::new(UpdateUserNotificationSettingsResponse {
            settings: Some(settings),
        }))
    }

    async fn create_profile_photo_upload_ticket(
        &self,
        request: Request<CreateProfilePhotoUploadTicketRequest>,
    ) -> Result<Response<CreateProfilePhotoUploadTicketResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        enforce_subject_ownership(
            caller.as_str(),
            auth_sub.as_deref(),
            payload.user_id.as_str(),
        )?;
        let user_uuid = parse_user_uuid(payload.user_id.as_str())?;
        self.ensure_user_exists(user_uuid).await?;

        let (content_type, _extension) = profile_photo_content_type_to_extension(
            payload.content_type.as_str(),
        )
        .ok_or_else(|| {
            Status::invalid_argument(
                "content_type must be one of image/jpeg, image/png, image/webp",
            )
        })?;
        if payload.content_length == 0 || payload.content_length > PROFILE_PHOTO_MAX_BYTES {
            return Err(Status::invalid_argument(
                "content_length must be between 1 and 5242880 bytes",
            ));
        }

        let ticket = {
            let mut storage_client = self.state.storage_client.lock().await;
            storage_client
                .create_profile_photo_upload_ticket(StorageCreateProfilePhotoUploadTicketRequest {
                    owner_id: payload.user_id.clone(),
                    content_type: content_type.to_string(),
                    content_length: payload.content_length,
                    expires_in_seconds: PROFILE_PHOTO_SIGNED_URL_TTL_SECONDS,
                })
                .await
                .map_err(|err| Status::internal(format!("storage upload ticket error: {err}")))?
        };

        Ok(Response::new(CreateProfilePhotoUploadTicketResponse {
            object_key: ticket.object_key,
            upload_url: ticket.upload_url,
            method: ticket.method,
            expires_at: ticket.expires_at,
            required_headers: ticket.required_headers,
            content_type: ticket.content_type,
            max_bytes: ticket.max_bytes,
        }))
    }

    async fn create_profile_photo_download_url(
        &self,
        request: Request<CreateProfilePhotoDownloadUrlRequest>,
    ) -> Result<Response<CreateProfilePhotoDownloadUrlResponse>, Status> {
        let caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;
        let auth_sub = metadata_value(&request, "x-auth-sub");
        let payload = request.into_inner();

        if payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }
        if payload.object_key.trim().is_empty() {
            return Err(Status::invalid_argument("object_key is required"));
        }
        enforce_subject_ownership(
            caller.as_str(),
            auth_sub.as_deref(),
            payload.user_id.as_str(),
        )?;
        let user_uuid = parse_user_uuid(payload.user_id.as_str())?;
        self.ensure_user_exists(user_uuid).await?;
        validate_profile_photo_key_ownership(
            payload.user_id.as_str(),
            payload.object_key.as_str(),
        )?;

        let response = {
            let mut storage_client = self.state.storage_client.lock().await;
            storage_client
                .create_profile_photo_download_url(StorageCreateProfilePhotoDownloadUrlRequest {
                    owner_id: payload.user_id.clone(),
                    object_key: payload.object_key.clone(),
                    expires_in_seconds: PROFILE_PHOTO_SIGNED_URL_TTL_SECONDS,
                })
                .await
                .map_err(|err| Status::internal(format!("storage download url error: {err}")))?
        };

        Ok(Response::new(CreateProfilePhotoDownloadUrlResponse {
            object_key: response.object_key,
            download_url: response.download_url,
            method: response.method,
            expires_at: response.expires_at,
        }))
    }
}

fn parse_user_uuid(user_id: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(user_id.trim())
        .map_err(|_| Status::invalid_argument("user_id must be a valid UUID"))
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

fn normalize_nullable_text(
    value: Option<String>,
    field_name: &str,
    max_len: usize,
) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > max_len {
        return Err(Status::invalid_argument(format!(
            "{field_name} exceeds max length of {max_len}",
        )));
    }
    Ok(Some(trimmed.to_string()))
}

fn normalize_username(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.len() < 3 || normalized.len() > 32 {
        return Err(Status::invalid_argument(
            "username length must be between 3 and 32 characters",
        ));
    }
    if !normalized.chars().all(|ch| {
        ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_' || ch == '-'
    }) {
        return Err(Status::invalid_argument(
            "username may only include lowercase letters, numbers, '.', '_' and '-'",
        ));
    }
    if !normalized
        .chars()
        .next()
        .map(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        .unwrap_or(false)
    {
        return Err(Status::invalid_argument(
            "username must start with a lowercase letter or number",
        ));
    }
    Ok(Some(normalized))
}

fn normalize_phone(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let phone = trimmed.to_string();
    let bytes = phone.as_bytes();
    if bytes.len() < 9 || bytes.len() > 16 || bytes[0] != b'+' {
        return Err(Status::invalid_argument("phone must use E.164 format"));
    }
    if bytes[1] == b'0' || !bytes[1..].iter().all(|b| b.is_ascii_digit()) {
        return Err(Status::invalid_argument("phone must use E.164 format"));
    }
    Ok(Some(phone))
}

fn normalize_language(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let language = value.trim();
    if language.is_empty() {
        return Err(Status::invalid_argument("language cannot be empty"));
    }
    if !language
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return Err(Status::invalid_argument(
            "language must be a valid BCP-47 style tag",
        ));
    }
    Ok(Some(language.to_ascii_lowercase()))
}

fn normalize_timezone(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let timezone = value.trim();
    if timezone.is_empty() {
        return Err(Status::invalid_argument("timezone cannot be empty"));
    }
    timezone
        .parse::<Tz>()
        .map(|tz| Some(tz.to_string()))
        .map_err(|_| Status::invalid_argument("timezone must be a valid IANA timezone"))
}

fn normalize_date_format(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim() {
        "YYYY-MM-DD" => Ok(Some("YYYY-MM-DD".to_string())),
        "DD-MM-YYYY" => Ok(Some("DD-MM-YYYY".to_string())),
        _ => Err(Status::invalid_argument(
            "date_format must be YYYY-MM-DD or DD-MM-YYYY",
        )),
    }
}

fn normalize_clock_format(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim() {
        "12h" => Ok(Some("12h".to_string())),
        "24h" => Ok(Some("24h".to_string())),
        _ => Err(Status::invalid_argument("clock_format must be 12h or 24h")),
    }
}

fn normalize_distance_unit(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim() {
        "km" => Ok(Some("km".to_string())),
        "miles" => Ok(Some("miles".to_string())),
        _ => Err(Status::invalid_argument(
            "distance_unit must be km or miles",
        )),
    }
}

fn normalize_temperature_unit(value: Option<String>) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim() {
        "C" => Ok(Some("C".to_string())),
        "F" => Ok(Some("F".to_string())),
        _ => Err(Status::invalid_argument("temperature_unit must be C or F")),
    }
}

fn profile_photo_content_type_to_extension(
    content_type: &str,
) -> Option<(&'static str, &'static str)> {
    match content_type.trim().to_ascii_lowercase().as_str() {
        "image/jpeg" | "image/jpg" => Some(("image/jpeg", "jpg")),
        "image/png" => Some(("image/png", "png")),
        "image/webp" => Some(("image/webp", "webp")),
        _ => None,
    }
}

fn normalize_profile_photo_object_key(
    value: Option<String>,
    user_id: &str,
) -> Result<Option<String>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    let key = value.trim();
    if key.is_empty() {
        return Ok(None);
    }
    validate_profile_photo_key_ownership(user_id, key)?;
    Ok(Some(key.to_string()))
}

fn validate_profile_photo_key_ownership(user_id: &str, object_key: &str) -> Result<(), Status> {
    let prefix = format!("users/{user_id}/profile/");
    if !object_key.starts_with(prefix.as_str()) {
        return Err(Status::invalid_argument(
            "profile_photo_object_key must be within the authenticated user profile prefix",
        ));
    }
    if !(object_key.ends_with(".jpg")
        || object_key.ends_with(".jpeg")
        || object_key.ends_with(".png")
        || object_key.ends_with(".webp"))
    {
        return Err(Status::invalid_argument(
            "profile_photo_object_key must end with .jpg, .jpeg, .png, or .webp",
        ));
    }
    Ok(())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.code().as_deref() == Some("23505"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_username_accepts_expected_format() {
        let normalized = normalize_username(Some("User.Name-01".to_string()))
            .expect("username should normalize")
            .expect("username should be present");
        assert_eq!(normalized, "user.name-01");
    }

    #[test]
    fn normalize_username_rejects_invalid_chars() {
        let err = normalize_username(Some("bad*name".to_string())).expect_err("expected error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn normalize_timezone_rejects_invalid_iana_name() {
        let err = normalize_timezone(Some("Mars/Olympus".to_string())).expect_err("expected error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn profile_photo_content_type_mapping_allows_expected_types() {
        assert_eq!(
            profile_photo_content_type_to_extension("image/jpeg"),
            Some(("image/jpeg", "jpg"))
        );
        assert_eq!(
            profile_photo_content_type_to_extension("image/png"),
            Some(("image/png", "png"))
        );
        assert_eq!(
            profile_photo_content_type_to_extension("image/webp"),
            Some(("image/webp", "webp"))
        );
        assert!(profile_photo_content_type_to_extension("application/json").is_none());
    }

    #[test]
    fn profile_photo_key_ownership_requires_user_prefix() {
        let user_id = "9f83c2a1-1111-4444-8888-abcdefabcdef";
        let allowed_key = format!("users/{user_id}/profile/abc123.jpg");
        validate_profile_photo_key_ownership(user_id, allowed_key.as_str())
            .expect("expected scoped key to pass");
        let denied =
            validate_profile_photo_key_ownership(user_id, "users/another-user/profile/abc123.jpg")
                .expect_err("expected mismatched prefix to fail");
        assert_eq!(denied.code(), tonic::Code::InvalidArgument);
    }
}

#[tokio::main]
async fn main() {
    init_tracing("users-service");

    let grpc_addr = env::var("USERS_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50057".to_string())
        .parse::<SocketAddr>()
        .expect("invalid USERS_GRPC_BIND_ADDR");

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://yugabyte@127.0.0.1:5433/wildon".to_string());
    let database_max_connections = env::var("USERS_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    let storage_grpc_endpoint =
        env::var("STORAGE_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());

    let db = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .connect(&database_url)
        .await
        .expect("failed to connect users-service db");
    let storage_client = StorageSdkClient::connect_as(storage_grpc_endpoint, "users-service")
        .await
        .expect("failed to connect to storage-service grpc endpoint");

    let grpc = UsersGrpc {
        state: AppState::new(db, storage_client),
        internal_auth: InternalAuthPolicy::from_env("users-service"),
    };

    tracing::info!(address = %grpc_addr, "users grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<UsersServiceServer<UsersGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply users grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(UsersServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("users grpc server failed");
}
