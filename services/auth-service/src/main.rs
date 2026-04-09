#![allow(dead_code)]

mod modules;
mod routes;
mod state;

use crate::{
    modules::mfa::{
        build_otpauth_qr_svg_data_uri, build_otpauth_uri, generate_authenticator_secret_base32,
        generate_backup_codes, normalize_backup_code, verify_authenticator_totp,
    },
    modules::sessions::{
        issue_session_tokens, list_sessions_for_user, logout_session_by_id,
        logout_session_by_refresh_token, refresh_session_tokens, revoke_all_sessions_for_user,
        run_cleanup_once, validate_claims_against_session, IssueSessionInput, ListSessionsInput,
        LogoutSessionByIdInput, LogoutSessionInput, RefreshSessionInput, RevokeAllSessionsInput,
        SessionError,
    },
    state::{AppState, TokenPolicyConfig},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use auth::jwt;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use config::grpc::{
    authorize_internal_request, connect_channel, inject_internal_metadata, load_server_tls_config,
    metadata_value, InternalAuthPolicy,
};
use contracts::wildon::auth::v1::{
    auth_service_server::{AuthService, AuthServiceServer},
    BeginAuthenticatorEnrollmentRequest, BeginAuthenticatorEnrollmentResponse,
    ChangePasswordRequest, ChangePasswordResponse, ConfirmAuthenticatorEnrollmentRequest,
    ConfirmAuthenticatorEnrollmentResponse, ConfirmEmailVerificationOtpRequest,
    ConfirmEmailVerificationOtpResponse, DisableMfaFactorRequest, DisableMfaFactorResponse,
    GetMfaStatusRequest, GetMfaStatusResponse, HealthRequest, HealthResponse, IssueTokenRequest,
    IssueTokenResponse, Jwk, JwksRequest, JwksResponse, ListSessionsRequest, ListSessionsResponse,
    LoginWithPasswordRequest, LogoutAllSessionsRequest, LogoutAllSessionsResponse,
    LogoutSessionByIdRequest, LogoutSessionByIdResponse, LogoutSessionRequest,
    LogoutSessionResponse, MfaFactorSummary, OAuthAuthorizeRequest, OAuthAuthorizeResponse,
    OAuthIntrospectRequest, OAuthIntrospectResponse, OAuthRevokeRequest, OAuthRevokeResponse,
    OAuthTokenExchangeRequest, OAuthTokenExchangeResponse, OidcDiscoveryRequest,
    OidcDiscoveryResponse, RefreshTokenRequest, RegenerateBackupCodesRequest,
    RegenerateBackupCodesResponse, RegisterUserRequest, RegisterUserResponse,
    RequestEmailVerificationOtpRequest, RequestEmailVerificationOtpResponse,
    RequestPasswordResetOtpRequest, RequestPasswordResetOtpResponse, ResetPasswordRequest,
    ResetPasswordResponse, SessionSummary, SocialLoginAppleRequest, SocialLoginGoogleRequest,
    UserInfoRequest, UserInfoResponse, ValidateAccessTokenRequest, ValidateAccessTokenResponse,
    VerifyLoginMfaRequest, VerifyPasswordResetOtpRequest, VerifyPasswordResetOtpResponse,
};
use contracts::wildon::users::v1::users_service_client::UsersServiceClient;
use ipnet::IpNet;
use observability::init_tracing;
use provider_clients::{
    sendgrid::SendgridClient, NotificationChannel, NotificationPayload, NotificationProvider,
};
use rand::{Rng, RngCore};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    str::FromStr,
};
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct AuthGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
}

const AUTH_TEMPLATE_EMAIL_OTP: &str = "email-otp";
const AUTH_TEMPLATE_EMAIL_WELCOME: &str = "welcome";
const AUTH_TEMPLATE_PASSWORD_RESET_REQUEST: &str = "password-reset-request";
const AUTH_TEMPLATE_PASSWORD_CHANGED_SUCCESS: &str = "password-changed-success";
const MFA_FACTOR_AUTHENTICATOR: &str = "authenticator";
const MFA_FACTOR_SMS: &str = "sms";
const MFA_FACTOR_BACKUP_CODE: &str = "backup_code";

#[derive(Debug, Clone)]
struct MfaAuthenticatorFactor {
    id: Uuid,
    secret_base32: String,
}

#[derive(Debug, Clone)]
struct MfaBackupCodeRecord {
    id: Uuid,
    factor_id: Uuid,
}

#[derive(Debug, Clone)]
struct MfaLoginChallenge {
    id: Uuid,
    user_id: Uuid,
    factor_type: String,
    aud: String,
    realm: String,
    client_id: Option<String>,
    device_id: Option<String>,
    device_fingerprint_hash: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    remember_me: bool,
    expires_at: chrono::DateTime<chrono::Utc>,
    attempts: i32,
}

#[derive(Debug, Clone)]
struct AuditorAccessPolicy {
    is_active: bool,
    expires_at: chrono::DateTime<chrono::Utc>,
    allowed_ips: Option<Vec<String>>,
}

#[tonic::async_trait]
impl AuthService for AuthGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "public-service"],
        )?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("missing")
            .to_string();

        tracing::info!(request_id = %request_id, "auth grpc health request");

        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            request_id,
        }))
    }

    async fn issue_token(
        &self,
        request: Request<IssueTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let x_forwarded_for = request
            .metadata()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let payload = request.into_inner();
        if payload.sub.is_empty() || payload.aud.is_empty() || payload.realm.is_empty() {
            return Err(Status::invalid_argument("sub, aud, and realm are required"));
        }

        let issued = issue_session_tokens(
            &self.state,
            IssueSessionInput {
                sub: payload.sub,
                aud: payload.aud,
                realm: payload.realm,
                device_id: optional_string(payload.device_id),
                device_fingerprint_hash: optional_string(payload.device_fingerprint_hash),
                user_agent: optional_string(payload.user_agent),
                ip_address: optional_string(payload.ip_address).or(x_forwarded_for),
                mfa_level: payload.mfa_level as i16,
                remember_me: payload.remember_me.unwrap_or(true),
                client_id: optional_string(payload.client_id),
                scopes: None,
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: issued.access_token,
            token_type: issued.token_type.to_string(),
            expires_at: issued.access_expires_at,
            refresh_token: issued.refresh_token,
            session_id: issued.session_id,
            refresh_expires_at: issued.refresh_expires_at,
            session_version: issued.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }

    async fn validate_access_token(
        &self,
        request: Request<ValidateAccessTokenRequest>,
    ) -> Result<Response<ValidateAccessTokenResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;

        let payload = request.into_inner();
        if payload.access_token.trim().is_empty() {
            return Ok(Response::new(ValidateAccessTokenResponse {
                active: false,
                reason: "missing access token".to_string(),
                current_session_version: 0,
                session_id: String::new(),
            }));
        }

        let claims = match jwt::decode_token(payload.access_token.trim()) {
            Ok(value) => value,
            Err(err) => {
                return Ok(Response::new(ValidateAccessTokenResponse {
                    active: false,
                    reason: format!("decode failed: {err}"),
                    current_session_version: 0,
                    session_id: String::new(),
                }));
            }
        };

        if let Err(err) = jwt::validate_claims(&claims) {
            return Ok(Response::new(ValidateAccessTokenResponse {
                active: false,
                reason: format!("invalid claims: {err}"),
                current_session_version: claims.sv,
                session_id: claims.sid.unwrap_or_default(),
            }));
        }

        let active = validate_claims_against_session(&self.state, &claims)
            .await
            .unwrap_or(false);

        Ok(Response::new(ValidateAccessTokenResponse {
            active,
            reason: if active {
                "ok".to_string()
            } else {
                "session invalid or session_version mismatch".to_string()
            },
            current_session_version: claims.sv,
            session_id: claims.sid.unwrap_or_default(),
        }))
    }

    async fn register_user(
        &self,
        request: Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");

        let payload = request.into_inner();
        let email = normalize_email(&payload.email)
            .ok_or_else(|| Status::invalid_argument("email is required"))?;
        validate_password_policy(&payload.password)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let password_hash = hash_password(&payload.password)
            .map_err(|err| Status::internal(format!("password hashing failed: {err}")))?;

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let user_row = sqlx::query(
            "SELECT id, email_verified
             FROM auth.users
             WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db read user failed: {err}")))?;

        let user_id = if let Some(row) = user_row {
            row.get::<Uuid, _>("id")
        } else {
            let user_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO auth.users (id, email, email_verified, created_at, updated_at)
                 VALUES ($1, $2, FALSE, NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db insert user failed: {err}")))?;

            sqlx::query(
                "INSERT INTO auth.credentials_password (user_id, password_hash, password_updated_at, created_at)
                 VALUES ($1, $2, NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db insert password failed: {err}")))?;

            let mut users_client = self.state.users_client.lock().await;
            let mut users_request =
                Request::new(contracts::wildon::users::v1::CreateUserRequest {
                    user_id: user_id.to_string(),
                    email: email.clone(),
                    first_name: payload.first_name.clone(),
                    last_name: payload.last_name.clone(),
                    middle_name: payload.middle_name.clone(),
                });
            let _ = inject_internal_metadata(
                &mut users_request,
                "auth-service",
                request_id.as_deref(),
                traceparent.as_deref(),
            );
            users_client
                .create_user(users_request)
                .await
                .map_err(|err| Status::unavailable(format!("users-service error: {err}")))?;

            user_id
        };

        let otp_code = match ensure_email_verification_otp(&mut tx, user_id, &email).await {
            Ok(code) => Some(code),
            Err(err) => {
                tracing::warn!(error = %err, "failed to stage email verification otp");
                None
            }
        };

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        if let Some(code) = otp_code {
            let mut variables = HashMap::new();
            variables.insert("otp_code".to_string(), code);
            spawn_template_email(
                &self.state,
                email.clone(),
                AUTH_TEMPLATE_EMAIL_OTP,
                variables,
                "Email verification",
                "<p>Use this verification code: <strong>{{otp_code}}</strong></p>",
            );
        }

        Ok(Response::new(RegisterUserResponse {
            accepted: true,
            message: "If the account is eligible, verification instructions were sent".to_string(),
        }))
    }

    async fn request_email_verification_otp(
        &self,
        request: Request<RequestEmailVerificationOtpRequest>,
    ) -> Result<Response<RequestEmailVerificationOtpResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let ip_address = metadata_value(&request, "x-forwarded-for").and_then(|value| {
            value
                .split(',')
                .next()
                .map(str::trim)
                .map(ToString::to_string)
        });

        let payload = request.into_inner();
        let Some(email) = normalize_email(&payload.email) else {
            return Ok(Response::new(RequestEmailVerificationOtpResponse {
                accepted: true,
                message: "If the account exists, verification instructions were sent".to_string(),
            }));
        };

        if !consume_rate_limit_counter(
            &self.state,
            &format!("rl:otp:verify_email_request:{email}"),
            3,
            10 * 60,
        )
        .await
        {
            return Ok(Response::new(RequestEmailVerificationOtpResponse {
                accepted: true,
                message: "If the account exists, verification instructions were sent".to_string(),
            }));
        }
        if let Some(ip) = ip_address.as_deref() {
            if !consume_rate_limit_counter(
                &self.state,
                &format!("rl:ip:verify_email_request:{ip}"),
                25,
                10 * 60,
            )
            .await
            {
                return Ok(Response::new(RequestEmailVerificationOtpResponse {
                    accepted: true,
                    message: "If the account exists, verification instructions were sent"
                        .to_string(),
                }));
            }
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let user_row = sqlx::query(
            "SELECT id, email_verified
             FROM auth.users
             WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db read user failed: {err}")))?;

        let mut otp_code_to_send: Option<String> = None;
        if let Some(row) = user_row {
            let user_id: Uuid = row.get("id");
            let email_verified: bool = row.get("email_verified");
            if !email_verified {
                if let Ok(code) = ensure_email_verification_otp(&mut tx, user_id, &email).await {
                    otp_code_to_send = Some(code);
                }
            }
        }

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        if let Some(code) = otp_code_to_send {
            let mut variables = HashMap::new();
            variables.insert("otp_code".to_string(), code);
            spawn_template_email(
                &self.state,
                email.clone(),
                AUTH_TEMPLATE_EMAIL_OTP,
                variables,
                "Email verification",
                "<p>Use this verification code: <strong>{{otp_code}}</strong></p>",
            );
        }
        Ok(Response::new(RequestEmailVerificationOtpResponse {
            accepted: true,
            message: "If the account exists, verification instructions were sent".to_string(),
        }))
    }

    async fn confirm_email_verification_otp(
        &self,
        request: Request<ConfirmEmailVerificationOtpRequest>,
    ) -> Result<Response<ConfirmEmailVerificationOtpResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;

        let payload = request.into_inner();
        let Some(email) = normalize_email(&payload.email) else {
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        };
        if !consume_rate_limit_counter(
            &self.state,
            &format!("rl:otp:verify_email_confirm:{email}"),
            10,
            15 * 60,
        )
        .await
        {
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        }

        let otp = payload.otp_code.trim();
        if otp.len() != 6 || !otp.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;
        let row = sqlx::query(
            "SELECT id, user_id, otp_hash, expires_at, attempts
             FROM auth.email_verification_otps
             WHERE email = $1
               AND consumed_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db lookup otp failed: {err}")))?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        };

        let otp_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let otp_hash: String = row.get("otp_hash");
        let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
        let attempts: i32 = row.get("attempts");

        if attempts >= 10 || expires_at <= chrono::Utc::now() {
            tx.rollback().await.ok();
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        }

        let presented_hash = hash_otp("email_verify", &user_id.to_string(), otp);
        if presented_hash != otp_hash {
            let _ = sqlx::query(
                "UPDATE auth.email_verification_otps
                 SET attempts = attempts + 1
                 WHERE id = $1",
            )
            .bind(otp_id)
            .execute(&mut *tx)
            .await;
            tx.rollback().await.ok();
            return Ok(Response::new(ConfirmEmailVerificationOtpResponse {
                verified: false,
                message: "Invalid verification code".to_string(),
            }));
        }

        sqlx::query(
            "UPDATE auth.email_verification_otps
             SET consumed_at = NOW()
             WHERE id = $1",
        )
        .bind(otp_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db consume otp failed: {err}")))?;

        sqlx::query(
            "UPDATE auth.users
             SET email_verified = TRUE, email_verified_at = NOW(), updated_at = NOW()
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db mark verified failed: {err}")))?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        let mut variables = HashMap::new();
        variables.insert("email".to_string(), email.clone());
        spawn_template_email(
            &self.state,
            email.clone(),
            AUTH_TEMPLATE_EMAIL_WELCOME,
            variables,
            "Welcome to Wildon",
            "<p>Your email has been verified successfully. Welcome to Wildon.</p>",
        );

        Ok(Response::new(ConfirmEmailVerificationOtpResponse {
            verified: true,
            message: "Email verified".to_string(),
        }))
    }

    async fn login_with_password(
        &self,
        request: Request<LoginWithPasswordRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let payload = request.into_inner();
        let email = normalize_email(&payload.email)
            .ok_or_else(|| Status::invalid_argument("email is required"))?;
        if payload.password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }
        let ip_address = optional_string(payload.ip_address.clone());
        let client_id = optional_string(payload.client_id.clone());
        let device_id = optional_string(payload.device_id.clone());
        let device_fingerprint_hash = optional_string(payload.device_fingerprint_hash.clone());
        let user_agent = optional_string(payload.user_agent.clone());
        let remember_me = payload.remember_me.unwrap_or(true);

        if is_account_locked(&self.state, &email).await {
            let _ = record_security_event(
                &self.state,
                "account_locked",
                None,
                request_id.as_deref(),
                serde_json::json!({
                    "account": email,
                    "reason": "lock_active",
                }),
            )
            .await;
            return Err(Status::resource_exhausted(
                "account temporarily locked due to repeated failures",
            ));
        }

        if let Some(ip) = ip_address.as_deref() {
            let key = format!("rl:ip:login:{ip}");
            if !consume_rate_limit_counter(&self.state, &key, 10, 5 * 60).await {
                let _ = record_security_event(
                    &self.state,
                    "login_failed",
                    None,
                    request_id.as_deref(),
                    serde_json::json!({
                        "account": email,
                        "reason": "ip_rate_limited",
                        "ip": ip,
                    }),
                )
                .await;
                return Err(Status::resource_exhausted("too many login attempts"));
            }
        }

        let user_row = sqlx::query(
            "SELECT u.id, u.email_verified, cp.password_hash
             FROM auth.users u
             JOIN auth.credentials_password cp ON cp.user_id = u.id
             WHERE u.email = $1",
        )
        .bind(&email)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db lookup failed: {err}")))?;

        let Some(row) = user_row else {
            let _ = register_failed_login_attempt(
                &self.state,
                &email,
                ip_address.as_deref(),
                None,
                "user_not_found",
                request_id.as_deref(),
            )
            .await;
            return Err(Status::unauthenticated("email not found"));
        };

        let user_id: Uuid = row.get("id");
        let email_verified: bool = row.get("email_verified");
        let password_hash: String = row.get("password_hash");
        if !email_verified {
            let _ = register_failed_login_attempt(
                &self.state,
                &email,
                ip_address.as_deref(),
                Some(user_id),
                "email_not_verified",
                request_id.as_deref(),
            )
            .await;
            return Err(Status::permission_denied("email is not verified"));
        }
        if !verify_password(&password_hash, &payload.password) {
            let _ = register_failed_login_attempt(
                &self.state,
                &email,
                ip_address.as_deref(),
                Some(user_id),
                "password_mismatch",
                request_id.as_deref(),
            )
            .await;
            return Err(Status::unauthenticated("password is incorrect"));
        }

        if let Some(policy) = load_auditor_access_policy(&self.state.db, user_id).await? {
            if payload.aud != "platform" || payload.realm != "platform" {
                let _ = record_security_event(
                    &self.state,
                    "login_failed",
                    Some(user_id),
                    request_id.as_deref(),
                    serde_json::json!({
                        "account": email,
                        "reason": "auditor_platform_surface_required",
                        "aud": payload.aud,
                        "realm": payload.realm,
                    }),
                )
                .await;
                return Err(Status::permission_denied(
                    "auditor accounts may only access the platform surface",
                ));
            }
            enforce_auditor_access_policy(&policy, ip_address.as_deref(), "auditor login denied")?;
        }

        clear_failed_login_state(&self.state, &email).await;

        if load_active_authenticator_factor(&self.state.db, user_id)
            .await?
            .is_some()
        {
            let challenge_token = create_mfa_login_challenge(
                &self.state.db,
                user_id,
                MFA_FACTOR_AUTHENTICATOR,
                &payload.aud,
                &payload.realm,
                client_id.clone(),
                device_id.clone(),
                device_fingerprint_hash.clone(),
                user_agent.clone(),
                ip_address.clone(),
                remember_me,
            )
            .await?;

            return Ok(Response::new(IssueTokenResponse {
                access_token: String::new(),
                token_type: "Bearer".to_string(),
                expires_at: 0,
                refresh_token: String::new(),
                session_id: String::new(),
                refresh_expires_at: 0,
                session_version: 0,
                mfa_required: true,
                mfa_challenge_token: challenge_token,
                mfa_method: MFA_FACTOR_AUTHENTICATOR.to_string(),
            }));
        }

        let issued = issue_session_tokens(
            &self.state,
            IssueSessionInput {
                sub: user_id.to_string(),
                aud: payload.aud,
                realm: payload.realm,
                device_id,
                device_fingerprint_hash,
                user_agent,
                ip_address,
                mfa_level: 0,
                remember_me,
                client_id,
                scopes: None,
                request_id: None,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: issued.access_token,
            token_type: issued.token_type.to_string(),
            expires_at: issued.access_expires_at,
            refresh_token: issued.refresh_token,
            session_id: issued.session_id,
            refresh_expires_at: issued.refresh_expires_at,
            session_version: issued.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }

    async fn verify_login_mfa(
        &self,
        request: Request<VerifyLoginMfaRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let payload = request.into_inner();

        let challenge_token = payload.challenge_token.trim();
        if challenge_token.is_empty() {
            return Err(Status::invalid_argument("challenge_token is required"));
        }
        let otp_code_raw = payload.otp_code.trim();
        if otp_code_raw.is_empty() {
            return Err(Status::invalid_argument("otp_code is required"));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let challenge = load_mfa_login_challenge_for_update(&mut tx, challenge_token).await?;
        let Some(challenge) = challenge else {
            tx.rollback().await.ok();
            return Err(Status::unauthenticated("invalid mfa challenge"));
        };

        if challenge.expires_at <= Utc::now() || challenge.attempts >= 10 {
            tx.rollback().await.ok();
            return Err(Status::unauthenticated("mfa challenge expired"));
        }

        let requested_factor = if payload.factor_type.trim().is_empty() {
            challenge.factor_type.clone()
        } else {
            normalize_mfa_factor_type(&payload.factor_type)
                .ok_or_else(|| Status::invalid_argument("unsupported factor_type"))?
        };
        let backup_code_allowed = challenge.factor_type == MFA_FACTOR_AUTHENTICATOR
            && requested_factor == MFA_FACTOR_BACKUP_CODE;
        if requested_factor != challenge.factor_type && !backup_code_allowed {
            tx.rollback().await.ok();
            return Err(Status::invalid_argument(
                "invalid factor_type for this challenge",
            ));
        }

        match requested_factor.as_str() {
            MFA_FACTOR_AUTHENTICATOR => {
                let otp_code = otp_code_raw;
                if otp_code.len() != 6 || !otp_code.chars().all(|ch| ch.is_ascii_digit()) {
                    tx.rollback().await.ok();
                    return Err(Status::invalid_argument("otp_code must be a 6-digit code"));
                }
                let Some(factor) =
                    load_active_authenticator_factor_for_update(&mut tx, challenge.user_id).await?
                else {
                    tx.rollback().await.ok();
                    return Err(Status::failed_precondition(
                        "no active authenticator factor",
                    ));
                };

                if !verify_authenticator_totp(
                    &factor.secret_base32,
                    otp_code,
                    auth_mfa_totp_drift_steps(),
                    Utc::now().timestamp(),
                ) {
                    increment_mfa_challenge_attempts(&mut tx, challenge.id).await?;
                    tx.commit()
                        .await
                        .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;
                    return Err(Status::unauthenticated("invalid mfa code"));
                }

                mark_mfa_challenge_consumed(&mut tx, challenge.id).await?;
                mark_mfa_factor_used(&mut tx, factor.id).await?;
            }
            MFA_FACTOR_BACKUP_CODE => {
                let Some(normalized_code) = normalize_backup_code(otp_code_raw) else {
                    tx.rollback().await.ok();
                    return Err(Status::invalid_argument(
                        "backup code must be 8 characters (format XXXX-XXXX)",
                    ));
                };
                let used =
                    consume_backup_code_for_update(&mut tx, challenge.user_id, &normalized_code)
                        .await?;
                let Some(backup_code) = used else {
                    increment_mfa_challenge_attempts(&mut tx, challenge.id).await?;
                    tx.commit()
                        .await
                        .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;
                    return Err(Status::unauthenticated("invalid mfa code"));
                };

                mark_mfa_challenge_consumed(&mut tx, challenge.id).await?;
                mark_mfa_factor_used(&mut tx, backup_code.factor_id).await?;
            }
            MFA_FACTOR_SMS => {
                tx.rollback().await.ok();
                return Err(Status::failed_precondition(
                    "sms mfa is not enabled in this deployment",
                ));
            }
            _ => {
                tx.rollback().await.ok();
                return Err(Status::internal("unsupported mfa factor type"));
            }
        }

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        let issued = issue_session_tokens(
            &self.state,
            IssueSessionInput {
                sub: challenge.user_id.to_string(),
                aud: challenge.aud,
                realm: challenge.realm,
                client_id: challenge.client_id,
                scopes: None,
                device_id: challenge.device_id,
                device_fingerprint_hash: challenge.device_fingerprint_hash,
                user_agent: challenge.user_agent,
                ip_address: challenge.ip_address,
                mfa_level: 1,
                remember_me: challenge.remember_me,
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: issued.access_token,
            token_type: issued.token_type.to_string(),
            expires_at: issued.access_expires_at,
            refresh_token: issued.refresh_token,
            session_id: issued.session_id,
            refresh_expires_at: issued.refresh_expires_at,
            session_version: issued.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }

    async fn get_mfa_status(
        &self,
        request: Request<GetMfaStatusRequest>,
    ) -> Result<Response<GetMfaStatusResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(&subject)
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let rows = sqlx::query(
            "SELECT f.factor_type, f.status,
                    COALESCE(EXTRACT(EPOCH FROM verified_at)::BIGINT, 0) AS enabled_at,
                    f.phone_e164,
                    COALESCE((
                        SELECT COUNT(*)
                        FROM auth.mfa_backup_codes bc
                        WHERE bc.user_id = f.user_id
                          AND bc.factor_id = f.id
                          AND bc.status = 'active'
                    ), 0)::INT AS backup_codes_remaining
             FROM auth.mfa_factors f
             WHERE f.user_id = $1
               AND f.status = 'active'
             ORDER BY verified_at DESC NULLS LAST, created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db list mfa factors failed: {err}")))?;

        let factors = rows
            .into_iter()
            .map(|row| {
                let factor_type: String = row.get("factor_type");
                let phone_e164: Option<String> = row.get("phone_e164");
                MfaFactorSummary {
                    factor_type,
                    status: "active".to_string(),
                    enabled_at: row.get::<i64, _>("enabled_at"),
                    masked_destination: phone_e164
                        .as_deref()
                        .map(mask_phone_e164)
                        .unwrap_or_default(),
                    backup_codes_remaining: row.get::<i32, _>("backup_codes_remaining"),
                }
            })
            .collect::<Vec<_>>();

        Ok(Response::new(GetMfaStatusResponse {
            mfa_enabled: !factors.is_empty(),
            factors,
        }))
    }

    async fn begin_authenticator_enrollment(
        &self,
        request: Request<BeginAuthenticatorEnrollmentRequest>,
    ) -> Result<Response<BeginAuthenticatorEnrollmentResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(&subject)
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let payload = request.into_inner();
        let issuer = if payload.issuer.trim().is_empty() {
            auth_mfa_totp_issuer()
        } else {
            payload.issuer.trim().to_string()
        };

        let email_row = sqlx::query(
            "SELECT email
             FROM auth.users
             WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db load user failed: {err}")))?;
        let Some(email_row) = email_row else {
            return Err(Status::not_found("user not found"));
        };
        let account_name: String = email_row.get("email");

        let factor_id = Uuid::new_v4();
        let secret = generate_authenticator_secret_base32();

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        sqlx::query(
            "UPDATE auth.mfa_factors
             SET status = 'disabled',
                 disabled_at = NOW()
             WHERE user_id = $1
               AND factor_type = 'authenticator'
               AND status = 'pending'",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db disable pending mfa factors failed: {err}")))?;

        sqlx::query(
            "INSERT INTO auth.mfa_factors (
                id,
                user_id,
                factor_type,
                status,
                secret_base32,
                created_at
             ) VALUES (
                $1,
                $2,
                'authenticator',
                'pending',
                $3,
                NOW()
             )",
        )
        .bind(factor_id)
        .bind(user_id)
        .bind(&secret)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db create pending mfa factor failed: {err}")))?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        let otpauth_uri = build_otpauth_uri(&secret, &issuer, &account_name);
        let qr_svg_data_uri = build_otpauth_qr_svg_data_uri(&otpauth_uri).unwrap_or_default();

        Ok(Response::new(BeginAuthenticatorEnrollmentResponse {
            factor_type: MFA_FACTOR_AUTHENTICATOR.to_string(),
            factor_id: factor_id.to_string(),
            issuer,
            account_name,
            secret,
            otpauth_uri,
            qr_svg_data_uri,
        }))
    }

    async fn confirm_authenticator_enrollment(
        &self,
        request: Request<ConfirmAuthenticatorEnrollmentRequest>,
    ) -> Result<Response<ConfirmAuthenticatorEnrollmentResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(&subject)
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let payload = request.into_inner();
        let otp_code = payload.otp_code.trim();
        if otp_code.len() != 6 || !otp_code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(Status::invalid_argument("otp_code must be a 6-digit code"));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let Some(pending_factor) =
            load_pending_authenticator_factor_for_update(&mut tx, user_id).await?
        else {
            tx.rollback().await.ok();
            return Err(Status::failed_precondition(
                "no pending authenticator setup",
            ));
        };

        if !verify_authenticator_totp(
            &pending_factor.secret_base32,
            otp_code,
            auth_mfa_totp_drift_steps(),
            Utc::now().timestamp(),
        ) {
            tx.rollback().await.ok();
            return Err(Status::unauthenticated("invalid mfa code"));
        }

        sqlx::query(
            "UPDATE auth.mfa_factors
             SET status = 'disabled',
                 disabled_at = NOW()
             WHERE user_id = $1
               AND factor_type = 'authenticator'
               AND status = 'active'",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            Status::internal(format!("db disable previous active factor failed: {err}"))
        })?;

        sqlx::query(
            "UPDATE auth.mfa_factors
             SET status = 'active',
                 verified_at = NOW(),
                 disabled_at = NULL
             WHERE id = $1",
        )
        .bind(pending_factor.id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db activate mfa factor failed: {err}")))?;

        revoke_active_backup_codes(&mut tx, user_id, Some(pending_factor.id)).await?;
        let backup_codes = create_backup_codes_for_factor(
            &mut tx,
            user_id,
            pending_factor.id,
            auth_mfa_backup_codes_count(),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        Ok(Response::new(ConfirmAuthenticatorEnrollmentResponse {
            enabled: true,
            message: "authenticator mfa enabled".to_string(),
            backup_codes,
        }))
    }

    async fn disable_mfa_factor(
        &self,
        request: Request<DisableMfaFactorRequest>,
    ) -> Result<Response<DisableMfaFactorResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(&subject)
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let payload = request.into_inner();
        let factor_type = normalize_mfa_factor_type(&payload.factor_type)
            .unwrap_or_else(|| MFA_FACTOR_AUTHENTICATOR.to_string());
        if factor_type != MFA_FACTOR_AUTHENTICATOR {
            return Err(Status::failed_precondition(
                "only authenticator mfa is currently supported",
            ));
        }
        let otp_code = payload.otp_code.trim();
        if otp_code.len() != 6 || !otp_code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(Status::invalid_argument("otp_code must be a 6-digit code"));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let Some(active_factor) =
            load_active_authenticator_factor_for_update(&mut tx, user_id).await?
        else {
            tx.rollback().await.ok();
            return Ok(Response::new(DisableMfaFactorResponse {
                disabled: false,
                message: "no active authenticator factor".to_string(),
            }));
        };

        if !verify_authenticator_totp(
            &active_factor.secret_base32,
            otp_code,
            auth_mfa_totp_drift_steps(),
            Utc::now().timestamp(),
        ) {
            tx.rollback().await.ok();
            return Err(Status::unauthenticated("invalid mfa code"));
        }

        sqlx::query(
            "UPDATE auth.mfa_factors
             SET status = 'disabled',
                 disabled_at = NOW()
             WHERE id = $1",
        )
        .bind(active_factor.id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db disable mfa factor failed: {err}")))?;

        revoke_active_backup_codes(&mut tx, user_id, Some(active_factor.id)).await?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        Ok(Response::new(DisableMfaFactorResponse {
            disabled: true,
            message: "mfa factor disabled".to_string(),
        }))
    }

    async fn regenerate_backup_codes(
        &self,
        request: Request<RegenerateBackupCodesRequest>,
    ) -> Result<Response<RegenerateBackupCodesResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(&subject)
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let payload = request.into_inner();
        let otp_code = payload.otp_code.trim();
        if otp_code.len() != 6 || !otp_code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(Status::invalid_argument("otp_code must be a 6-digit code"));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let Some(active_factor) =
            load_active_authenticator_factor_for_update(&mut tx, user_id).await?
        else {
            tx.rollback().await.ok();
            return Err(Status::failed_precondition(
                "no active authenticator factor",
            ));
        };

        if !verify_authenticator_totp(
            &active_factor.secret_base32,
            otp_code,
            auth_mfa_totp_drift_steps(),
            Utc::now().timestamp(),
        ) {
            tx.rollback().await.ok();
            return Err(Status::unauthenticated("invalid mfa code"));
        }

        revoke_active_backup_codes(&mut tx, user_id, Some(active_factor.id)).await?;
        let backup_codes = create_backup_codes_for_factor(
            &mut tx,
            user_id,
            active_factor.id,
            auth_mfa_backup_codes_count(),
        )
        .await?;
        mark_mfa_factor_used(&mut tx, active_factor.id).await?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        Ok(Response::new(RegenerateBackupCodesResponse {
            regenerated: true,
            message: "backup codes regenerated".to_string(),
            backup_codes,
        }))
    }

    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();
        let refreshed = refresh_session_tokens(
            &self.state,
            RefreshSessionInput {
                token: payload.refresh_token,
                device_id: optional_string(payload.device_id),
                request_id: None,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: refreshed.access_token,
            token_type: refreshed.token_type.to_string(),
            expires_at: refreshed.access_expires_at,
            refresh_token: refreshed.refresh_token,
            session_id: refreshed.session_id,
            refresh_expires_at: refreshed.refresh_expires_at,
            session_version: refreshed.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }

    async fn logout_session(
        &self,
        request: Request<LogoutSessionRequest>,
    ) -> Result<Response<LogoutSessionResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();
        let result = logout_session_by_refresh_token(
            &self.state,
            LogoutSessionInput {
                refresh_token: payload.refresh_token,
                reason: payload.reason,
                request_id: None,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(LogoutSessionResponse {
            revoked: result.revoked,
            message: if result.revoked {
                "session revoked".to_string()
            } else {
                "session not found".to_string()
            },
        }))
    }

    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let payload = request.into_inner();

        let sessions = list_sessions_for_user(
            &self.state,
            ListSessionsInput {
                sub: subject,
                limit: payload.limit,
                cursor: payload.cursor,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(ListSessionsResponse {
            sessions: sessions
                .sessions
                .into_iter()
                .map(|value| SessionSummary {
                    session_id: value.session_id,
                    aud: value.aud,
                    realm: value.realm,
                    client_id: value.client_id.unwrap_or_default(),
                    device_id: value.device_id.unwrap_or_default(),
                    remember_me: value.remember_me,
                    ip_address: value.ip_address.unwrap_or_default(),
                    user_agent: value.user_agent.unwrap_or_default(),
                    created_at: value.created_at,
                    last_activity_at: value.last_activity_at,
                    expires_at: value.expires_at,
                    revoked_at: value.revoked_at.unwrap_or_default(),
                    revoked_reason: value.revoked_reason.unwrap_or_default(),
                    mfa_level: value.mfa_level as i32,
                })
                .collect(),
            next_cursor: sessions.next_cursor.unwrap_or_default(),
            has_more: sessions.has_more,
        }))
    }

    async fn logout_session_by_id(
        &self,
        request: Request<LogoutSessionByIdRequest>,
    ) -> Result<Response<LogoutSessionByIdResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let payload = request.into_inner();
        let result = logout_session_by_id(
            &self.state,
            LogoutSessionByIdInput {
                sub: subject,
                session_id: payload.session_id,
                reason: payload.reason,
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(LogoutSessionByIdResponse {
            revoked: result.revoked,
            message: if result.revoked {
                "session revoked".to_string()
            } else {
                "session not found".to_string()
            },
        }))
    }

    async fn logout_all_sessions(
        &self,
        request: Request<LogoutAllSessionsRequest>,
    ) -> Result<Response<LogoutAllSessionsResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service"],
        )?;
        let request_id = metadata_value(&request, "x-request-id");
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let payload = request.into_inner();

        let result = revoke_all_sessions_for_user(
            &self.state,
            RevokeAllSessionsInput {
                sub: subject,
                reason: optional_string(payload.reason)
                    .unwrap_or_else(|| "user_logout_all".to_string()),
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(LogoutAllSessionsResponse {
            session_version: result.session_version,
            revoked_sessions: result.revoked_sessions,
        }))
    }

    async fn request_password_reset_otp(
        &self,
        request: Request<RequestPasswordResetOtpRequest>,
    ) -> Result<Response<RequestPasswordResetOtpResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let ip_address = metadata_value(&request, "x-forwarded-for").and_then(|value| {
            value
                .split(',')
                .next()
                .map(str::trim)
                .map(ToString::to_string)
        });

        let payload = request.into_inner();
        if let Some(email) = normalize_email(&payload.email) {
            if !consume_rate_limit_counter(
                &self.state,
                &format!("rl:otp:password_forgot_request:{email}"),
                3,
                15 * 60,
            )
            .await
            {
                return Ok(Response::new(RequestPasswordResetOtpResponse {
                    accepted: true,
                    message: "If the account exists, reset instructions were sent".to_string(),
                }));
            }
            if let Some(ip) = ip_address.as_deref() {
                if !consume_rate_limit_counter(
                    &self.state,
                    &format!("rl:ip:password_forgot_request:{ip}"),
                    25,
                    15 * 60,
                )
                .await
                {
                    return Ok(Response::new(RequestPasswordResetOtpResponse {
                        accepted: true,
                        message: "If the account exists, reset instructions were sent".to_string(),
                    }));
                }
            }

            let mut tx = self
                .state
                .db
                .begin()
                .await
                .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

            let mut otp_code_to_send: Option<String> = None;
            if let Some(row) = sqlx::query("SELECT id FROM auth.users WHERE email = $1")
                .bind(&email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|err| Status::internal(format!("db lookup user failed: {err}")))?
            {
                let user_id: Uuid = row.get("id");
                if let Ok(code) = ensure_password_reset_otp(&mut tx, user_id, &email).await {
                    otp_code_to_send = Some(code);
                }
            }

            tx.commit()
                .await
                .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

            if let Some(code) = otp_code_to_send {
                let mut variables = HashMap::new();
                variables.insert("otp_code".to_string(), code);
                spawn_template_email(
                    &self.state,
                    email.clone(),
                    AUTH_TEMPLATE_PASSWORD_RESET_REQUEST,
                    variables,
                    "Password reset code",
                    "<p>Use this password reset code: <strong>{{otp_code}}</strong></p>",
                );
            }
        }

        Ok(Response::new(RequestPasswordResetOtpResponse {
            accepted: true,
            message: "If the account exists, reset instructions were sent".to_string(),
        }))
    }

    async fn verify_password_reset_otp(
        &self,
        request: Request<VerifyPasswordResetOtpRequest>,
    ) -> Result<Response<VerifyPasswordResetOtpResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;

        let payload = request.into_inner();
        let Some(email) = normalize_email(&payload.email) else {
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        };
        if !consume_rate_limit_counter(
            &self.state,
            &format!("rl:otp:password_forgot_verify:{email}"),
            10,
            15 * 60,
        )
        .await
        {
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        }
        let otp = payload.otp_code.trim();
        if otp.len() != 6 || !otp.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        }

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

        let row = sqlx::query(
            "SELECT id, user_id, otp_hash, expires_at, attempts
             FROM auth.password_reset_otps
             WHERE email = $1
               AND consumed_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db lookup reset otp failed: {err}")))?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        };

        let otp_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let otp_hash: String = row.get("otp_hash");
        let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
        let attempts: i32 = row.get("attempts");
        if attempts >= 10 || expires_at <= chrono::Utc::now() {
            tx.rollback().await.ok();
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        }

        let presented_hash = hash_otp("password_reset", &user_id.to_string(), otp);
        if presented_hash != otp_hash {
            let _ = sqlx::query(
                "UPDATE auth.password_reset_otps
                 SET attempts = attempts + 1
                 WHERE id = $1",
            )
            .bind(otp_id)
            .execute(&mut *tx)
            .await;
            tx.rollback().await.ok();
            return Ok(Response::new(VerifyPasswordResetOtpResponse {
                accepted: false,
                reset_token: String::new(),
                message: "Invalid reset code".to_string(),
            }));
        }

        let reset_token = format!("rst_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let reset_token_hash = hash_token("password_reset_token", &reset_token);
        let reset_token_expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

        sqlx::query(
            "UPDATE auth.password_reset_otps
             SET verified_at = NOW(),
                 reset_token_hash = $2,
                 reset_token_expires_at = $3
             WHERE id = $1",
        )
        .bind(otp_id)
        .bind(reset_token_hash)
        .bind(reset_token_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db update reset otp failed: {err}")))?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        Ok(Response::new(VerifyPasswordResetOtpResponse {
            accepted: true,
            reset_token,
            message: "Reset token issued".to_string(),
        }))
    }

    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();
        let Some(email) = normalize_email(&payload.email) else {
            return Ok(Response::new(ResetPasswordResponse {
                reset: false,
                message: "Invalid reset request".to_string(),
            }));
        };
        if payload.reset_token.trim().is_empty() {
            return Ok(Response::new(ResetPasswordResponse {
                reset: false,
                message: "Invalid reset request".to_string(),
            }));
        }
        validate_password_policy(&payload.new_password)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        let password_hash = hash_password(&payload.new_password)
            .map_err(|err| Status::internal(format!("password hashing failed: {err}")))?;
        let presented_token_hash = hash_token("password_reset_token", payload.reset_token.trim());

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;
        let row = sqlx::query(
            "SELECT id, user_id, reset_token_expires_at
             FROM auth.password_reset_otps
             WHERE email = $1
               AND reset_token_hash = $2
               AND consumed_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(&email)
        .bind(&presented_token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db lookup reset token failed: {err}")))?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Ok(Response::new(ResetPasswordResponse {
                reset: false,
                message: "Invalid reset request".to_string(),
            }));
        };

        let otp_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let reset_token_expires_at: Option<chrono::DateTime<chrono::Utc>> =
            row.get("reset_token_expires_at");
        if reset_token_expires_at.unwrap_or_else(chrono::Utc::now) <= chrono::Utc::now() {
            tx.rollback().await.ok();
            return Ok(Response::new(ResetPasswordResponse {
                reset: false,
                message: "Invalid reset request".to_string(),
            }));
        }

        sqlx::query(
            "UPDATE auth.credentials_password
             SET password_hash = $2, password_updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db update password failed: {err}")))?;

        sqlx::query(
            "UPDATE auth.password_reset_otps
             SET consumed_at = NOW()
             WHERE id = $1",
        )
        .bind(otp_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db consume reset token failed: {err}")))?;

        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

        let _ = revoke_all_sessions_for_user(
            &self.state,
            RevokeAllSessionsInput {
                sub: user_id.to_string(),
                reason: "password_reset".to_string(),
                request_id: None,
            },
        )
        .await;
        clear_failed_login_state(&self.state, &email).await;

        let mut variables = HashMap::new();
        variables.insert("email".to_string(), email.clone());
        variables.insert("changed_at".to_string(), chrono::Utc::now().to_rfc3339());
        spawn_template_email(
            &self.state,
            email.clone(),
            AUTH_TEMPLATE_PASSWORD_CHANGED_SUCCESS,
            variables,
            "Your password has been changed",
            "<p>Your password was changed successfully.</p>",
        );

        Ok(Response::new(ResetPasswordResponse {
            reset: true,
            message: "Password reset complete".to_string(),
        }))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let subject = metadata_value(&request, "x-auth-sub")
            .ok_or_else(|| Status::unauthenticated("missing authenticated subject"))?;
        let user_id = Uuid::parse_str(subject.trim())
            .map_err(|_| Status::unauthenticated("invalid authenticated subject"))?;

        let payload = request.into_inner();
        if payload.current_password.trim().is_empty() {
            return Err(Status::invalid_argument("current_password is required"));
        }
        validate_password_policy(&payload.new_password)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        if payload.current_password == payload.new_password {
            return Err(Status::invalid_argument(
                "new_password must be different from current_password",
            ));
        }

        let row = sqlx::query(
            "SELECT u.email, cp.password_hash
             FROM auth.credentials_password cp
             JOIN auth.users u ON u.id = cp.user_id
             WHERE cp.user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db lookup failed: {err}")))?;

        let Some(row) = row else {
            return Err(Status::not_found("password credential not found"));
        };
        let email: Option<String> = row.try_get("email").ok();
        let stored_hash: String = row.get("password_hash");
        if !verify_password(&stored_hash, &payload.current_password) {
            return Err(Status::permission_denied("current password is incorrect"));
        }

        let new_hash = hash_password(&payload.new_password)
            .map_err(|err| Status::internal(format!("password hashing failed: {err}")))?;
        sqlx::query(
            "UPDATE auth.credentials_password
             SET password_hash = $2, password_updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(new_hash)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db update failed: {err}")))?;

        let _ = revoke_all_sessions_for_user(
            &self.state,
            RevokeAllSessionsInput {
                sub: user_id.to_string(),
                reason: "password_change".to_string(),
                request_id: None,
            },
        )
        .await;

        if let Some(email) = email {
            clear_failed_login_state(&self.state, &email).await;
            let mut variables = HashMap::new();
            variables.insert("email".to_string(), email.clone());
            variables.insert("changed_at".to_string(), chrono::Utc::now().to_rfc3339());
            spawn_template_email(
                &self.state,
                email,
                AUTH_TEMPLATE_PASSWORD_CHANGED_SUCCESS,
                variables,
                "Your password has been changed",
                "<p>Your password was changed successfully.</p>",
            );
        }

        Ok(Response::new(ChangePasswordResponse {
            changed: true,
            message: "Password updated".to_string(),
        }))
    }

    async fn get_oidc_discovery(
        &self,
        request: Request<OidcDiscoveryRequest>,
    ) -> Result<Response<OidcDiscoveryResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let issuer = self.state.issuer.trim_end_matches('/').to_string();
        Ok(Response::new(OidcDiscoveryResponse {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{issuer}/oauth2/authorize"),
            token_endpoint: format!("{issuer}/oauth2/token"),
            userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
            jwks_uri: format!("{issuer}/oauth2/jwks.json"),
            revocation_endpoint: format!("{issuer}/oauth2/revoke"),
            introspection_endpoint: format!("{issuer}/oauth2/introspect"),
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ],
        }))
    }

    async fn get_jwks(
        &self,
        request: Request<JwksRequest>,
    ) -> Result<Response<JwksResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;

        let kid =
            env::var("OIDC_JWKS_KID").unwrap_or_else(|_| "wildon-dev-hs256-v1".to_string());
        let raw_key = env::var("OIDC_JWKS_SYMMETRIC_KEY")
            .unwrap_or_else(|_| "dev-unsafe-change-me".to_string());
        let key = URL_SAFE_NO_PAD.encode(raw_key.as_bytes());

        Ok(Response::new(JwksResponse {
            keys: vec![Jwk {
                kty: "oct".to_string(),
                r#use: "sig".to_string(),
                alg: "HS256".to_string(),
                kid,
                k: key,
            }],
        }))
    }

    async fn authorize_oauth(
        &self,
        request: Request<OAuthAuthorizeRequest>,
    ) -> Result<Response<OAuthAuthorizeResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();

        if payload.response_type != "code" {
            return Err(Status::invalid_argument("response_type must be code"));
        }
        if payload.state.trim().is_empty() {
            return Err(Status::invalid_argument("state is required"));
        }
        if payload.client_id.trim().is_empty()
            || payload.redirect_uri.trim().is_empty()
            || payload.sub.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "client_id, redirect_uri, and sub are required",
            ));
        }
        if payload.aud != payload.realm {
            return Err(Status::invalid_argument("aud and realm must match"));
        }

        let client = load_oauth_client(&self.state.db, payload.client_id.trim())
            .await?
            .ok_or_else(|| Status::unauthenticated("oauth client not found"))?;
        if !client.active {
            return Err(Status::permission_denied("oauth client is disabled"));
        }
        if !client
            .redirect_uris
            .iter()
            .any(|uri| uri == payload.redirect_uri.trim())
        {
            return Err(Status::invalid_argument("redirect_uri mismatch"));
        }
        if !client
            .allowed_grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Err(Status::permission_denied(
                "client does not allow authorization_code",
            ));
        }

        if (client.client_type == "public" || client.require_pkce_s256)
            && (payload.code_challenge.trim().is_empty()
                || payload.code_challenge_method.trim() != "S256")
        {
            return Err(Status::invalid_argument(
                "public clients must use PKCE with code_challenge_method=S256",
            ));
        }

        let scopes = parse_scope_string(&payload.scope);
        if scopes.iter().any(|scope| scope == "openid") && payload.nonce.trim().is_empty() {
            return Err(Status::invalid_argument(
                "nonce is required when openid scope is requested",
            ));
        }

        let user_id = Uuid::parse_str(payload.sub.trim())
            .map_err(|_| Status::invalid_argument("sub must be a uuid"))?;

        let code = format!("oc_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let code_hash = hash_token("oauth_code", &code);
        let expires_at = Utc::now() + Duration::minutes(5);
        let device_id = optional_string(payload.device_id)
            .map(|value| Uuid::parse_str(&value))
            .transpose()
            .map_err(|_| Status::invalid_argument("device_id must be uuid"))?;

        sqlx::query(
            "INSERT INTO auth.oauth_authorization_codes (
                id, code_hash, user_id, client_id, redirect_uri, scope, nonce,
                code_challenge, code_challenge_method, aud, realm, device_id,
                device_fingerprint_hash, user_agent, ip_address, expires_at, consumed_at, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, $12,
                $13, $14, $15::INET, $16, NULL, NOW()
            )",
        )
        .bind(Uuid::new_v4())
        .bind(code_hash)
        .bind(user_id)
        .bind(payload.client_id.trim())
        .bind(payload.redirect_uri.trim())
        .bind(scopes.join(" "))
        .bind(optional_string(payload.nonce))
        .bind(payload.code_challenge.trim())
        .bind(payload.code_challenge_method.trim())
        .bind(payload.aud.trim())
        .bind(payload.realm.trim())
        .bind(device_id)
        .bind(optional_string(payload.device_fingerprint_hash))
        .bind(optional_string(payload.user_agent))
        .bind(optional_string(payload.ip_address))
        .bind(expires_at)
        .execute(&self.state.db)
        .await
        .map_err(|err| Status::internal(format!("db insert authorization code failed: {err}")))?;

        Ok(Response::new(OAuthAuthorizeResponse {
            code,
            state: payload.state,
            redirect_uri: payload.redirect_uri,
            expires_at: expires_at.timestamp(),
        }))
    }

    async fn exchange_oauth_token(
        &self,
        request: Request<OAuthTokenExchangeRequest>,
    ) -> Result<Response<OAuthTokenExchangeResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();
        let grant_type = payload.grant_type.trim();

        match grant_type {
            "authorization_code" => {
                if payload.client_id.trim().is_empty() || payload.code.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "client_id and code are required for authorization_code grant",
                    ));
                }

                let client = load_oauth_client(&self.state.db, payload.client_id.trim())
                    .await?
                    .ok_or_else(|| Status::unauthenticated("oauth client not found"))?;
                validate_oauth_client_auth(&client, payload.client_secret.as_str())?;

                if !client
                    .allowed_grant_types
                    .iter()
                    .any(|grant| grant == "authorization_code")
                {
                    return Err(Status::permission_denied(
                        "client does not allow authorization_code",
                    ));
                }

                let code_hash = hash_token("oauth_code", payload.code.trim());
                let row = sqlx::query(
                    "SELECT user_id, client_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method,
                            aud, realm, device_id, device_fingerprint_hash, user_agent, ip_address, expires_at, consumed_at
                     FROM auth.oauth_authorization_codes
                     WHERE code_hash = $1
                     LIMIT 1",
                )
                .bind(&code_hash)
                .fetch_optional(&self.state.db)
                .await
                .map_err(|err| Status::internal(format!("db read authorization code failed: {err}")))?;

                let Some(row) = row else {
                    return Err(Status::unauthenticated("invalid authorization code"));
                };

                let stored_client_id: String = row.get("client_id");
                let redirect_uri: String = row.get("redirect_uri");
                let scope: String = row.get("scope");
                let nonce: Option<String> = row.get("nonce");
                let code_challenge: String = row.get("code_challenge");
                let code_challenge_method: String = row.get("code_challenge_method");
                let aud: String = row.get("aud");
                let realm: String = row.get("realm");
                let user_id: Uuid = row.get("user_id");
                let device_id: Option<Uuid> = row.get("device_id");
                let device_fingerprint_hash: Option<String> = row.get("device_fingerprint_hash");
                let user_agent: Option<String> = row.get("user_agent");
                let ip_address: Option<String> = row.get("ip_address");
                let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
                let consumed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("consumed_at");

                if stored_client_id != payload.client_id.trim() {
                    return Err(Status::permission_denied(
                        "authorization code client mismatch",
                    ));
                }
                if !payload.redirect_uri.trim().is_empty()
                    && payload.redirect_uri.trim() != redirect_uri
                {
                    return Err(Status::invalid_argument("redirect_uri mismatch"));
                }
                if consumed_at.is_some() || expires_at <= Utc::now() {
                    return Err(Status::unauthenticated("authorization code expired"));
                }

                if code_challenge_method == "S256" {
                    let verifier = payload.code_verifier.trim();
                    if verifier.is_empty() {
                        return Err(Status::invalid_argument("code_verifier is required"));
                    }
                    let derived_challenge = oauth_pkce_s256(verifier);
                    if derived_challenge != code_challenge {
                        return Err(Status::permission_denied("pkce verification failed"));
                    }
                }

                sqlx::query(
                    "UPDATE auth.oauth_authorization_codes
                     SET consumed_at = NOW()
                     WHERE code_hash = $1 AND consumed_at IS NULL",
                )
                .bind(code_hash)
                .execute(&self.state.db)
                .await
                .map_err(|err| {
                    Status::internal(format!("db consume authorization code failed: {err}"))
                })?;

                let scopes = parse_scope_string(&scope);
                let issued = issue_session_tokens(
                    &self.state,
                    IssueSessionInput {
                        sub: user_id.to_string(),
                        aud: aud.clone(),
                        realm: realm.clone(),
                        client_id: Some(payload.client_id),
                        scopes: Some(scopes.clone()),
                        device_id: device_id.map(|value| value.to_string()),
                        device_fingerprint_hash,
                        user_agent,
                        ip_address,
                        mfa_level: 0,
                        remember_me: true,
                        request_id: None,
                    },
                )
                .await
                .map_err(map_session_error_to_grpc)?;

                let id_token = if scopes.iter().any(|scope| scope == "openid") {
                    mint_id_token(
                        &self.state,
                        &user_id,
                        scopes.as_slice(),
                        nonce,
                        client.client_id.as_str(),
                    )
                    .await
                    .unwrap_or_default()
                } else {
                    String::new()
                };

                return Ok(Response::new(OAuthTokenExchangeResponse {
                    access_token: issued.access_token,
                    token_type: issued.token_type.to_string(),
                    expires_at: issued.access_expires_at,
                    refresh_token: issued.refresh_token,
                    session_id: issued.session_id,
                    refresh_expires_at: issued.refresh_expires_at,
                    session_version: issued.session_version,
                    id_token,
                    scope: scopes.join(" "),
                }));
            }
            "refresh_token" => {
                if payload.refresh_token.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "refresh_token is required for refresh_token grant",
                    ));
                }

                if !payload.client_id.trim().is_empty() {
                    if let Some(client) =
                        load_oauth_client(&self.state.db, payload.client_id.trim()).await?
                    {
                        validate_oauth_client_auth(&client, payload.client_secret.as_str())?;
                    }
                }

                let refreshed = refresh_session_tokens(
                    &self.state,
                    RefreshSessionInput {
                        token: payload.refresh_token,
                        device_id: None,
                        request_id: None,
                    },
                )
                .await
                .map_err(map_session_error_to_grpc)?;

                return Ok(Response::new(OAuthTokenExchangeResponse {
                    access_token: refreshed.access_token,
                    token_type: refreshed.token_type.to_string(),
                    expires_at: refreshed.access_expires_at,
                    refresh_token: refreshed.refresh_token,
                    session_id: refreshed.session_id,
                    refresh_expires_at: refreshed.refresh_expires_at,
                    session_version: refreshed.session_version,
                    id_token: String::new(),
                    scope: String::new(),
                }));
            }
            "client_credentials" => {
                if payload.client_id.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "client_id is required for client_credentials grant",
                    ));
                }
                let client = load_oauth_client(&self.state.db, payload.client_id.trim())
                    .await?
                    .ok_or_else(|| Status::unauthenticated("oauth client not found"))?;
                if client.client_type != "confidential" {
                    return Err(Status::permission_denied(
                        "public clients cannot use client_credentials",
                    ));
                }
                validate_oauth_client_auth(&client, payload.client_secret.as_str())?;
                if !client
                    .allowed_grant_types
                    .iter()
                    .any(|grant| grant == "client_credentials")
                {
                    return Err(Status::permission_denied(
                        "client does not allow client_credentials",
                    ));
                }

                let now = Utc::now();
                let exp = now + Duration::minutes(10);
                let scopes = parse_scope_string(&payload.scope);
                let claims = auth::claims::Claims {
                    sub: format!("svc:{}", client.client_id),
                    cid: client.client_id,
                    aud: "control".to_string(),
                    iss: self.state.issuer.clone(),
                    realm: "control".to_string(),
                    iat: now.timestamp(),
                    exp: exp.timestamp(),
                    jti: Uuid::new_v4().to_string(),
                    sid: None,
                    scopes: if scopes.is_empty() {
                        vec!["core:read".to_string()]
                    } else {
                        scopes.clone()
                    },
                    amr: vec!["client_credentials".to_string()],
                    sv: 1,
                    perm_rev: 1,
                    device_id: None,
                    roles: vec!["service".to_string()],
                };
                let token = URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&claims)
                        .map_err(|err| Status::internal(format!("token encode failed: {err}")))?,
                );

                return Ok(Response::new(OAuthTokenExchangeResponse {
                    access_token: token,
                    token_type: "Bearer".to_string(),
                    expires_at: exp.timestamp(),
                    refresh_token: String::new(),
                    session_id: String::new(),
                    refresh_expires_at: 0,
                    session_version: 1,
                    id_token: String::new(),
                    scope: if scopes.is_empty() {
                        "core:read".to_string()
                    } else {
                        scopes.join(" ")
                    },
                }));
            }
            _ => {
                return Err(Status::invalid_argument(
                    "unsupported grant_type; allowed: authorization_code, refresh_token, client_credentials",
                ));
            }
        }
    }

    async fn get_user_info(
        &self,
        request: Request<UserInfoRequest>,
    ) -> Result<Response<UserInfoResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();

        if payload.access_token.trim().is_empty() {
            return Err(Status::invalid_argument("access_token is required"));
        }

        let claims = jwt::decode_token(payload.access_token.trim())
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        jwt::validate_claims(&claims)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;

        let (email, email_verified, name) = if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
            if let Ok(Some(row)) =
                sqlx::query("SELECT email, email_verified FROM auth.users WHERE id = $1")
                    .bind(user_id)
                    .fetch_optional(&self.state.db)
                    .await
            {
                let email: Option<String> = row.try_get("email").ok();
                let email_verified: bool = row.try_get("email_verified").unwrap_or(false);
                (email.unwrap_or_default(), email_verified, String::new())
            } else {
                (String::new(), false, String::new())
            }
        } else {
            (String::new(), false, String::new())
        };

        Ok(Response::new(UserInfoResponse {
            sub: claims.sub,
            email,
            email_verified,
            name,
            client_id: claims.cid,
            aud: claims.aud,
            realm: claims.realm,
            scopes: claims.scopes,
        }))
    }

    async fn revoke_oauth_token(
        &self,
        request: Request<OAuthRevokeRequest>,
    ) -> Result<Response<OAuthRevokeResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let payload = request.into_inner();
        if payload.token.trim().is_empty() {
            return Ok(Response::new(OAuthRevokeResponse { revoked: true }));
        }

        let revoked = if payload
            .token_type_hint
            .trim()
            .eq_ignore_ascii_case("refresh_token")
            || payload.token.starts_with("rt_")
        {
            let result = logout_session_by_refresh_token(
                &self.state,
                LogoutSessionInput {
                    refresh_token: payload.token,
                    reason: "oauth_revoke".to_string(),
                    request_id: None,
                },
            )
            .await
            .map_err(map_session_error_to_grpc)?;
            result.revoked
        } else {
            let claims = jwt::decode_token(payload.token.trim()).ok();
            if let Some(claims) = claims {
                if let Some(sid) = claims.sid {
                    if let Ok(session_id) = Uuid::parse_str(&sid) {
                        sqlx::query(
                            "UPDATE auth.sessions
                             SET revoked_at = COALESCE(revoked_at, NOW()),
                                 revoked_reason = COALESCE(revoked_reason, 'oauth_revoke')
                             WHERE id = $1",
                        )
                        .bind(session_id)
                        .execute(&self.state.db)
                        .await
                        .ok();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        };

        Ok(Response::new(OAuthRevokeResponse { revoked }))
    }

    async fn introspect_oauth_token(
        &self,
        request: Request<OAuthIntrospectRequest>,
    ) -> Result<Response<OAuthIntrospectResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["gateway-service", "control-service", "platform-service"],
        )?;
        let payload = request.into_inner();
        if payload.token.trim().is_empty() {
            return Ok(Response::new(OAuthIntrospectResponse {
                active: false,
                sub: String::new(),
                client_id: String::new(),
                aud: String::new(),
                realm: String::new(),
                exp: 0,
                iat: 0,
                scope: String::new(),
                token_type: "Bearer".to_string(),
            }));
        }

        let claims = match jwt::decode_token(payload.token.trim()) {
            Ok(claims) => claims,
            Err(_) => {
                return Ok(Response::new(OAuthIntrospectResponse {
                    active: false,
                    sub: String::new(),
                    client_id: String::new(),
                    aud: String::new(),
                    realm: String::new(),
                    exp: 0,
                    iat: 0,
                    scope: String::new(),
                    token_type: "Bearer".to_string(),
                }));
            }
        };

        let valid = jwt::validate_claims(&claims).is_ok()
            && validate_claims_against_session(&self.state, &claims)
                .await
                .unwrap_or(false);

        Ok(Response::new(OAuthIntrospectResponse {
            active: valid,
            sub: if valid { claims.sub } else { String::new() },
            client_id: if valid { claims.cid } else { String::new() },
            aud: if valid { claims.aud } else { String::new() },
            realm: if valid { claims.realm } else { String::new() },
            exp: if valid { claims.exp } else { 0 },
            iat: if valid { claims.iat } else { 0 },
            scope: if valid {
                claims.scopes.join(" ")
            } else {
                String::new()
            },
            token_type: "Bearer".to_string(),
        }))
    }

    async fn social_login_google(
        &self,
        request: Request<SocialLoginGoogleRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let payload = request.into_inner();
        if payload.id_token.trim().is_empty() {
            return Err(Status::invalid_argument("google id_token is required"));
        }
        if payload.aud != payload.realm {
            return Err(Status::invalid_argument("aud and realm must match"));
        }

        let social_subject = derive_social_subject("google", payload.id_token.trim());
        let user_id = resolve_or_create_social_user(
            &self.state,
            "google",
            &social_subject,
            optional_string(payload.email),
            optional_string(payload.first_name),
            optional_string(payload.last_name),
            request_id.as_deref(),
            traceparent.as_deref(),
        )
        .await?;

        let issued = issue_session_tokens(
            &self.state,
            IssueSessionInput {
                sub: user_id.to_string(),
                aud: payload.aud,
                realm: payload.realm,
                client_id: optional_string(payload.client_id),
                scopes: None,
                device_id: optional_string(payload.device_id),
                device_fingerprint_hash: optional_string(payload.device_fingerprint_hash),
                user_agent: optional_string(payload.user_agent),
                ip_address: optional_string(payload.ip_address),
                mfa_level: 0,
                remember_me: payload.remember_me.unwrap_or(true),
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: issued.access_token,
            token_type: issued.token_type.to_string(),
            expires_at: issued.access_expires_at,
            refresh_token: issued.refresh_token,
            session_id: issued.session_id,
            refresh_expires_at: issued.refresh_expires_at,
            session_version: issued.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }

    async fn social_login_apple(
        &self,
        request: Request<SocialLoginAppleRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["gateway-service"])?;
        let request_id = metadata_value(&request, "x-request-id");
        let traceparent = metadata_value(&request, "traceparent");
        let payload = request.into_inner();
        if payload.id_token.trim().is_empty() {
            return Err(Status::invalid_argument("apple id_token is required"));
        }
        if payload.aud != payload.realm {
            return Err(Status::invalid_argument("aud and realm must match"));
        }

        let social_subject = derive_social_subject("apple", payload.id_token.trim());
        let user_id = resolve_or_create_social_user(
            &self.state,
            "apple",
            &social_subject,
            optional_string(payload.email),
            optional_string(payload.first_name),
            optional_string(payload.last_name),
            request_id.as_deref(),
            traceparent.as_deref(),
        )
        .await?;

        let issued = issue_session_tokens(
            &self.state,
            IssueSessionInput {
                sub: user_id.to_string(),
                aud: payload.aud,
                realm: payload.realm,
                client_id: optional_string(payload.client_id),
                scopes: None,
                device_id: optional_string(payload.device_id),
                device_fingerprint_hash: optional_string(payload.device_fingerprint_hash),
                user_agent: optional_string(payload.user_agent),
                ip_address: optional_string(payload.ip_address),
                mfa_level: 0,
                remember_me: payload.remember_me.unwrap_or(true),
                request_id,
            },
        )
        .await
        .map_err(map_session_error_to_grpc)?;

        Ok(Response::new(IssueTokenResponse {
            access_token: issued.access_token,
            token_type: issued.token_type.to_string(),
            expires_at: issued.access_expires_at,
            refresh_token: issued.refresh_token,
            session_id: issued.session_id,
            refresh_expires_at: issued.refresh_expires_at,
            session_version: issued.session_version,
            mfa_required: false,
            mfa_challenge_token: String::new(),
            mfa_method: String::new(),
        }))
    }
}

#[tokio::main]
async fn main() {
    init_tracing("auth-service");

    let http_addr = env::var("AUTH_HTTP_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
        .parse::<SocketAddr>()
        .expect("invalid AUTH_HTTP_BIND_ADDR");
    let grpc_addr = env::var("AUTH_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse::<SocketAddr>()
        .expect("invalid AUTH_GRPC_BIND_ADDR");

    let issuer =
        env::var("JWT_ISSUER").unwrap_or_else(|_| "https://auth.wildon.local".to_string());
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://yugabyte@127.0.0.1:5433/wildon".to_string());
    let database_max_connections = env::var("AUTH_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(20);
    let redis_cache_ttl_seconds = env::var("AUTH_SESSION_CACHE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);

    let access_ttl_public_seconds = env::var("AUTH_ACCESS_TTL_PUBLIC_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(15 * 60);
    let access_ttl_platform_seconds = env::var("AUTH_ACCESS_TTL_PLATFORM_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(10 * 60);
    let access_ttl_control_seconds = env::var("AUTH_ACCESS_TTL_CONTROL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(5 * 60);
    let refresh_ttl_public_seconds = env::var("AUTH_REFRESH_TTL_PUBLIC_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30 * 24 * 60 * 60);
    let refresh_ttl_platform_seconds = env::var("AUTH_REFRESH_TTL_PLATFORM_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(14 * 24 * 60 * 60);
    let refresh_ttl_control_seconds = env::var("AUTH_REFRESH_TTL_CONTROL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(14 * 24 * 60 * 60);
    let session_abs_ttl_public_seconds = env::var("AUTH_ABSOLUTE_SESSION_TTL_PUBLIC_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(90 * 24 * 60 * 60);
    let session_abs_ttl_platform_seconds = env::var("AUTH_ABSOLUTE_SESSION_TTL_PLATFORM_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30 * 24 * 60 * 60);
    let session_abs_ttl_control_seconds = env::var("AUTH_ABSOLUTE_SESSION_TTL_CONTROL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30 * 24 * 60 * 60);
    let inactivity_ttl_public_seconds = env::var("AUTH_INACTIVITY_TTL_PUBLIC_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30 * 24 * 60 * 60);
    let inactivity_ttl_platform_seconds = env::var("AUTH_INACTIVITY_TTL_PLATFORM_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(14 * 24 * 60 * 60);
    let inactivity_ttl_control_seconds = env::var("AUTH_INACTIVITY_TTL_CONTROL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(7 * 24 * 60 * 60);
    let cleanup_interval_seconds = env::var("AUTH_CLEANUP_INTERVAL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);

    let db = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .connect(&database_url)
        .await
        .expect("failed to connect to auth database");

    let redis = env::var("REDIS_URL")
        .ok()
        .and_then(|url| redis::Client::open(url).ok());
    let users_grpc_endpoint =
        env::var("USERS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50057".to_string());
    let users_channel = connect_channel(&users_grpc_endpoint, "users-service")
        .await
        .expect("failed to connect to users-service grpc endpoint");
    let users_client = UsersServiceClient::new(users_channel);

    let state = AppState::new(
        issuer,
        db,
        redis,
        users_client,
        redis_cache_ttl_seconds,
        TokenPolicyConfig {
            access_ttl_public_seconds,
            access_ttl_platform_seconds,
            access_ttl_control_seconds,
            refresh_ttl_public_seconds,
            refresh_ttl_platform_seconds,
            refresh_ttl_control_seconds,
            absolute_session_ttl_public_seconds: session_abs_ttl_public_seconds,
            absolute_session_ttl_platform_seconds: session_abs_ttl_platform_seconds,
            absolute_session_ttl_control_seconds: session_abs_ttl_control_seconds,
            inactivity_ttl_public_seconds,
            inactivity_ttl_platform_seconds,
            inactivity_ttl_control_seconds,
        },
    );

    let http_router = routes::router(state.clone());

    let http_task = tokio::spawn(async move {
        let listener = TcpListener::bind(http_addr)
            .await
            .expect("failed to bind auth http listener");
        tracing::info!(address = %http_addr, "auth http listening");
        axum::serve(listener, http_router)
            .await
            .expect("auth http server failed");
    });

    let grpc = AuthGrpc {
        state: state.clone(),
        internal_auth: InternalAuthPolicy::from_env("auth-service"),
    };
    let grpc_task = tokio::spawn(async move {
        tracing::info!(address = %grpc_addr, "auth grpc listening");
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<AuthServiceServer<AuthGrpc>>()
            .await;
        let mut builder = tonic::transport::Server::builder();
        if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
            builder = builder
                .tls_config(tls)
                .expect("failed to apply auth grpc tls config");
        }
        builder
            .add_service(health_service)
            .add_service(AuthServiceServer::new(grpc))
            .serve(grpc_addr)
            .await
            .expect("auth grpc server failed");
    });

    let cleanup_state = state.clone();
    let cleanup_task = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_seconds));
        loop {
            interval.tick().await;
            if let Err(err) = run_cleanup_once(&cleanup_state).await {
                tracing::warn!(error = %err, "auth cleanup worker run failed");
            }
        }
    });

    let _ = tokio::join!(http_task, grpc_task, cleanup_task);
}

async fn load_active_authenticator_factor(
    db: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Option<MfaAuthenticatorFactor>, Status> {
    let row = sqlx::query(
        "SELECT id, secret_base32
         FROM auth.mfa_factors
         WHERE user_id = $1
           AND factor_type = 'authenticator'
           AND status = 'active'
         ORDER BY verified_at DESC NULLS LAST, created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|err| Status::internal(format!("db load active mfa factor failed: {err}")))?;

    Ok(row.map(|row| MfaAuthenticatorFactor {
        id: row.get("id"),
        secret_base32: row.get("secret_base32"),
    }))
}

async fn load_active_authenticator_factor_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<Option<MfaAuthenticatorFactor>, Status> {
    let row = sqlx::query(
        "SELECT id, secret_base32
         FROM auth.mfa_factors
         WHERE user_id = $1
           AND factor_type = 'authenticator'
           AND status = 'active'
         ORDER BY verified_at DESC NULLS LAST, created_at DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db lock active mfa factor failed: {err}")))?;

    Ok(row.map(|row| MfaAuthenticatorFactor {
        id: row.get("id"),
        secret_base32: row.get("secret_base32"),
    }))
}

async fn load_pending_authenticator_factor_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<Option<MfaAuthenticatorFactor>, Status> {
    let row = sqlx::query(
        "SELECT id, secret_base32
         FROM auth.mfa_factors
         WHERE user_id = $1
           AND factor_type = 'authenticator'
           AND status = 'pending'
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db lock pending mfa factor failed: {err}")))?;

    Ok(row.map(|row| MfaAuthenticatorFactor {
        id: row.get("id"),
        secret_base32: row.get("secret_base32"),
    }))
}

async fn create_mfa_login_challenge(
    db: &sqlx::PgPool,
    user_id: Uuid,
    factor_type: &str,
    aud: &str,
    realm: &str,
    client_id: Option<String>,
    device_id: Option<String>,
    device_fingerprint_hash: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    remember_me: bool,
) -> Result<String, Status> {
    let mut random = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut random);
    let challenge_token = URL_SAFE_NO_PAD.encode(random);
    let challenge_hash = hash_token("mfa_login_challenge", &challenge_token);
    let expires_at = Utc::now() + Duration::seconds(auth_mfa_login_challenge_ttl_seconds().max(30));

    let device_uuid = match device_id.as_deref() {
        Some(value) => Some(
            Uuid::parse_str(value)
                .map_err(|_| Status::invalid_argument("invalid device_id format"))?,
        ),
        None => None,
    };
    let ip_addr = match ip_address.as_deref() {
        Some(value) => {
            let parsed = std::net::IpAddr::from_str(value)
                .map_err(|_| Status::invalid_argument("invalid ip_address format"))?;
            Some(parsed.to_string())
        }
        None => None,
    };

    sqlx::query(
        "INSERT INTO auth.mfa_login_challenges (
            id,
            user_id,
            factor_type,
            challenge_hash,
            aud,
            realm,
            client_id,
            device_id,
            device_fingerprint_hash,
            user_agent,
            ip_address,
            remember_me,
            attempts,
            expires_at,
            consumed_at,
            created_at
         ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11::INET,
            $12,
            0,
            $13,
            NULL,
            NOW()
         )",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(factor_type)
    .bind(challenge_hash)
    .bind(aud)
    .bind(realm)
    .bind(client_id)
    .bind(device_uuid)
    .bind(device_fingerprint_hash)
    .bind(user_agent)
    .bind(ip_addr)
    .bind(remember_me)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|err| Status::internal(format!("db create mfa login challenge failed: {err}")))?;

    Ok(challenge_token)
}

async fn load_mfa_login_challenge_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_token: &str,
) -> Result<Option<MfaLoginChallenge>, Status> {
    let challenge_hash = hash_token("mfa_login_challenge", challenge_token);
    let row = sqlx::query(
        "SELECT id,
                user_id,
                factor_type,
                aud,
                realm,
                client_id,
                device_id::TEXT AS device_id,
                device_fingerprint_hash,
                user_agent,
                ip_address::TEXT AS ip_address,
                remember_me,
                attempts,
                expires_at
         FROM auth.mfa_login_challenges
         WHERE challenge_hash = $1
           AND consumed_at IS NULL
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind(challenge_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db lock mfa login challenge failed: {err}")))?;

    Ok(row.map(|row| MfaLoginChallenge {
        id: row.get("id"),
        user_id: row.get("user_id"),
        factor_type: row.get("factor_type"),
        aud: row.get("aud"),
        realm: row.get("realm"),
        client_id: row.get("client_id"),
        device_id: row.get("device_id"),
        device_fingerprint_hash: row.get("device_fingerprint_hash"),
        user_agent: row.get("user_agent"),
        ip_address: row.get("ip_address"),
        remember_me: row.get("remember_me"),
        expires_at: row.get("expires_at"),
        attempts: row.get("attempts"),
    }))
}

async fn increment_mfa_challenge_attempts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_id: Uuid,
) -> Result<(), Status> {
    sqlx::query(
        "UPDATE auth.mfa_login_challenges
         SET attempts = attempts + 1
         WHERE id = $1",
    )
    .bind(challenge_id)
    .execute(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db update mfa challenge attempts failed: {err}")))?;
    Ok(())
}

async fn mark_mfa_challenge_consumed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    challenge_id: Uuid,
) -> Result<(), Status> {
    sqlx::query(
        "UPDATE auth.mfa_login_challenges
         SET consumed_at = NOW(),
             attempts = attempts + 1
         WHERE id = $1",
    )
    .bind(challenge_id)
    .execute(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db consume mfa challenge failed: {err}")))?;
    Ok(())
}

async fn mark_mfa_factor_used(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    factor_id: Uuid,
) -> Result<(), Status> {
    sqlx::query(
        "UPDATE auth.mfa_factors
         SET last_used_at = NOW()
         WHERE id = $1",
    )
    .bind(factor_id)
    .execute(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db update mfa factor usage failed: {err}")))?;
    Ok(())
}

async fn revoke_active_backup_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    factor_id: Option<Uuid>,
) -> Result<(), Status> {
    if let Some(factor_id) = factor_id {
        sqlx::query(
            "UPDATE auth.mfa_backup_codes
             SET status = 'revoked',
                 revoked_at = NOW()
             WHERE user_id = $1
               AND factor_id = $2
               AND status = 'active'",
        )
        .bind(user_id)
        .bind(factor_id)
        .execute(&mut **tx)
        .await
        .map_err(|err| Status::internal(format!("db revoke backup codes failed: {err}")))?;
    } else {
        sqlx::query(
            "UPDATE auth.mfa_backup_codes
             SET status = 'revoked',
                 revoked_at = NOW()
             WHERE user_id = $1
               AND status = 'active'",
        )
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(|err| Status::internal(format!("db revoke backup codes failed: {err}")))?;
    }
    Ok(())
}

async fn create_backup_codes_for_factor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    factor_id: Uuid,
    count: usize,
) -> Result<Vec<String>, Status> {
    let codes = generate_backup_codes(count);
    for code in &codes {
        let Some(normalized) = normalize_backup_code(code) else {
            return Err(Status::internal("generated invalid backup code"));
        };
        let code_hash = hash_token("mfa_backup_code", &normalized);
        let code_suffix = normalized[normalized.len() - 4..].to_string();
        sqlx::query(
            "INSERT INTO auth.mfa_backup_codes (
                id,
                user_id,
                factor_id,
                code_hash,
                code_suffix,
                status,
                used_at,
                revoked_at,
                created_at
             ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                'active',
                NULL,
                NULL,
                NOW()
             )",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(factor_id)
        .bind(code_hash)
        .bind(code_suffix)
        .execute(&mut **tx)
        .await
        .map_err(|err| Status::internal(format!("db create backup code failed: {err}")))?;
    }
    Ok(codes)
}

async fn consume_backup_code_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    normalized_code: &str,
) -> Result<Option<MfaBackupCodeRecord>, Status> {
    let code_hash = hash_token("mfa_backup_code", normalized_code);
    let row = sqlx::query(
        "SELECT id, factor_id
         FROM auth.mfa_backup_codes
         WHERE user_id = $1
           AND code_hash = $2
           AND status = 'active'
         LIMIT 1
         FOR UPDATE",
    )
    .bind(user_id)
    .bind(code_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db lock backup code failed: {err}")))?;

    let Some(row) = row else {
        return Ok(None);
    };
    let id: Uuid = row.get("id");
    let factor_id: Uuid = row.get("factor_id");

    sqlx::query(
        "UPDATE auth.mfa_backup_codes
         SET status = 'used',
             used_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(|err| Status::internal(format!("db consume backup code failed: {err}")))?;

    Ok(Some(MfaBackupCodeRecord { id, factor_id }))
}

fn normalize_mfa_factor_type(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        MFA_FACTOR_AUTHENTICATOR => Some(MFA_FACTOR_AUTHENTICATOR.to_string()),
        MFA_FACTOR_SMS => Some(MFA_FACTOR_SMS.to_string()),
        MFA_FACTOR_BACKUP_CODE => Some(MFA_FACTOR_BACKUP_CODE.to_string()),
        _ => None,
    }
}

fn mask_phone_e164(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 4 {
        return "****".to_string();
    }
    let tail = &trimmed[trimmed.len() - 4..];
    format!("***{tail}")
}

fn auth_mfa_totp_issuer() -> String {
    env::var("AUTH_MFA_TOTP_ISSUER").unwrap_or_else(|_| "Wildon".to_string())
}

fn auth_mfa_totp_drift_steps() -> i64 {
    env::var("AUTH_MFA_TOTP_DRIFT_STEPS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|value| value.clamp(0, 3))
        .unwrap_or(1)
}

fn auth_mfa_login_challenge_ttl_seconds() -> i64 {
    env::var("AUTH_MFA_LOGIN_CHALLENGE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(300)
}

fn auth_mfa_backup_codes_count() -> usize {
    env::var("AUTH_MFA_BACKUP_CODES_COUNT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(4, 20))
        .unwrap_or(10)
}

fn optional_string(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn map_session_error_to_grpc(err: SessionError) -> Status {
    match err {
        SessionError::InvalidSubject
        | SessionError::InvalidDeviceId
        | SessionError::InvalidSessionId
        | SessionError::InvalidCursor
        | SessionError::UnsupportedAudience
        | SessionError::AudienceRealmMismatch => Status::invalid_argument(err.to_string()),
        SessionError::InvalidRefreshToken
        | SessionError::RefreshTokenExpired
        | SessionError::SessionExpiredOrRevoked
        | SessionError::DeviceBindingMismatch
        | SessionError::RefreshReuseDetected
        | SessionError::UserNotFound => Status::unauthenticated(err.to_string()),
        SessionError::UserDisabled | SessionError::AuditorAccessDenied => {
            Status::permission_denied(err.to_string())
        }
        SessionError::UserStateUnavailable(_) => Status::unavailable(err.to_string()),
        SessionError::Db(_) => Status::internal(err.to_string()),
    }
}

fn normalize_email(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || !normalized.contains('@') {
        None
    } else {
        Some(normalized)
    }
}

fn validate_password_policy(password: &str) -> Result<(), &'static str> {
    if password.len() < 10 {
        return Err("password must be at least 10 characters");
    }
    if password.len() > 128 {
        return Err("password must be at most 128 characters");
    }
    let has_lower = password.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = password.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return Err("password must include uppercase, lowercase, and numeric characters");
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

fn verify_password(stored_hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn generate_otp_code() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..=999_999))
}

fn hash_otp(purpose: &str, user_id: &str, otp_code: &str) -> String {
    hash_token(purpose, format!("{user_id}:{otp_code}"))
}

fn hash_token(purpose: &str, raw: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(purpose.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

async fn send_template_email(
    state: &AppState,
    destination: &str,
    template_name: &str,
    variables: HashMap<String, String>,
    fallback_subject: &str,
    fallback_html: &str,
) -> Result<(), String> {
    validate_template_variables(&variables)?;

    let mut subject = render_subject_template(fallback_subject, &variables)
        .unwrap_or_else(|_| fallback_subject.to_string());
    let mut html = render_html_template(fallback_html, &variables)
        .unwrap_or_else(|_| ammonia::clean(fallback_html));

    match load_email_template(state, template_name).await {
        Ok(Some(template)) => {
            match (
                render_subject_template(&template.subject_template, &variables),
                render_html_template(&template.html_template, &variables),
            ) {
                (Ok(rendered_subject), Ok(rendered_html)) => {
                    subject = rendered_subject;
                    html = rendered_html;
                }
                (subject_result, html_result) => {
                    tracing::warn!(
                        template_name,
                        subject_error = %subject_result.err().unwrap_or_default(),
                        html_error = %html_result.err().unwrap_or_default(),
                        "failed to render stored email template, using fallback",
                    );
                }
            }
        }
        Ok(None) => {
            tracing::warn!(template_name, "email template not found, using fallback");
        }
        Err(err) => {
            tracing::warn!(template_name, error = %err, "failed to load email template, using fallback");
        }
    }

    send_email(destination, &subject, &html)
}

fn spawn_template_email(
    state: &AppState,
    destination: String,
    template_name: &'static str,
    variables: HashMap<String, String>,
    fallback_subject: &'static str,
    fallback_html: &'static str,
) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = send_template_email(
            &state,
            &destination,
            template_name,
            variables,
            fallback_subject,
            fallback_html,
        )
        .await
        {
            tracing::warn!(
                error = %err,
                destination,
                template_name,
                "auth email send failed"
            );
        }
    });
}

fn send_email(destination: &str, subject: &str, message: &str) -> Result<(), String> {
    let payload = NotificationPayload {
        destination: destination.to_string(),
        subject: subject.to_string(),
        message: message.to_string(),
    };
    let client = SendgridClient::from_env();
    match client.send(NotificationChannel::Email, &payload) {
        Ok(receipt) => {
            tracing::info!(
                provider = receipt.provider,
                external_id = receipt.external_id,
                destination,
                "auth email sent"
            );
            Ok(())
        }
        Err(err) => {
            tracing::warn!(error = %err, destination, "auth email send failed");
            Err(err.to_string())
        }
    }
}

async fn load_email_template(
    state: &AppState,
    template_name: &str,
) -> Result<Option<AuthEmailTemplate>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT subject_template, html_template
         FROM control_app.email_templates
         WHERE template_name = $1
         LIMIT 1",
    )
    .bind(template_name)
    .fetch_optional(&state.db)
    .await?;

    Ok(row.map(|row| AuthEmailTemplate {
        subject_template: row.get("subject_template"),
        html_template: row.get("html_template"),
    }))
}

fn validate_template_variables(variables: &HashMap<String, String>) -> Result<(), String> {
    if variables.len() > MAX_TEMPLATE_VARIABLES {
        return Err(format!(
            "too many template variables, max={MAX_TEMPLATE_VARIABLES}"
        ));
    }

    for (key, value) in variables {
        if !is_valid_template_key(key) {
            return Err(format!("invalid template variable key `{key}`"));
        }
        if value.len() > MAX_TEMPLATE_VARIABLE_VALUE_LEN {
            return Err(format!("template variable `{key}` exceeds max length"));
        }
    }

    Ok(())
}

fn render_subject_template(
    template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, String> {
    let rendered = render_template(template, variables, false)?;
    let subject = rendered.trim();
    if subject.is_empty() {
        return Err("rendered subject is empty".to_string());
    }
    if subject.contains('\n') || subject.contains('\r') {
        return Err("rendered subject contains newlines".to_string());
    }
    if subject.len() > 200 {
        return Err("rendered subject exceeds max length".to_string());
    }
    Ok(subject.to_string())
}

fn render_html_template(
    template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, String> {
    let rendered = render_template(template, variables, true)?;
    let sanitized = ammonia::clean(rendered.trim());
    if sanitized.trim().is_empty() {
        return Err("rendered html is empty after sanitization".to_string());
    }
    Ok(sanitized)
}

fn render_template(
    template: &str,
    variables: &HashMap<String, String>,
    escape_values_for_html: bool,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut cursor = 0;

    while let Some(open_rel) = template[cursor..].find("{{") {
        let open = cursor + open_rel;
        out.push_str(&template[cursor..open]);

        let token_start = open + 2;
        let Some(close_rel) = template[token_start..].find("}}") else {
            return Err("template contains unclosed placeholder".to_string());
        };
        let token_end = token_start + close_rel;
        let key = template[token_start..token_end].trim();
        if !is_valid_template_key(key) {
            return Err(format!("template contains invalid placeholder `{key}`"));
        }

        let value = variables
            .get(key)
            .ok_or_else(|| format!("missing template variable `{key}`"))?;

        if escape_values_for_html {
            out.push_str(&escape_html(value));
        } else {
            out.push_str(value);
        }

        cursor = token_end + 2;
    }

    out.push_str(&template[cursor..]);
    Ok(out)
}

fn is_valid_template_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Debug, Clone)]
struct AuthEmailTemplate {
    subject_template: String,
    html_template: String,
}

const MAX_TEMPLATE_VARIABLES: usize = 64;
const MAX_TEMPLATE_VARIABLE_VALUE_LEN: usize = 4_096;

async fn ensure_email_verification_otp(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    email: &str,
) -> Result<String, sqlx::Error> {
    let otp_code = generate_otp_code();
    let otp_hash = hash_otp("email_verify", &user_id.to_string(), &otp_code);
    let otp_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO auth.email_verification_otps (
            id, user_id, email, otp_hash, expires_at, consumed_at, attempts, created_at
         ) VALUES ($1, $2, $3, $4, $5, NULL, 0, NOW())",
    )
    .bind(otp_id)
    .bind(user_id)
    .bind(email)
    .bind(otp_hash)
    .bind(expires_at)
    .execute(&mut **tx)
    .await?;

    Ok(otp_code)
}

async fn ensure_password_reset_otp(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    email: &str,
) -> Result<String, sqlx::Error> {
    let otp_code = generate_otp_code();
    let otp_hash = hash_otp("password_reset", &user_id.to_string(), &otp_code);
    let otp_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO auth.password_reset_otps (
            id, user_id, email, otp_hash, expires_at, attempts,
            verified_at, reset_token_hash, reset_token_expires_at, consumed_at, created_at
         ) VALUES (
            $1, $2, $3, $4, $5, 0,
            NULL, NULL, NULL, NULL, NOW()
         )",
    )
    .bind(otp_id)
    .bind(user_id)
    .bind(email)
    .bind(otp_hash)
    .bind(expires_at)
    .execute(&mut **tx)
    .await?;

    Ok(otp_code)
}

async fn consume_rate_limit_counter(
    state: &AppState,
    key: &str,
    limit: i64,
    window_seconds: u64,
) -> bool {
    let Some(redis) = &state.redis else {
        return true;
    };

    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return true;
    };

    let Ok(count) = conn.incr::<_, _, i64>(key, 1).await else {
        return true;
    };
    if count == 1 {
        let _ = conn.expire::<_, bool>(key, window_seconds as i64).await;
    }

    count <= limit
}

async fn load_auditor_access_policy(
    db: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Option<AuditorAccessPolicy>, Status> {
    let row = sqlx::query(
        "SELECT is_active, expires_at, allowed_ips
         FROM control_app.audit_accounts
         WHERE user_id = $1
           AND role = 'auditor'
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|err| Status::internal(format!("db auditor lookup failed: {err}")))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let allowed_ips = row
        .get::<Option<serde_json::Value>, _>("allowed_ips")
        .map(parse_allowed_ips)
        .transpose()?;

    Ok(Some(AuditorAccessPolicy {
        is_active: row.get("is_active"),
        expires_at: row.get("expires_at"),
        allowed_ips,
    }))
}

fn parse_allowed_ips(value: serde_json::Value) -> Result<Vec<String>, Status> {
    let items = value.as_array().ok_or_else(|| {
        Status::internal("audit_accounts.allowed_ips must be stored as a json array")
    })?;
    let mut allowed = Vec::with_capacity(items.len());
    for item in items {
        let raw = item
            .as_str()
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .ok_or_else(|| {
                Status::internal("audit_accounts.allowed_ips entries must be strings")
            })?;
        validate_allowed_ip_entry(raw)?;
        allowed.push(raw.to_string());
    }
    Ok(allowed)
}

fn enforce_auditor_access_policy(
    policy: &AuditorAccessPolicy,
    request_ip: Option<&str>,
    denied_message: &str,
) -> Result<(), Status> {
    if !policy.is_active {
        return Err(Status::permission_denied(denied_message));
    }
    if policy.expires_at <= Utc::now() {
        return Err(Status::permission_denied(denied_message));
    }
    if let Some(allowed_ips) = policy.allowed_ips.as_ref() {
        let Some(ip) = request_ip else {
            return Err(Status::permission_denied(denied_message));
        };
        if !ip_matches_any_allowed(ip, allowed_ips) {
            return Err(Status::permission_denied(denied_message));
        }
    }
    Ok(())
}

fn validate_allowed_ip_entry(value: &str) -> Result<(), Status> {
    if value.contains('/') {
        value
            .parse::<IpNet>()
            .map(|_| ())
            .map_err(|_| Status::invalid_argument("invalid allowed_ips CIDR entry"))
    } else {
        std::net::IpAddr::from_str(value)
            .map(|_| ())
            .map_err(|_| Status::invalid_argument("invalid allowed_ips IP entry"))
    }
}

fn ip_matches_any_allowed(ip: &str, allowed_ips: &[String]) -> bool {
    let Ok(parsed_ip) = std::net::IpAddr::from_str(ip.trim()) else {
        return false;
    };

    allowed_ips.iter().any(|candidate| {
        let candidate = candidate.trim();
        if candidate.contains('/') {
            candidate
                .parse::<IpNet>()
                .map(|network| network.contains(&parsed_ip))
                .unwrap_or(false)
        } else {
            std::net::IpAddr::from_str(candidate)
                .map(|allowed| allowed == parsed_ip)
                .unwrap_or(false)
        }
    })
}

async fn is_account_locked(state: &AppState, account: &str) -> bool {
    let Some(redis) = &state.redis else {
        return false;
    };
    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return false;
    };

    let key = format!("lock:acct:{account}");
    let ttl = conn.ttl::<_, i64>(key).await.ok().unwrap_or(-1);
    ttl > 0
}

async fn clear_failed_login_state(state: &AppState, account: &str) {
    let Some(redis) = &state.redis else {
        return;
    };
    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return;
    };
    let _ = conn.del::<_, i64>(format!("rl:acct:login:{account}")).await;
    let _ = conn.del::<_, i64>(format!("lock:acct:{account}")).await;
}

async fn register_failed_login_attempt(
    state: &AppState,
    account: &str,
    ip_address: Option<&str>,
    user_id: Option<Uuid>,
    reason: &str,
    request_id: Option<&str>,
) -> Result<(), Status> {
    record_security_event(
        state,
        "login_failed",
        user_id,
        request_id,
        serde_json::json!({
            "account": account,
            "reason": reason,
            "ip": ip_address.unwrap_or_default(),
        }),
    )
    .await?;

    let Some(redis) = &state.redis else {
        return Ok(());
    };
    let mut conn = match redis.get_multiplexed_async_connection().await {
        Ok(conn) => conn,
        Err(_) => return Ok(()),
    };

    let fail_key = format!("rl:acct:login:{account}");
    let failures = conn.incr::<_, _, i64>(&fail_key, 1).await.unwrap_or(1);
    if failures == 1 {
        let _ = conn.expire::<_, bool>(&fail_key, 15 * 60).await;
    }

    if failures >= 5 {
        let lock_key = format!("lock:acct:{account}");
        let _ = conn.set_ex::<_, _, ()>(lock_key, "1", 30 * 60).await;
        let _ = record_security_event(
            state,
            "account_locked",
            user_id,
            request_id,
            serde_json::json!({
                "account": account,
                "reason": "failed_login_threshold",
                "failures": failures,
            }),
        )
        .await;
    }

    Ok(())
}

async fn record_security_event(
    state: &AppState,
    event_type: &str,
    user_id: Option<Uuid>,
    request_id: Option<&str>,
    details: serde_json::Value,
) -> Result<(), Status> {
    sqlx::query(
        "INSERT INTO auth.security_events (
            event_type, user_id, session_id, request_id, details
         ) VALUES ($1, $2, NULL, $3, $4)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(request_id)
    .bind(details)
    .execute(&state.db)
    .await
    .map_err(|err| Status::internal(format!("security event insert failed: {err}")))?;

    Ok(())
}

#[derive(Debug, Clone)]
struct OAuthClientRecord {
    client_id: String,
    client_type: String,
    client_secret_hash: Option<String>,
    redirect_uris: Vec<String>,
    allowed_grant_types: Vec<String>,
    require_pkce_s256: bool,
    active: bool,
}

async fn load_oauth_client(
    db: &sqlx::PgPool,
    client_id: &str,
) -> Result<Option<OAuthClientRecord>, Status> {
    let row = sqlx::query(
        "SELECT client_id, client_type, client_secret_hash, redirect_uris, allowed_grant_types,
                require_pkce_s256, active
         FROM auth.oauth_clients
         WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(db)
    .await
    .map_err(|err| Status::internal(format!("db read oauth_client failed: {err}")))?;

    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(OAuthClientRecord {
        client_id: row.get("client_id"),
        client_type: row.get("client_type"),
        client_secret_hash: row.get("client_secret_hash"),
        redirect_uris: row.get("redirect_uris"),
        allowed_grant_types: row.get("allowed_grant_types"),
        require_pkce_s256: row.get("require_pkce_s256"),
        active: row.get("active"),
    }))
}

fn validate_oauth_client_auth(
    client: &OAuthClientRecord,
    presented_secret: &str,
) -> Result<(), Status> {
    if client.client_type == "public" {
        if !presented_secret.trim().is_empty() {
            return Err(Status::permission_denied(
                "public clients must not use client_secret",
            ));
        }
        return Ok(());
    }

    let stored = client
        .client_secret_hash
        .as_ref()
        .ok_or_else(|| Status::permission_denied("confidential client secret is not configured"))?;
    if presented_secret.trim().is_empty() {
        return Err(Status::unauthenticated(
            "confidential clients must provide client credentials",
        ));
    }

    let presented_hash = hash_token("oauth_client_secret", presented_secret.trim());
    if &presented_hash != stored {
        return Err(Status::unauthenticated("invalid client credentials"));
    }
    Ok(())
}

fn parse_scope_string(scope: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    scope
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert((*value).to_string()))
        .map(ToString::to_string)
        .collect()
}

fn oauth_pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

async fn mint_id_token(
    state: &AppState,
    user_id: &Uuid,
    scopes: &[String],
    nonce: Option<String>,
    client_id: &str,
) -> Result<String, Status> {
    let now = Utc::now();
    let exp = now + Duration::minutes(10);

    let mut payload = serde_json::json!({
        "sub": user_id.to_string(),
        "iss": state.issuer.clone(),
        "aud": client_id,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
    });

    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::Value::String(nonce);
    }

    if scopes
        .iter()
        .any(|scope| scope == "email" || scope == "profile" || scope == "openid")
    {
        if let Ok(Some(row)) =
            sqlx::query("SELECT email, email_verified FROM auth.users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&state.db)
                .await
        {
            let email: Option<String> = row.try_get("email").ok();
            let email_verified: bool = row.try_get("email_verified").unwrap_or(false);
            if let Some(email) = email {
                payload["email"] = serde_json::Value::String(email);
            }
            payload["email_verified"] = serde_json::Value::Bool(email_verified);
        }
    }

    let bytes = serde_json::to_vec(&payload)
        .map_err(|err| Status::internal(format!("id_token serialization failed: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn derive_social_subject(provider: &str, token: &str) -> String {
    hash_token(format!("social_subject:{provider}").as_str(), token)
}

async fn resolve_or_create_social_user(
    state: &AppState,
    provider: &str,
    provider_subject: &str,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    request_id: Option<&str>,
    traceparent: Option<&str>,
) -> Result<Uuid, Status> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| Status::internal(format!("db begin failed: {err}")))?;

    if let Some(row) = sqlx::query(
        "SELECT user_id
         FROM auth.oauth_provider_accounts
         WHERE provider = $1 AND provider_subject = $2",
    )
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| Status::internal(format!("db provider lookup failed: {err}")))?
    {
        let user_id: Uuid = row.get("user_id");
        tx.commit()
            .await
            .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;
        return Ok(user_id);
    }

    let normalized_email = email.and_then(|value| normalize_email(&value));
    let user_id = if let Some(email) = normalized_email.clone() {
        if let Some(row) = sqlx::query("SELECT id FROM auth.users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db user lookup failed: {err}")))?
        {
            row.get("id")
        } else {
            let user_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO auth.users (id, email, email_verified, email_verified_at, created_at, updated_at)
                 VALUES ($1, $2, TRUE, NOW(), NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(|err| Status::internal(format!("db social user insert failed: {err}")))?;
            user_id
        }
    } else {
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO auth.users (id, email_verified, created_at, updated_at)
             VALUES ($1, TRUE, NOW(), NOW())",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Status::internal(format!("db social user insert failed: {err}")))?;
        user_id
    };

    sqlx::query(
        "INSERT INTO auth.oauth_provider_accounts (
            id, user_id, provider, provider_subject, email, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (provider, provider_subject) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(provider)
    .bind(provider_subject)
    .bind(normalized_email.clone())
    .execute(&mut *tx)
    .await
    .map_err(|err| Status::internal(format!("db provider account insert failed: {err}")))?;

    tx.commit()
        .await
        .map_err(|err| Status::internal(format!("db commit failed: {err}")))?;

    let mut users_client = state.users_client.lock().await;
    let mut users_request = Request::new(contracts::wildon::users::v1::CreateUserRequest {
        user_id: user_id.to_string(),
        email: normalized_email.unwrap_or_else(|| format!("social+{}@wildon.local", user_id)),
        first_name: first_name.unwrap_or_default(),
        last_name: last_name.unwrap_or_default(),
        middle_name: String::new(),
    });
    let _ = inject_internal_metadata(&mut users_request, "auth-service", request_id, traceparent);
    users_client
        .create_user(users_request)
        .await
        .map_err(|err| Status::unavailable(format!("users-service error: {err}")))?;

    Ok(user_id)
}
