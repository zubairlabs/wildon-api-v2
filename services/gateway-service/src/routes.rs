use crate::{
    error::grpc_error_tuple,
    routing::host_router::{classify_host, resolve_surface},
    state::AppState,
    state::ValidatedClient,
};
use ::middleware::RequestId;
use auth::{claims::Claims, scope_catalog};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{
        header::{HeaderMap, CONTENT_TYPE, HOST},
        StatusCode,
    },
    response::Html,
    routing::{delete, get, patch, post, put},
    Router,
};
use base64::Engine as _;
use common::http::json::Json;
use config::grpc::inject_internal_metadata;
use contracts::wildon::{
    auth::v1::{
        BeginAuthenticatorEnrollmentRequest, ChangePasswordRequest,
        ConfirmAuthenticatorEnrollmentRequest, ConfirmEmailVerificationOtpRequest,
        DisableMfaFactorRequest, GetMfaStatusRequest, HealthRequest, JwksRequest,
        ListSessionsRequest, LoginWithPasswordRequest, LogoutAllSessionsRequest,
        LogoutSessionByIdRequest, LogoutSessionRequest, OAuthAuthorizeRequest,
        OAuthIntrospectRequest, OAuthRevokeRequest, OAuthTokenExchangeRequest,
        OidcDiscoveryRequest, RefreshTokenRequest, RegenerateBackupCodesRequest,
        RegisterUserRequest, RequestEmailVerificationOtpRequest, RequestPasswordResetOtpRequest,
        ResetPasswordRequest, SocialLoginAppleRequest, SocialLoginGoogleRequest, UserInfoRequest,
        VerifyLoginMfaRequest, VerifyPasswordResetOtpRequest,
    },
    billing::v1::{
        AddPaymentMethodRequest, CancelDeviceSubscriptionRequest, CreateDeviceSubscriptionRequest,
        CreateSetupIntentRequest, GetBillingSummaryRequest, GetDeviceSubscriptionRequest,
        GetInvoiceHtmlRequest, GetInvoiceV2Request, GetSubscriptionPlanRequest,
        IngestBillingWebhookRequest, ListDeviceSubscriptionsRequest, ListInvoicesV2Request,
        ListPaymentMethodsRequest, ListSubscriptionPlansRequest, RemovePaymentMethodRequest,
        ResumeDeviceSubscriptionRequest, RetryInvoicePaymentRequest,
        SetDefaultPaymentMethodRequest,
    },
    public::v1::{
        CreateDeviceRequest, CreateExportJobRequest, CreateMediaUploadTicketRequest,
        GetDashboardSummaryRequest, GetExportJobRequest, GetProfileRequest, ListDevicesRequest,
        UpdateProfileRequest,
    },
    users::v1::{
        CreateProfilePhotoDownloadUrlRequest, CreateProfilePhotoUploadTicketRequest,
        GetUserSettingsRequest, UpdateUserNotificationSettingsRequest, UpdateUserSettingsRequest,
        UserSettings,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use tonic::metadata::MetadataValue;
use tonic::Request as GrpcRequest;

const GATEWAY_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/gateway-v1.json");
const CONTROL_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/control-v1.json");
const CHAT_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/chat-v1.json");

fn apply_gateway_internal_metadata<T>(
    request: &mut GrpcRequest<T>,
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let traceparent = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok());
    inject_internal_metadata(
        request,
        "gateway-service",
        Some(request_id.0.as_str()),
        traceparent,
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid grpc metadata: {err}"),
        )
    })
}

fn apply_gateway_internal_metadata_with_auth<T>(
    request: &mut GrpcRequest<T>,
    request_id: &RequestId,
    headers: &HeaderMap,
    claims: Option<&Claims>,
) -> Result<(), (StatusCode, String)> {
    apply_gateway_internal_metadata(request, request_id, headers)?;
    if let Some(claims) = claims {
        let sub = MetadataValue::try_from(claims.sub.as_str()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid x-auth-sub metadata: {err}"),
            )
        })?;
        request.metadata_mut().insert("x-auth-sub", sub);

        let role = claims.roles.first().map(String::as_str).unwrap_or("user");
        let role = MetadataValue::try_from(role).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid x-auth-role metadata: {err}"),
            )
        })?;
        request.metadata_mut().insert("x-auth-role", role);

        if let Some(session_id) = claims.sid.as_deref().filter(|value| !value.is_empty()) {
            let session_id = MetadataValue::try_from(session_id).map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid x-auth-session-id metadata: {err}"),
                )
            })?;
            request
                .metadata_mut()
                .insert("x-auth-session-id", session_id);
        }

        let access_purpose = headers
            .get("x-access-purpose")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("treatment");
        let access_purpose = MetadataValue::try_from(access_purpose).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid x-access-purpose metadata: {err}"),
            )
        })?;
        request
            .metadata_mut()
            .insert("x-access-purpose", access_purpose);

        let perm_rev = MetadataValue::try_from(claims.perm_rev.to_string()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid x-auth-perm-rev metadata: {err}"),
            )
        })?;
        request.metadata_mut().insert("x-auth-perm-rev", perm_rev);
    }
    Ok(())
}

fn parse_basic_client_credentials(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let Some(value) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return (None, None);
    };
    let Some(raw) = value.strip_prefix("Basic ") else {
        return (None, None);
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw.as_bytes()) else {
        return (None, None);
    };
    let Ok(decoded) = String::from_utf8(bytes) else {
        return (None, None);
    };
    let Some((client_id, client_secret)) = decoded.split_once(':') else {
        return (None, None);
    };
    (Some(client_id.to_string()), Some(client_secret.to_string()))
}

fn empty_to_none(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[derive(Debug, Serialize)]
struct HealthPayload {
    status: &'static str,
    surface: String,
}

#[derive(Debug, Serialize)]
struct PublicPingPayload {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    remember_me: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct VerifyLoginMfaBody {
    challenge_token: String,
    otp_code: String,
    factor_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_at: i64,
    refresh_expires_at: i64,
    session_id: String,
    session_version: i32,
}

#[derive(Debug, Serialize)]
struct PasswordLoginResponse {
    mfa_required: bool,
    mfa_method: Option<String>,
    mfa_challenge_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_at: Option<i64>,
    refresh_expires_at: Option<i64>,
    session_id: Option<String>,
    session_version: Option<i32>,
}

#[derive(Debug, Serialize)]
struct LoginErrorResponse {
    error: LoginErrorBody,
}

#[derive(Debug, Serialize)]
struct LoginErrorBody {
    code: String,
    message: String,
    request_id: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    meta: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    #[serde(default)]
    middle_name: String,
}

#[derive(Debug, Serialize)]
struct GenericAcceptedResponse {
    accepted: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct VerifyEmailRequestBody {
    email: String,
}

#[derive(Debug, Deserialize)]
struct VerifyEmailConfirmBody {
    email: String,
    otp_code: String,
}

#[derive(Debug, Serialize)]
struct VerifyEmailConfirmResponse {
    verified: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RefreshRequestBody {
    refresh_token: String,
    device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutRequestBody {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct LogoutResponseBody {
    revoked: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct SessionSummaryBody {
    session_id: String,
    aud: String,
    realm: String,
    client_id: Option<String>,
    device_id: Option<String>,
    remember_me: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    created_at: i64,
    last_activity_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    revoked_reason: Option<String>,
    mfa_level: i32,
}

#[derive(Debug, Serialize)]
struct SessionListResponseBody {
    sessions: Vec<SessionSummaryBody>,
    page: CursorPageResponse,
}

#[derive(Debug, Deserialize)]
struct SessionLogoutRequestBody {
    session_id: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutAllRequestBody {
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct LogoutAllResponseBody {
    session_version: i32,
    revoked_sessions: i64,
}

#[derive(Debug, Deserialize)]
struct ForgotPasswordRequestBody {
    email: String,
}

#[derive(Debug, Deserialize)]
struct ForgotPasswordVerifyBody {
    email: String,
    otp_code: String,
}

#[derive(Debug, Serialize)]
struct ForgotPasswordVerifyResponse {
    accepted: bool,
    reset_token: Option<String>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordBody {
    email: String,
    reset_token: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
struct ResetPasswordResponseBody {
    reset: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
struct ChangePasswordResponseBody {
    changed: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct BeginAuthenticatorEnrollmentBody {
    issuer: Option<String>,
}

#[derive(Debug, Serialize)]
struct BeginAuthenticatorEnrollmentResponseBody {
    factor_type: String,
    factor_id: String,
    issuer: String,
    account_name: String,
    secret: String,
    otpauth_uri: String,
    qr_svg_data_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfirmAuthenticatorEnrollmentBody {
    otp_code: String,
}

#[derive(Debug, Serialize)]
struct ConfirmAuthenticatorEnrollmentResponseBody {
    enabled: bool,
    message: String,
    backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DisableMfaFactorBody {
    factor_type: Option<String>,
    otp_code: String,
}

#[derive(Debug, Serialize)]
struct DisableMfaFactorResponseBody {
    disabled: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RegenerateBackupCodesBody {
    otp_code: String,
}

#[derive(Debug, Serialize)]
struct RegenerateBackupCodesResponseBody {
    regenerated: bool,
    message: String,
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MfaFactorSummaryBody {
    factor_type: String,
    status: String,
    enabled_at: Option<i64>,
    masked_destination: Option<String>,
    backup_codes_remaining: i32,
}

#[derive(Debug, Serialize)]
struct MfaStatusResponseBody {
    mfa_enabled: bool,
    factors: Vec<MfaFactorSummaryBody>,
}

#[derive(Debug, Deserialize)]
struct OAuthAuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthAuthorizeApiResponse {
    code: String,
    state: String,
    redirect_uri: String,
    expires_at: i64,
    redirect_to: String,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenRequestBody {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthTokenApiResponse {
    access_token: String,
    token_type: String,
    expires_at: i64,
    refresh_token: Option<String>,
    session_id: Option<String>,
    refresh_expires_at: Option<i64>,
    session_version: Option<i32>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthRevokeBody {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthRevokeApiResponse {
    revoked: bool,
}

#[derive(Debug, Deserialize)]
struct OAuthIntrospectBody {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthIntrospectApiResponse {
    active: bool,
    sub: Option<String>,
    client_id: Option<String>,
    aud: Option<String>,
    realm: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    scope: Option<String>,
    token_type: String,
}

#[derive(Debug, Serialize)]
struct OidcDiscoveryApiResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: String,
    introspection_endpoint: String,
    grant_types_supported: Vec<String>,
    response_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScopeManifestResponse {
    issuer: String,
    scopes: Vec<ScopeManifestScope>,
}

#[derive(Debug, Serialize)]
struct ScopeManifestScope {
    name: String,
    description: String,
    first_party_default: bool,
    third_party_required: bool,
}

#[derive(Debug, Serialize)]
struct JwksApiResponse {
    keys: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct OAuthUserInfoApiResponse {
    sub: String,
    email: String,
    email_verified: bool,
    name: String,
    client_id: String,
    aud: String,
    realm: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SocialLoginBody {
    id_token: String,
    nonce: Option<String>,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    remember_me: Option<bool>,
}


#[derive(Debug, Serialize)]
struct ProfileResponse {
    user_id: String,
    email: String,
    first_name: String,
    last_name: String,
    middle_name: String,
    preferred_name: String,
    display_name: String,
    full_name: String,
    timezone: String,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct DashboardSummaryResponse {
    user_id: String,
    devices_count: u32,
    trips_count: u32,
    media_count: u32,
    subscription_plan: String,
    subscription_status: String,
    ai_usage_total: u64,
    generated_at: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateProfileBody {
    first_name: Option<String>,
    last_name: Option<String>,
    middle_name: Option<String>,
    preferred_name: Option<String>,
    display_name: Option<String>,
    timezone: Option<String>,
    feature_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdateProfileResponse {
    user_id: String,
    first_name: String,
    last_name: String,
    middle_name: String,
    preferred_name: String,
    display_name: String,
    full_name: String,
    timezone: String,
    event_published: bool,
    event_duplicate: bool,
}

#[derive(Debug, Serialize)]
struct UserSettingsProfileResponse {
    user_id: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    middle_name: Option<String>,
    preferred_name: Option<String>,
    display_name: Option<String>,
    full_name: Option<String>,
    username: Option<String>,
    phone: Option<String>,
    profile_photo_object_key: Option<String>,
    bio: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserSettingsLocaleTimeResponse {
    language: String,
    timezone: String,
    date_format: String,
    clock_format: String,
    distance_unit: String,
    temperature_unit: String,
}

#[derive(Debug, Serialize)]
struct UserSettingsNotificationsResponse {
    push_new_photo_captured: bool,
    push_species_detected: bool,
    push_device_offline: bool,
    push_low_battery: bool,
    push_storage_full: bool,
    push_subscription_renewal_reminder: bool,
    push_trip_activity_updates: bool,
    email_new_photo_captured: bool,
    email_species_detected: bool,
    email_device_offline: bool,
    email_low_battery: bool,
    email_storage_full: bool,
    email_subscription_renewal_reminder: bool,
    email_trip_activity_updates: bool,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct UserSettingsResponse {
    profile: UserSettingsProfileResponse,
    locale_time: UserSettingsLocaleTimeResponse,
    notifications: UserSettingsNotificationsResponse,
    settings_version: i32,
    settings_updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateUserSettingsBody {
    first_name: Option<String>,
    last_name: Option<String>,
    middle_name: Option<String>,
    preferred_name: Option<String>,
    display_name: Option<String>,
    full_name: Option<String>,
    username: Option<String>,
    phone: Option<String>,
    profile_photo_object_key: Option<String>,
    bio: Option<String>,
    language: Option<String>,
    timezone: Option<String>,
    date_format: Option<String>,
    clock_format: Option<String>,
    distance_unit: Option<String>,
    temperature_unit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserNotificationSettingsBody {
    push_new_photo_captured: Option<bool>,
    push_species_detected: Option<bool>,
    push_device_offline: Option<bool>,
    push_low_battery: Option<bool>,
    push_storage_full: Option<bool>,
    push_subscription_renewal_reminder: Option<bool>,
    push_trip_activity_updates: Option<bool>,
    email_new_photo_captured: Option<bool>,
    email_species_detected: Option<bool>,
    email_device_offline: Option<bool>,
    email_low_battery: Option<bool>,
    email_storage_full: Option<bool>,
    email_subscription_renewal_reminder: Option<bool>,
    email_trip_activity_updates: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CreateProfilePhotoUploadTicketBody {
    content_type: String,
    content_length: u64,
}

#[derive(Debug, Serialize)]
struct CreateProfilePhotoUploadTicketResponseBody {
    object_key: String,
    upload_url: String,
    method: String,
    expires_at: i64,
    required_headers: std::collections::BTreeMap<String, String>,
    content_type: String,
    max_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct GetProfilePhotoDownloadUrlQuery {
    object_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct GetProfilePhotoDownloadUrlResponseBody {
    object_key: String,
    download_url: String,
    method: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct CursorListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct CursorPageResponse {
    limit: u32,
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct CreateDeviceBody {
    platform: String,
    nickname: String,
}

#[derive(Debug, Serialize)]
struct DeviceResponse {
    device_id: String,
    platform: String,
    nickname: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct DevicesListResponse {
    devices: Vec<DeviceResponse>,
    page: CursorPageResponse,
}

#[derive(Debug, Deserialize)]
struct CreateMediaUploadTicketBody {
    filename: String,
    content_type: String,
    content_length: u64,
}

#[derive(Debug, Serialize)]
struct MediaUploadTicketResponse {
    object_key: String,
    upload_url: String,
    method: String,
    expires_at: i64,
    required_headers: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct CreateExportBody {
    export_kind: String,
    format: String,
}

#[derive(Debug, Serialize)]
struct ExportJobResponse {
    job_id: String,
    status: String,
    artifact_key: String,
    download_url: Option<String>,
    download_expires_at: Option<i64>,
    duplicate: bool,
    error_message: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/openapi/gateway-v1.json", get(openapi_gateway))
        .route("/openapi/control-v1.json", get(openapi_control))
        .route("/openapi/chat-v1.json", get(openapi_chat))
        .route("/docs/openapi/control-v1.json", get(openapi_control))
        .route("/health", get(health))
        .route("/v1/system/info", get(system_info))
        .route("/v1/public/ping", get(public_ping))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/.well-known/scopes", get(scope_manifest))
        .route("/oauth2/jwks.json", get(oauth_jwks))
        .route("/oauth2/authorize", get(oauth_authorize))
        .route("/oauth2/token", post(oauth_token))
        .route("/oauth2/revoke", post(oauth_revoke))
        .route("/oauth2/introspect", post(oauth_introspect))
        .route("/oauth2/userinfo", get(oauth_userinfo))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/verify-email/request", post(request_verify_email))
        .route("/v1/auth/verify-email/confirm", post(confirm_verify_email))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/login/mfa/verify", post(verify_login_mfa))
        .route("/v1/auth/social/google", post(social_login_google))
        .route("/v1/auth/social/apple", post(social_login_apple))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/sessions", get(list_sessions))
        .route("/v1/auth/sessions/logout", post(logout_session_by_id))
        .route("/v1/auth/sessions/logout-all", post(logout_all_sessions))
        .route("/v1/auth/mfa/status", get(get_mfa_status))
        .route(
            "/v1/auth/mfa/authenticator/setup",
            post(begin_authenticator_enrollment),
        )
        .route(
            "/v1/auth/mfa/authenticator/confirm",
            post(confirm_authenticator_enrollment),
        )
        .route(
            "/v1/auth/mfa/authenticator/disable",
            post(disable_mfa_factor),
        )
        .route(
            "/v1/auth/mfa/backup-codes/regenerate",
            post(regenerate_backup_codes),
        )
        .route(
            "/v1/auth/password/forgot/request",
            post(request_forgot_password),
        )
        .route("/v1/auth/forgot-password", post(request_forgot_password))
        .route(
            "/v1/auth/password/forgot/verify",
            post(verify_forgot_password),
        )
        .route("/v1/auth/password/reset", post(reset_password))
        .route("/v1/auth/password/change", post(change_password))
        .route("/v1/dashboard/summary", get(get_dashboard_summary))
        .route("/v1/users/me", get(get_me).patch(update_me))
        .route(
            "/v1/users/me/settings",
            get(get_user_settings).patch(update_user_settings),
        )
        .route(
            "/v1/users/me/settings/notifications",
            patch(update_user_notification_settings),
        )
        .route(
            "/v1/users/me/settings/profile-photo/upload-ticket",
            post(create_profile_photo_upload_ticket),
        )
        .route(
            "/v1/users/me/settings/profile-photo/download-url",
            get(get_profile_photo_download_url),
        )
        .route("/v1/devices", post(create_device).get(list_devices))
        .route("/v1/media/upload-ticket", post(create_media_upload_ticket))
        .route("/v1/exports", post(create_export_job))
        .route("/v1/exports/:job_id", get(get_export_job))
        .route("/v1/proxy/auth-health", get(proxy_auth_health))
        // Billing — Payment Methods
        .route(
            "/v1/billing/payment-methods",
            get(billing_list_payment_methods).post(billing_add_payment_method),
        )
        .route(
            "/v1/billing/payment-methods/setup-intent",
            post(billing_create_setup_intent),
        )
        .route(
            "/v1/billing/payment-methods/:id/default",
            put(billing_set_default_payment_method),
        )
        .route(
            "/v1/billing/payment-methods/:id",
            delete(billing_remove_payment_method),
        )
        // Billing — Plans
        .route("/v1/billing/plans", get(billing_list_plans))
        .route("/v1/billing/plans/:id", get(billing_get_plan))
        // Billing — Device Subscriptions
        .route("/v1/billing/subscriptions", get(billing_list_subscriptions))
        .route(
            "/v1/billing/devices/:device_id/subscription",
            get(billing_get_device_subscription).post(billing_create_device_subscription),
        )
        .route(
            "/v1/billing/subscriptions/:id/cancel",
            patch(billing_cancel_subscription),
        )
        .route(
            "/v1/billing/subscriptions/:id/resume",
            patch(billing_resume_subscription),
        )
        // Billing — Invoices
        .route("/v1/billing/invoices", get(billing_list_invoices))
        .route("/v1/billing/invoices/:id", get(billing_get_invoice))
        .route(
            "/v1/billing/invoices/:id/html",
            get(billing_get_invoice_html),
        )
        .route(
            "/v1/billing/invoices/:id/retry",
            post(billing_retry_invoice),
        )
        // Billing — Summary
        .route("/v1/billing/summary", get(billing_get_summary))
        // Billing — Stripe Webhook
        .route("/v1/billing/stripe/webhook", post(billing_stripe_webhook))
        .with_state(state)
}

async fn swagger_ui() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Wildon API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        urls: [
          { url: "/openapi/gateway-v1.json",  name: "Gateway API (public + platform surfaces)" },
          { url: "/openapi/control-v1.json",  name: "Control API (internal admin surface)" },
          { url: "/openapi/chat-v1.json",     name: "Chat API (live support chat)" }
        ],
        "urls.primaryName": "Gateway API (public + platform surfaces)",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    </script>
  </body>
</html>"##,
    )
}

async fn openapi_gateway() -> impl axum::response::IntoResponse {
    (
        [(CONTENT_TYPE, "application/json; charset=utf-8")],
        GATEWAY_OPENAPI_JSON,
    )
}

async fn openapi_control() -> impl axum::response::IntoResponse {
    (
        [(CONTENT_TYPE, "application/json; charset=utf-8")],
        CONTROL_OPENAPI_JSON,
    )
}

async fn openapi_chat() -> impl axum::response::IntoResponse {
    (
        [(CONTENT_TYPE, "application/json; charset=utf-8")],
        CHAT_OPENAPI_JSON,
    )
}

fn to_optional_string(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn normalize_list_limit(limit: Option<u32>) -> u32 {
    match limit.unwrap_or(50) {
        0 => 50,
        value => value.min(200),
    }
}

fn map_user_settings_payload(settings: UserSettings) -> UserSettingsResponse {
    let notifications = settings.notifications.unwrap_or_default();
    UserSettingsResponse {
        profile: UserSettingsProfileResponse {
            user_id: settings.user_id,
            email: settings.email,
            first_name: to_optional_string(settings.first_name),
            last_name: to_optional_string(settings.last_name),
            middle_name: to_optional_string(settings.middle_name),
            preferred_name: to_optional_string(settings.preferred_name),
            display_name: to_optional_string(settings.display_name),
            full_name: to_optional_string(settings.full_name),
            username: to_optional_string(settings.username),
            phone: to_optional_string(settings.phone),
            profile_photo_object_key: to_optional_string(settings.profile_photo_object_key),
            bio: to_optional_string(settings.bio),
        },
        locale_time: UserSettingsLocaleTimeResponse {
            language: settings.language,
            timezone: settings.timezone,
            date_format: settings.date_format,
            clock_format: settings.clock_format,
            distance_unit: settings.distance_unit,
            temperature_unit: settings.temperature_unit,
        },
        notifications: UserSettingsNotificationsResponse {
            push_new_photo_captured: notifications.push_new_photo_captured,
            push_species_detected: notifications.push_species_detected,
            push_device_offline: notifications.push_device_offline,
            push_low_battery: notifications.push_low_battery,
            push_storage_full: notifications.push_storage_full,
            push_subscription_renewal_reminder: notifications.push_subscription_renewal_reminder,
            push_trip_activity_updates: notifications.push_trip_activity_updates,
            email_new_photo_captured: notifications.email_new_photo_captured,
            email_species_detected: notifications.email_species_detected,
            email_device_offline: notifications.email_device_offline,
            email_low_battery: notifications.email_low_battery,
            email_storage_full: notifications.email_storage_full,
            email_subscription_renewal_reminder: notifications.email_subscription_renewal_reminder,
            email_trip_activity_updates: notifications.email_trip_activity_updates,
            updated_at: notifications.updated_at,
        },
        settings_version: settings.settings_version,
        settings_updated_at: settings.settings_updated_at,
    }
}

async fn health(headers: HeaderMap) -> Json<HealthPayload> {
    let host = headers.get(HOST).and_then(|v| v.to_str().ok());
    let surface = classify_host(host).as_str().to_string();
    Json(HealthPayload {
        status: "ok",
        surface,
    })
}

async fn public_ping() -> Json<PublicPingPayload> {
    Json(PublicPingPayload { status: "ok" })
}

// ── System info ────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
struct SystemInfoService {
    name: String,
    url: String,
    port: Option<u16>,
    status: String,          // "UP" | "DOWN" | "UNKNOWN"
    reason: Option<String>,  // error detail when DOWN
}

#[derive(Debug, serde::Serialize)]
struct SystemInfoServer {
    cpu_cores: u32,
    cpu_usage_percent: f64,
    ram_gb: u64,
    ram_usage_percent: f64,
    storage_gb: u64,
    storage_usage_percent: f64,
    uptime_days: u64,
    api_latency_ms: u64,
}

#[derive(Debug, serde::Serialize)]
struct SystemInfoResponse {
    server: SystemInfoServer,
    services: Vec<SystemInfoService>,
    api_calls: crate::state::ApiCallSnapshot,
}

async fn system_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SystemInfoResponse>, (StatusCode, &'static str)> {
    let expected_pk = env::var("REGION_PUBLIC_KEY").unwrap_or_default();
    let expected_sk = env::var("REGION_SECRET_KEY").unwrap_or_default();
    if expected_pk.is_empty() || expected_sk.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "region credentials not configured"));
    }
    let provided_pk = headers.get("x-public-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let provided_sk = headers.get("x-secret-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    if provided_pk != expected_pk || provided_sk != expected_sk {
        return Err((StatusCode::UNAUTHORIZED, "invalid region credentials"));
    }

    let cpu_cores = read_cpu_cores().await.unwrap_or(1);
    let (ram_gb, ram_usage_percent) = read_ram_stats().await.unwrap_or((0, 0.0));
    let uptime_days = read_uptime_days().await.unwrap_or(0);
    let cpu_usage_percent = read_cpu_usage(cpu_cores).await.unwrap_or(0.0);
    let (storage_gb, storage_usage_percent) = read_storage_stats().await.unwrap_or((0, 0.0));

    let server = SystemInfoServer {
        cpu_cores,
        cpu_usage_percent,
        ram_gb,
        ram_usage_percent,
        storage_gb,
        storage_usage_percent,
        uptime_days,
        api_latency_ms: 0,
    };

    let services = build_services_list(&state).await;
    let api_calls = state.api_metrics.snapshot().await;
    Ok(Json(SystemInfoResponse { server, services, api_calls }))
}

async fn read_cpu_cores() -> Option<u32> {
    let content = tokio::fs::read_to_string("/proc/cpuinfo").await.ok()?;
    let count = content.lines().filter(|l| l.starts_with("processor")).count();
    Some(count.max(1) as u32)
}

async fn read_ram_stats() -> Option<(u64, f64)> {
    let content = tokio::fs::read_to_string("/proc/meminfo").await.ok()?;
    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line.split_whitespace().nth(1)?.parse().ok()?;
        } else if line.starts_with("MemAvailable:") {
            available_kb = line.split_whitespace().nth(1)?.parse().ok()?;
        }
    }
    if total_kb == 0 {
        return None;
    }
    let ram_gb = (total_kb / (1024 * 1024)).max(1);
    let used_kb = total_kb.saturating_sub(available_kb);
    let pct = (used_kb as f64 / total_kb as f64 * 1000.0).round() / 10.0;
    Some((ram_gb, pct))
}

async fn read_uptime_days() -> Option<u64> {
    let content = tokio::fs::read_to_string("/proc/uptime").await.ok()?;
    let secs: f64 = content.split_whitespace().next()?.parse().ok()?;
    Some((secs / 86400.0) as u64)
}

async fn read_cpu_usage(cpu_cores: u32) -> Option<f64> {
    let content = tokio::fs::read_to_string("/proc/loadavg").await.ok()?;
    let one_min: f64 = content.split_whitespace().next()?.parse().ok()?;
    let pct = one_min / cpu_cores.max(1) as f64 * 100.0;
    Some((pct.min(100.0) * 10.0).round() / 10.0)
}

async fn read_storage_stats() -> Option<(u64, f64)> {
    let output = tokio::process::Command::new("df")
        .args(["-B1", "/"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let out = String::from_utf8(output.stdout).ok()?;
    let line = out.lines().nth(1)?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    let total_bytes: u64 = parts.get(1)?.parse().ok()?;
    let used_bytes: u64 = parts.get(2)?.parse().ok()?;
    let storage_gb = total_bytes / (1024 * 1024 * 1024);
    let pct = if total_bytes > 0 {
        (used_bytes as f64 / total_bytes as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };
    Some((storage_gb, pct))
}

fn extract_port_from_url(url: &str) -> Option<u16> {
    url.rsplit(':').next()?.parse().ok()
}

async fn build_services_list(state: &AppState) -> Vec<SystemInfoService> {
    let service_map = &state.service_map;
    let health = state.service_health.lock().await;

    let svc_status = |name: &str| -> (String, Option<String>) {
        health
            .get(name)
            .map(|s| (s.status.clone(), s.reason.clone()))
            .unwrap_or_else(|| ("UNKNOWN".to_string(), None))
    };

    let gateway_url = env::var("GATEWAY_BASE_URL").unwrap_or_default();
    // Gateway health is self — it's serving this request, so it's UP
    let mut services = vec![SystemInfoService {
        name: "gateway".to_string(),
        url: gateway_url,
        port: Some(8080),
        status: "UP".to_string(),
        reason: None,
    }];

    let always_present = [
        ("auth-service", service_map.auth_grpc.as_str()),
        ("public-service", service_map.public_grpc.as_str()),
        ("users-service", service_map.users_grpc.as_str()),
        ("core-service", service_map.core_grpc.as_str()),
        ("billing-service", service_map.billing_grpc.as_str()),
        ("api-clients-service", service_map.api_clients_grpc.as_str()),
    ];
    for (name, endpoint) in always_present {
        let port = extract_port_from_url(endpoint);
        let (status, reason) = svc_status(name);
        services.push(SystemInfoService {
            name: name.to_string(),
            url: endpoint.to_string(),
            port,
            status,
            reason,
        });
    }

    let optional = [
        ("control-service", "CONTROL_HTTP_ENDPOINT"),
        ("logs-service", "LOGS_GRPC_ENDPOINT"),
        ("storage-service", "STORAGE_GRPC_ENDPOINT"),
        ("export-service", "EXPORT_GRPC_ENDPOINT"),
        ("platform-service", "PLATFORM_HTTP_ENDPOINT"),
        ("device-gateway", "DEVICE_GATEWAY_ENDPOINT"),
    ];
    for (name, var) in optional {
        if let Ok(url) = env::var(var) {
            if !url.is_empty() {
                let port = extract_port_from_url(&url);
                let (status, reason) = svc_status(name);
                services.push(SystemInfoService {
                    name: name.to_string(),
                    url,
                    port,
                    status,
                    reason,
                });
            }
        }
    }

    services
}

async fn scope_manifest() -> Json<ScopeManifestResponse> {
    let scopes = scope_catalog::scopes()
        .iter()
        .map(|scope| ScopeManifestScope {
            name: scope.name.to_string(),
            description: scope.description.to_string(),
            first_party_default: scope.first_party_default,
            third_party_required: scope.third_party_required,
        })
        .collect();

    Json(ScopeManifestResponse {
        issuer: "gateway-service".to_string(),
        scopes,
    })
}

async fn oidc_discovery(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<OidcDiscoveryApiResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(OidcDiscoveryRequest {});
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .get_oidc_discovery(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(OidcDiscoveryApiResponse {
        issuer: response.issuer,
        authorization_endpoint: response.authorization_endpoint,
        token_endpoint: response.token_endpoint,
        userinfo_endpoint: response.userinfo_endpoint,
        jwks_uri: response.jwks_uri,
        revocation_endpoint: response.revocation_endpoint,
        introspection_endpoint: response.introspection_endpoint,
        grant_types_supported: response.grant_types_supported,
        response_types_supported: response.response_types_supported,
        code_challenge_methods_supported: response.code_challenge_methods_supported,
        token_endpoint_auth_methods_supported: response.token_endpoint_auth_methods_supported,
    }))
}

async fn oauth_jwks(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<JwksApiResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(JwksRequest {});
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .get_jwks(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let keys = response
        .keys
        .into_iter()
        .map(|key| {
            serde_json::json!({
                "kty": key.kty,
                "use": key.r#use,
                "alg": key.alg,
                "kid": key.kid,
                "k": key.k
            })
        })
        .collect();

    Ok(Json(JwksApiResponse { keys }))
}

async fn oauth_authorize(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<Json<OAuthAuthorizeApiResponse>, (StatusCode, String)> {
    let surface = classify_host(headers.get(HOST).and_then(|v| v.to_str().ok()));
    let client_id = query.client_id.unwrap_or_default();
    if client_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "client_id is required".to_string()));
    }

    let mut grpc_request = GrpcRequest::new(OAuthAuthorizeRequest {
        response_type: query.response_type.unwrap_or_else(|| "code".to_string()),
        client_id,
        redirect_uri: query.redirect_uri.unwrap_or_default(),
        scope: query.scope.unwrap_or_default(),
        state: query.state.unwrap_or_default(),
        nonce: query.nonce.unwrap_or_default(),
        code_challenge: query.code_challenge.unwrap_or_default(),
        code_challenge_method: query.code_challenge_method.unwrap_or_default(),
        aud: surface.expected_audience().to_string(),
        realm: surface.expected_realm().to_string(),
        sub: claims.sub,
        device_id: headers
            .get("x-device-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        device_fingerprint_hash: headers
            .get("x-device-fingerprint")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        user_agent: headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        ip_address: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .unwrap_or_default()
            .trim()
            .to_string(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .authorize_oauth(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let separator = if response.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let redirect_to = format!(
        "{}{}code={}&state={}",
        response.redirect_uri, separator, response.code, response.state
    );

    Ok(Json(OAuthAuthorizeApiResponse {
        code: response.code,
        state: response.state,
        redirect_uri: response.redirect_uri,
        expires_at: response.expires_at,
        redirect_to,
    }))
}

async fn oauth_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<OAuthTokenRequestBody>,
) -> Result<Json<OAuthTokenApiResponse>, (StatusCode, String)> {
    let (basic_client_id, basic_client_secret) = parse_basic_client_credentials(&headers);
    let mut grpc_request = GrpcRequest::new(OAuthTokenExchangeRequest {
        grant_type: payload.grant_type,
        code: payload.code.unwrap_or_default(),
        redirect_uri: payload.redirect_uri.unwrap_or_default(),
        code_verifier: payload.code_verifier.unwrap_or_default(),
        refresh_token: payload.refresh_token.unwrap_or_default(),
        client_id: payload.client_id.or(basic_client_id).unwrap_or_default(),
        client_secret: payload
            .client_secret
            .or(basic_client_secret)
            .unwrap_or_default(),
        scope: payload.scope.unwrap_or_default(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .exchange_oauth_token(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(OAuthTokenApiResponse {
        access_token: response.access_token,
        token_type: response.token_type,
        expires_at: response.expires_at,
        refresh_token: if response.refresh_token.is_empty() {
            None
        } else {
            Some(response.refresh_token)
        },
        session_id: if response.session_id.is_empty() {
            None
        } else {
            Some(response.session_id)
        },
        refresh_expires_at: if response.refresh_expires_at > 0 {
            Some(response.refresh_expires_at)
        } else {
            None
        },
        session_version: if response.session_version > 0 {
            Some(response.session_version)
        } else {
            None
        },
        id_token: if response.id_token.is_empty() {
            None
        } else {
            Some(response.id_token)
        },
        scope: if response.scope.is_empty() {
            None
        } else {
            Some(response.scope)
        },
    }))
}

async fn oauth_revoke(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<OAuthRevokeBody>,
) -> Result<Json<OAuthRevokeApiResponse>, (StatusCode, String)> {
    let (basic_client_id, basic_client_secret) = parse_basic_client_credentials(&headers);
    let mut grpc_request = GrpcRequest::new(OAuthRevokeRequest {
        token: payload.token,
        token_type_hint: payload.token_type_hint.unwrap_or_default(),
        client_id: payload.client_id.or(basic_client_id).unwrap_or_default(),
        client_secret: payload
            .client_secret
            .or(basic_client_secret)
            .unwrap_or_default(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .revoke_oauth_token(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(OAuthRevokeApiResponse {
        revoked: response.revoked,
    }))
}

async fn oauth_introspect(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<OAuthIntrospectBody>,
) -> Result<Json<OAuthIntrospectApiResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(OAuthIntrospectRequest {
        token: payload.token,
        token_type_hint: payload.token_type_hint.unwrap_or_default(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .introspect_oauth_token(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(OAuthIntrospectApiResponse {
        active: response.active,
        sub: if response.sub.is_empty() {
            None
        } else {
            Some(response.sub)
        },
        client_id: if response.client_id.is_empty() {
            None
        } else {
            Some(response.client_id)
        },
        aud: if response.aud.is_empty() {
            None
        } else {
            Some(response.aud)
        },
        realm: if response.realm.is_empty() {
            None
        } else {
            Some(response.realm)
        },
        exp: if response.exp > 0 {
            Some(response.exp)
        } else {
            None
        },
        iat: if response.iat > 0 {
            Some(response.iat)
        } else {
            None
        },
        scope: if response.scope.is_empty() {
            None
        } else {
            Some(response.scope)
        },
        token_type: response.token_type,
    }))
}

async fn oauth_userinfo(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<OAuthUserInfoApiResponse>, (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".to_string()))?
        .to_string();

    let mut grpc_request = GrpcRequest::new(UserInfoRequest {
        access_token: token,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .get_user_info(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(OAuthUserInfoApiResponse {
        sub: response.sub,
        email: response.email,
        email_verified: response.email_verified,
        name: response.name,
        client_id: response.client_id,
        aud: response.aud,
        realm: response.realm,
        scopes: response.scopes,
    }))
}

async fn social_login_google(
    State(state): State<AppState>,
    Extension(validated_client): Extension<ValidatedClient>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<SocialLoginBody>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let surface = resolve_surface(
        headers.get(HOST).and_then(|v| v.to_str().ok()),
        Some(validated_client.policy.surface.as_str()),
    );
    let mut grpc_request = GrpcRequest::new(SocialLoginGoogleRequest {
        id_token: payload.id_token,
        nonce: payload.nonce.unwrap_or_default(),
        aud: surface.expected_audience().to_string(),
        realm: surface.expected_realm().to_string(),
        client_id: validated_client.client_id,
        email: payload.email.unwrap_or_default(),
        first_name: payload.first_name.unwrap_or_default(),
        last_name: payload.last_name.unwrap_or_default(),
        device_id: headers
            .get("x-device-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        device_fingerprint_hash: headers
            .get("x-device-fingerprint")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        user_agent: headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        ip_address: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .unwrap_or_default()
            .trim()
            .to_string(),
        remember_me: payload.remember_me,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .social_login_google(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LoginResponse {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        token_type: response.token_type,
        expires_at: response.expires_at,
        refresh_expires_at: response.refresh_expires_at,
        session_id: response.session_id,
        session_version: response.session_version,
    }))
}

async fn social_login_apple(
    State(state): State<AppState>,
    Extension(validated_client): Extension<ValidatedClient>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<SocialLoginBody>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let surface = resolve_surface(
        headers.get(HOST).and_then(|v| v.to_str().ok()),
        Some(validated_client.policy.surface.as_str()),
    );
    let mut grpc_request = GrpcRequest::new(SocialLoginAppleRequest {
        id_token: payload.id_token,
        nonce: payload.nonce.unwrap_or_default(),
        aud: surface.expected_audience().to_string(),
        realm: surface.expected_realm().to_string(),
        client_id: validated_client.client_id,
        email: payload.email.unwrap_or_default(),
        first_name: payload.first_name.unwrap_or_default(),
        last_name: payload.last_name.unwrap_or_default(),
        device_id: headers
            .get("x-device-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        device_fingerprint_hash: headers
            .get("x-device-fingerprint")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        user_agent: headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        ip_address: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .unwrap_or_default()
            .trim()
            .to_string(),
        remember_me: payload.remember_me,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .social_login_apple(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LoginResponse {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        token_type: response.token_type,
        expires_at: response.expires_at,
        refresh_expires_at: response.refresh_expires_at,
        session_id: response.session_id,
        session_version: response.session_version,
    }))
}

async fn login(
    State(state): State<AppState>,
    Extension(validated_client): Extension<ValidatedClient>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<PasswordLoginResponse>, (StatusCode, String)> {
    let surface = resolve_surface(
        headers.get(HOST).and_then(|v| v.to_str().ok()),
        Some(validated_client.policy.surface.as_str()),
    );
    let device_id = headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let device_fingerprint_hash = headers
        .get("x-device-fingerprint")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .unwrap_or_default()
        .trim()
        .to_string();

    let mut grpc_request = GrpcRequest::new(LoginWithPasswordRequest {
        email: payload.email,
        password: payload.password,
        aud: surface.expected_audience().to_string(),
        realm: surface.expected_realm().to_string(),
        device_id,
        device_fingerprint_hash,
        user_agent,
        ip_address,
        mfa_level: 0,
        client_id: validated_client.client_id,
        remember_me: payload.remember_me,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .login_with_password(grpc_request)
        .await
        .map_err(|err| login_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let mfa_required = response.mfa_required;
    if mfa_required {
        return Ok(Json(PasswordLoginResponse {
            mfa_required: true,
            mfa_method: empty_to_none(response.mfa_method),
            mfa_challenge_token: empty_to_none(response.mfa_challenge_token),
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_at: None,
            refresh_expires_at: None,
            session_id: None,
            session_version: None,
        }));
    }

    Ok(Json(PasswordLoginResponse {
        mfa_required: false,
        mfa_method: None,
        mfa_challenge_token: None,
        access_token: empty_to_none(response.access_token),
        refresh_token: empty_to_none(response.refresh_token),
        token_type: empty_to_none(response.token_type),
        expires_at: Some(response.expires_at),
        refresh_expires_at: Some(response.refresh_expires_at),
        session_id: empty_to_none(response.session_id),
        session_version: Some(response.session_version),
    }))
}

fn login_error_tuple(err: tonic::Status, request_id: &str) -> (StatusCode, String) {
    let message = err.message().trim();
    let mut meta = BTreeMap::new();

    let user_message = match message {
        "email not found" => {
            meta.insert("email".to_string(), "No account exists for this email.".to_string());
            "We couldn't find an account with that email address."
        }
        "password is incorrect" => {
            meta.insert(
                "password".to_string(),
                "The password you entered is incorrect.".to_string(),
            );
            "The password you entered is incorrect."
        }
        "email is not verified" => {
            meta.insert(
                "email".to_string(),
                "This email address has not been verified yet.".to_string(),
            );
            "This email address has not been verified yet."
        }
        "account temporarily locked due to repeated failures" => {
            meta.insert(
                "password".to_string(),
                "Too many failed attempts. Try again in a few minutes.".to_string(),
            );
            "Too many failed login attempts. Please wait a few minutes and try again."
        }
        _ => return grpc_error_tuple(err, request_id),
    };

    let payload = serde_json::to_string(&LoginErrorResponse {
        error: LoginErrorBody {
            code: "ERROR_CODE_UNAUTHORIZED".to_string(),
            message: user_message.to_string(),
            request_id: request_id.to_string(),
            meta,
        },
    })
    .unwrap_or_else(|_| {
        "{\"error\":{\"code\":\"ERROR_CODE_UNAUTHORIZED\",\"message\":\"Authentication failed\",\"request_id\":\"missing\"}}".to_string()
    });

    (StatusCode::UNAUTHORIZED, payload)
}

async fn verify_login_mfa(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<VerifyLoginMfaBody>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(VerifyLoginMfaRequest {
        challenge_token: payload.challenge_token,
        otp_code: payload.otp_code,
        factor_type: payload.factor_type.unwrap_or_default(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .verify_login_mfa(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LoginResponse {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        token_type: response.token_type,
        expires_at: response.expires_at,
        refresh_expires_at: response.refresh_expires_at,
        session_id: response.session_id,
        session_version: response.session_version,
    }))
}

async fn register(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<GenericAcceptedResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(RegisterUserRequest {
        email: payload.email,
        password: payload.password,
        first_name: payload.first_name,
        last_name: payload.last_name,
        middle_name: payload.middle_name,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .register_user(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(GenericAcceptedResponse {
        accepted: response.accepted,
        message: response.message,
    }))
}

async fn request_verify_email(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailRequestBody>,
) -> Result<Json<GenericAcceptedResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(RequestEmailVerificationOtpRequest {
        email: payload.email,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .request_email_verification_otp(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(GenericAcceptedResponse {
        accepted: response.accepted,
        message: response.message,
    }))
}

async fn confirm_verify_email(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailConfirmBody>,
) -> Result<Json<VerifyEmailConfirmResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(ConfirmEmailVerificationOtpRequest {
        email: payload.email,
        otp_code: payload.otp_code,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .confirm_email_verification_otp(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(VerifyEmailConfirmResponse {
        verified: response.verified,
        message: response.message,
    }))
}

async fn refresh(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequestBody>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(RefreshTokenRequest {
        refresh_token: payload.refresh_token,
        device_id: payload.device_id.unwrap_or_default(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .refresh_token(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LoginResponse {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        token_type: response.token_type,
        expires_at: response.expires_at,
        refresh_expires_at: response.refresh_expires_at,
        session_id: response.session_id,
        session_version: response.session_version,
    }))
}

async fn logout(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<LogoutRequestBody>,
) -> Result<Json<LogoutResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(LogoutSessionRequest {
        refresh_token: payload.refresh_token,
        reason: "user_logout".to_string(),
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .logout_session(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LogoutResponseBody {
        revoked: response.revoked,
        message: response.message,
    }))
}

async fn list_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<CursorListQuery>,
) -> Result<Json<SessionListResponseBody>, (StatusCode, String)> {
    let limit = normalize_list_limit(query.limit);
    let mut grpc_request = GrpcRequest::new(ListSessionsRequest {
        limit,
        cursor: query.cursor.unwrap_or_default(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .list_sessions(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(SessionListResponseBody {
        sessions: response
            .sessions
            .into_iter()
            .map(|value| SessionSummaryBody {
                session_id: value.session_id,
                aud: value.aud,
                realm: value.realm,
                client_id: empty_to_none(value.client_id),
                device_id: empty_to_none(value.device_id),
                remember_me: value.remember_me,
                ip_address: empty_to_none(value.ip_address),
                user_agent: empty_to_none(value.user_agent),
                created_at: value.created_at,
                last_activity_at: value.last_activity_at,
                expires_at: value.expires_at,
                revoked_at: if value.revoked_at > 0 {
                    Some(value.revoked_at)
                } else {
                    None
                },
                revoked_reason: empty_to_none(value.revoked_reason),
                mfa_level: value.mfa_level,
            })
            .collect(),
        page: CursorPageResponse {
            limit,
            next_cursor: empty_to_none(response.next_cursor),
            has_more: response.has_more,
        },
    }))
}

async fn logout_session_by_id(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<SessionLogoutRequestBody>,
) -> Result<Json<LogoutResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(LogoutSessionByIdRequest {
        session_id: payload.session_id,
        reason: payload.reason.unwrap_or_else(|| "user_logout".to_string()),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .logout_session_by_id(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LogoutResponseBody {
        revoked: response.revoked,
        message: response.message,
    }))
}

async fn logout_all_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<LogoutAllRequestBody>,
) -> Result<Json<LogoutAllResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(LogoutAllSessionsRequest {
        reason: payload.reason.unwrap_or_default(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .logout_all_sessions(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(LogoutAllResponseBody {
        session_version: response.session_version,
        revoked_sessions: response.revoked_sessions,
    }))
}

async fn request_forgot_password(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ForgotPasswordRequestBody>,
) -> Result<Json<GenericAcceptedResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(RequestPasswordResetOtpRequest {
        email: payload.email,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .request_password_reset_otp(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(GenericAcceptedResponse {
        accepted: response.accepted,
        message: response.message,
    }))
}

async fn verify_forgot_password(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ForgotPasswordVerifyBody>,
) -> Result<Json<ForgotPasswordVerifyResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(VerifyPasswordResetOtpRequest {
        email: payload.email,
        otp_code: payload.otp_code,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .verify_password_reset_otp(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(ForgotPasswordVerifyResponse {
        accepted: response.accepted,
        reset_token: if response.reset_token.is_empty() {
            None
        } else {
            Some(response.reset_token)
        },
        message: response.message,
    }))
}

async fn reset_password(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ResetPasswordBody>,
) -> Result<Json<ResetPasswordResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(ResetPasswordRequest {
        email: payload.email,
        reset_token: payload.reset_token,
        new_password: payload.new_password,
    });
    apply_gateway_internal_metadata(&mut grpc_request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .reset_password(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(ResetPasswordResponseBody {
        reset: response.reset,
        message: response.message,
    }))
}

async fn change_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ChangePasswordBody>,
) -> Result<Json<ChangePasswordResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(ChangePasswordRequest {
        current_password: payload.current_password,
        new_password: payload.new_password,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .change_password(grpc_request)
        .await
        .map_err(|err| {
            tracing::error!(
                request_id = %request_id.0,
                error = %err,
                "auth change_password grpc failed"
            );
            grpc_error_tuple(err, request_id.0.as_str())
        })?
        .into_inner();

    Ok(Json(ChangePasswordResponseBody {
        changed: response.changed,
        message: response.message,
    }))
}

async fn get_mfa_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<MfaStatusResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(GetMfaStatusRequest {});
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .get_mfa_status(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(MfaStatusResponseBody {
        mfa_enabled: response.mfa_enabled,
        factors: response
            .factors
            .into_iter()
            .map(|factor| MfaFactorSummaryBody {
                factor_type: factor.factor_type,
                status: factor.status,
                enabled_at: if factor.enabled_at > 0 {
                    Some(factor.enabled_at)
                } else {
                    None
                },
                masked_destination: empty_to_none(factor.masked_destination),
                backup_codes_remaining: factor.backup_codes_remaining,
            })
            .collect(),
    }))
}

async fn begin_authenticator_enrollment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    payload: Option<Json<BeginAuthenticatorEnrollmentBody>>,
) -> Result<Json<BeginAuthenticatorEnrollmentResponseBody>, (StatusCode, String)> {
    let issuer = payload
        .and_then(|Json(body)| body.issuer)
        .unwrap_or_default();
    let mut grpc_request = GrpcRequest::new(BeginAuthenticatorEnrollmentRequest { issuer });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .begin_authenticator_enrollment(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(BeginAuthenticatorEnrollmentResponseBody {
        factor_type: response.factor_type,
        factor_id: response.factor_id,
        issuer: response.issuer,
        account_name: response.account_name,
        secret: response.secret,
        otpauth_uri: response.otpauth_uri,
        qr_svg_data_uri: empty_to_none(response.qr_svg_data_uri),
    }))
}

async fn confirm_authenticator_enrollment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ConfirmAuthenticatorEnrollmentBody>,
) -> Result<Json<ConfirmAuthenticatorEnrollmentResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(ConfirmAuthenticatorEnrollmentRequest {
        otp_code: payload.otp_code,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .confirm_authenticator_enrollment(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(ConfirmAuthenticatorEnrollmentResponseBody {
        enabled: response.enabled,
        message: response.message,
        backup_codes: response.backup_codes,
    }))
}

async fn disable_mfa_factor(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<DisableMfaFactorBody>,
) -> Result<Json<DisableMfaFactorResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(DisableMfaFactorRequest {
        factor_type: payload.factor_type.unwrap_or_default(),
        otp_code: payload.otp_code,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .disable_mfa_factor(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(DisableMfaFactorResponseBody {
        disabled: response.disabled,
        message: response.message,
    }))
}

async fn regenerate_backup_codes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<RegenerateBackupCodesBody>,
) -> Result<Json<RegenerateBackupCodesResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(RegenerateBackupCodesRequest {
        otp_code: payload.otp_code,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .regenerate_backup_codes(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(RegenerateBackupCodesResponseBody {
        regenerated: response.regenerated,
        message: response.message,
        backup_codes: response.backup_codes,
    }))
}

async fn get_dashboard_summary(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<DashboardSummaryResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(GetDashboardSummaryRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .get_dashboard_summary(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(DashboardSummaryResponse {
        user_id: response.user_id,
        devices_count: response.devices_count,
        trips_count: response.trips_count,
        media_count: response.media_count,
        subscription_plan: response.subscription_plan,
        subscription_status: response.subscription_status,
        ai_usage_total: response.ai_usage_total,
        generated_at: response.generated_at,
    }))
}

async fn get_me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<ProfileResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(GetProfileRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .get_profile(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let profile = response.profile.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing profile in get response".to_string(),
    ))?;

    Ok(Json(ProfileResponse {
        user_id: profile.user_id,
        email: profile.email,
        first_name: profile.first_name,
        last_name: profile.last_name,
        middle_name: profile.middle_name,
        preferred_name: profile.preferred_name,
        display_name: profile.display_name,
        full_name: profile.full_name,
        timezone: profile.timezone,
        updated_at: profile.updated_at,
    }))
}

async fn update_me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProfileBody>,
) -> Result<Json<UpdateProfileResponse>, (StatusCode, String)> {
    let idempotency_key = headers
        .get("x-idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let mut grpc_request = GrpcRequest::new(UpdateProfileRequest {
        user_id: claims.sub.clone(),
        first_name: payload.first_name.unwrap_or_default(),
        last_name: payload.last_name.unwrap_or_default(),
        middle_name: payload.middle_name.unwrap_or_default(),
        preferred_name: payload.preferred_name.unwrap_or_default(),
        display_name: payload.display_name.unwrap_or_default(),
        feature_key: payload
            .feature_key
            .unwrap_or_else(|| "profile_write".to_string()),
        idempotency_key,
        timezone: payload.timezone.unwrap_or_default(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .update_profile(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let profile = response.profile.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing profile in update response".to_string(),
    ))?;

    Ok(Json(UpdateProfileResponse {
        user_id: profile.user_id,
        first_name: profile.first_name,
        last_name: profile.last_name,
        middle_name: profile.middle_name,
        preferred_name: profile.preferred_name,
        display_name: profile.display_name,
        full_name: profile.full_name,
        timezone: profile.timezone,
        event_published: response.event_published,
        event_duplicate: response.event_duplicate,
    }))
}

async fn get_user_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<UserSettingsResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(GetUserSettingsRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut users_client = state.users_client.lock().await;
    let response = users_client
        .get_user_settings(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();
    let settings = response.settings.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing settings in get response".to_string(),
    ))?;

    Ok(Json(map_user_settings_payload(settings)))
}

async fn update_user_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserSettingsBody>,
) -> Result<Json<UserSettingsResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(UpdateUserSettingsRequest {
        user_id: claims.sub.clone(),
        full_name: payload.full_name,
        username: payload.username,
        phone: payload.phone,
        profile_photo_object_key: payload.profile_photo_object_key,
        bio: payload.bio,
        language: payload.language,
        timezone: payload.timezone,
        date_format: payload.date_format,
        clock_format: payload.clock_format,
        distance_unit: payload.distance_unit,
        temperature_unit: payload.temperature_unit,
        first_name: payload.first_name,
        last_name: payload.last_name,
        middle_name: payload.middle_name,
        preferred_name: payload.preferred_name,
        display_name: payload.display_name,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut users_client = state.users_client.lock().await;
    let response = users_client
        .update_user_settings(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();
    let settings = response.settings.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing settings in update response".to_string(),
    ))?;

    Ok(Json(map_user_settings_payload(settings)))
}

async fn update_user_notification_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserNotificationSettingsBody>,
) -> Result<Json<UserSettingsResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(UpdateUserNotificationSettingsRequest {
        user_id: claims.sub.clone(),
        push_new_photo_captured: payload.push_new_photo_captured,
        push_species_detected: payload.push_species_detected,
        push_device_offline: payload.push_device_offline,
        push_low_battery: payload.push_low_battery,
        push_storage_full: payload.push_storage_full,
        push_subscription_renewal_reminder: payload.push_subscription_renewal_reminder,
        push_trip_activity_updates: payload.push_trip_activity_updates,
        email_new_photo_captured: payload.email_new_photo_captured,
        email_species_detected: payload.email_species_detected,
        email_device_offline: payload.email_device_offline,
        email_low_battery: payload.email_low_battery,
        email_storage_full: payload.email_storage_full,
        email_subscription_renewal_reminder: payload.email_subscription_renewal_reminder,
        email_trip_activity_updates: payload.email_trip_activity_updates,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut users_client = state.users_client.lock().await;
    let response = users_client
        .update_user_notification_settings(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();
    let settings = response.settings.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing settings in notifications update response".to_string(),
    ))?;

    Ok(Json(map_user_settings_payload(settings)))
}

async fn create_profile_photo_upload_ticket(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<CreateProfilePhotoUploadTicketBody>,
) -> Result<Json<CreateProfilePhotoUploadTicketResponseBody>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(CreateProfilePhotoUploadTicketRequest {
        user_id: claims.sub.clone(),
        content_type: payload.content_type,
        content_length: payload.content_length,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut users_client = state.users_client.lock().await;
    let response = users_client
        .create_profile_photo_upload_ticket(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(CreateProfilePhotoUploadTicketResponseBody {
        object_key: response.object_key,
        upload_url: response.upload_url,
        method: response.method,
        expires_at: response.expires_at,
        required_headers: response.required_headers.into_iter().collect(),
        content_type: response.content_type,
        max_bytes: response.max_bytes,
    }))
}

async fn get_profile_photo_download_url(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<GetProfilePhotoDownloadUrlQuery>,
) -> Result<Json<GetProfilePhotoDownloadUrlResponseBody>, (StatusCode, String)> {
    let object_key = if let Some(object_key) = query.object_key.filter(|value| !value.is_empty()) {
        object_key
    } else {
        let mut settings_request = GrpcRequest::new(GetUserSettingsRequest {
            user_id: claims.sub.clone(),
        });
        apply_gateway_internal_metadata_with_auth(
            &mut settings_request,
            &request_id,
            &headers,
            Some(&claims),
        )?;
        let mut users_client = state.users_client.lock().await;
        let settings_response = users_client
            .get_user_settings(settings_request)
            .await
            .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
            .into_inner();
        let settings = settings_response.settings.ok_or((
            StatusCode::BAD_GATEWAY,
            "missing settings in get response".to_string(),
        ))?;
        if settings.profile_photo_object_key.trim().is_empty() {
            return Err((
                StatusCode::NOT_FOUND,
                "profile photo is not set".to_string(),
            ));
        }
        settings.profile_photo_object_key
    };

    let mut grpc_request = GrpcRequest::new(CreateProfilePhotoDownloadUrlRequest {
        user_id: claims.sub.clone(),
        object_key,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut users_client = state.users_client.lock().await;
    let response = users_client
        .create_profile_photo_download_url(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(GetProfilePhotoDownloadUrlResponseBody {
        object_key: response.object_key,
        download_url: response.download_url,
        method: response.method,
        expires_at: response.expires_at,
    }))
}

async fn create_device(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<CreateDeviceBody>,
) -> Result<Json<DeviceResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(CreateDeviceRequest {
        user_id: claims.sub.clone(),
        platform: payload.platform,
        nickname: payload.nickname,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .create_device(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let device = response.device.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing device in response".to_string(),
    ))?;

    Ok(Json(DeviceResponse {
        device_id: device.device_id,
        platform: device.platform,
        nickname: device.nickname,
        created_at: device.created_at,
    }))
}

async fn list_devices(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<CursorListQuery>,
) -> Result<Json<DevicesListResponse>, (StatusCode, String)> {
    let limit = normalize_list_limit(query.limit);
    let mut grpc_request = GrpcRequest::new(ListDevicesRequest {
        user_id: claims.sub.clone(),
        limit,
        cursor: query.cursor.unwrap_or_default(),
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .list_devices(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    let devices = response
        .devices
        .into_iter()
        .map(|device| DeviceResponse {
            device_id: device.device_id,
            platform: device.platform,
            nickname: device.nickname,
            created_at: device.created_at,
        })
        .collect();

    Ok(Json(DevicesListResponse {
        devices,
        page: CursorPageResponse {
            limit,
            next_cursor: empty_to_none(response.next_cursor),
            has_more: response.has_more,
        },
    }))
}


async fn create_media_upload_ticket(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<CreateMediaUploadTicketBody>,
) -> Result<Json<MediaUploadTicketResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(CreateMediaUploadTicketRequest {
        user_id: claims.sub.clone(),
        filename: payload.filename,
        content_type: payload.content_type,
        content_length: payload.content_length,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .create_media_upload_ticket(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(MediaUploadTicketResponse {
        object_key: response.object_key,
        upload_url: response.upload_url,
        method: response.method,
        expires_at: response.expires_at,
        required_headers: std::collections::BTreeMap::new(),
    }))
}

async fn create_export_job(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<CreateExportBody>,
) -> Result<Json<ExportJobResponse>, (StatusCode, String)> {
    let idempotency_key = headers
        .get("x-idempotency-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let mut grpc_request = GrpcRequest::new(CreateExportJobRequest {
        user_id: claims.sub.clone(),
        export_kind: payload.export_kind,
        format: payload.format,
        idempotency_key,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .create_export_job(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(ExportJobResponse {
        job_id: response.job_id,
        status: response.status,
        artifact_key: response.artifact_key,
        download_url: None,
        download_expires_at: None,
        duplicate: response.duplicate,
        error_message: None,
    }))
}

async fn get_export_job(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<ExportJobResponse>, (StatusCode, String)> {
    let mut grpc_request = GrpcRequest::new(GetExportJobRequest {
        user_id: claims.sub.clone(),
        job_id,
    });
    apply_gateway_internal_metadata_with_auth(
        &mut grpc_request,
        &request_id,
        &headers,
        Some(&claims),
    )?;

    let mut public_client = state.public_client.lock().await;
    let response = public_client
        .get_export_job(grpc_request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?
        .into_inner();

    Ok(Json(ExportJobResponse {
        job_id: response.job_id,
        status: response.status,
        artifact_key: response.artifact_key,
        download_url: if response.download_url.is_empty() {
            None
        } else {
            Some(response.download_url)
        },
        download_expires_at: if response.download_expires_at == 0 {
            None
        } else {
            Some(response.download_expires_at)
        },
        duplicate: false,
        error_message: if response.error_message.is_empty() {
            None
        } else {
            Some(response.error_message)
        },
    }))
}

#[derive(Debug, Serialize)]
struct ProxyPayload {
    status: String,
    request_id: String,
    propagated_request_id: String,
    subject: String,
}

async fn proxy_auth_health(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Result<Json<ProxyPayload>, (StatusCode, String)> {
    let mut request = GrpcRequest::new(HealthRequest {});
    apply_gateway_internal_metadata(&mut request, &request_id, &headers)?;

    let mut auth_client = state.auth_client.lock().await;
    let response = auth_client
        .health(request)
        .await
        .map_err(|err| grpc_error_tuple(err, request_id.0.as_str()))?;

    let body = response.into_inner();
    Ok(Json(ProxyPayload {
        status: body.status,
        request_id: request_id.0,
        propagated_request_id: body.request_id,
        subject: claims.sub,
    }))
}

// =========================================================================
// Billing Handlers
// =========================================================================

async fn billing_list_payment_methods(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(ListPaymentMethodsRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .list_payment_methods(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_create_setup_intent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(CreateSetupIntentRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .create_setup_intent(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct AddPaymentMethodBody {
    stripe_payment_method_id: String,
    #[serde(default)]
    set_as_default: bool,
}

async fn billing_add_payment_method(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<AddPaymentMethodBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(AddPaymentMethodRequest {
        user_id: claims.sub.clone(),
        stripe_payment_method_id: body.stripe_payment_method_id,
        set_as_default: body.set_as_default,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .add_payment_method(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_set_default_payment_method(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(pm_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(SetDefaultPaymentMethodRequest {
        user_id: claims.sub.clone(),
        payment_method_id: pm_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .set_default_payment_method(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_remove_payment_method(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(pm_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(RemovePaymentMethodRequest {
        user_id: claims.sub.clone(),
        payment_method_id: pm_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .remove_payment_method(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_list_plans(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(ListSubscriptionPlansRequest {});
    apply_gateway_internal_metadata(&mut grpc, &request_id, &headers)?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .list_subscription_plans(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_get_plan(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(plan_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(GetSubscriptionPlanRequest { plan_id });
    apply_gateway_internal_metadata(&mut grpc, &request_id, &headers)?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .get_subscription_plan(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_list_subscriptions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(ListDeviceSubscriptionsRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .list_device_subscriptions(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_get_device_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(GetDeviceSubscriptionRequest {
        user_id: claims.sub.clone(),
        device_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .get_device_subscription(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct CreateDeviceSubscriptionBody {
    plan_id: String,
    payment_method_id: String,
}

async fn billing_create_device_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<CreateDeviceSubscriptionBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(CreateDeviceSubscriptionRequest {
        user_id: claims.sub.clone(),
        device_id,
        plan_id: body.plan_id,
        payment_method_id: body.payment_method_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .create_device_subscription(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct CancelSubscriptionBody {
    #[serde(default)]
    cancel_immediately: bool,
}

async fn billing_cancel_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(sub_id): Path<String>,
    Json(body): Json<CancelSubscriptionBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(CancelDeviceSubscriptionRequest {
        user_id: claims.sub.clone(),
        subscription_id: sub_id,
        cancel_immediately: body.cancel_immediately,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .cancel_device_subscription(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_resume_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(sub_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(ResumeDeviceSubscriptionRequest {
        user_id: claims.sub.clone(),
        subscription_id: sub_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .resume_device_subscription(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_list_invoices(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<CursorListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = normalize_list_limit(query.limit);
    let mut grpc = GrpcRequest::new(ListInvoicesV2Request {
        user_id: claims.sub.clone(),
        limit,
        cursor: query.cursor.unwrap_or_default(),
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .list_invoices_v2(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_get_invoice(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(GetInvoiceV2Request {
        user_id: claims.sub.clone(),
        invoice_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .get_invoice_v2(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_get_invoice_html(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(GetInvoiceHtmlRequest {
        user_id: claims.sub.clone(),
        invoice_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .get_invoice_html(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Html(resp.html))
}

async fn billing_retry_invoice(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(RetryInvoicePaymentRequest {
        user_id: claims.sub.clone(),
        invoice_id,
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .retry_invoice_payment(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

async fn billing_get_summary(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(GetBillingSummaryRequest {
        user_id: claims.sub.clone(),
    });
    apply_gateway_internal_metadata_with_auth(&mut grpc, &request_id, &headers, Some(&claims))?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .get_billing_summary(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct StripeWebhookBody {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    amount_cents: i64,
    #[serde(default)]
    currency: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    payload_json: String,
}

async fn billing_stripe_webhook(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<StripeWebhookBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut grpc = GrpcRequest::new(IngestBillingWebhookRequest {
        provider: body.provider,
        event_id: body.event_id,
        user_id: body.user_id,
        amount_cents: body.amount_cents,
        currency: body.currency,
        signature: body.signature,
        payload_json: body.payload_json,
    });
    apply_gateway_internal_metadata(&mut grpc, &request_id, &headers)?;
    let mut client = state.billing_client.lock().await;
    let resp = client
        .ingest_billing_webhook(grpc)
        .await
        .map_err(|e| grpc_error_tuple(e, &request_id.0))?
        .into_inner();
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}
