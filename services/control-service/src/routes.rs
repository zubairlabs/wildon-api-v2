use crate::{
    modules::{dashboard, feature_flags, notification_templates},
    state::{AdminUserRecord, AppState},
};
use ::middleware::RequestId;
use reqwest;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use auth::{claims::Claims, jwt, scope_catalog};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, MatchedPath, Multipart, Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, HOST},
        HeaderMap, Method, Request, StatusCode,
    },
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use common::http::{
    json::Json,
    pagination::{parse_offset_cursor, CursorPage, CursorPagination},
};
use config::grpc::inject_internal_metadata;
use contracts::wildon::api_clients::v1::{
    ApiClient, ClientEvent, ClientStatus as ApiClientStatus, ClientType as ApiClientType,
    CreateClientRequest as ApiCreateClientRequest, GetClientByIdRequest, GetClientByRefRequest,
    ListClientEventsRequest, ListClientsRequest, ListRateLimitPoliciesRequest,
    RotateClientSecretRequest, SetClientStatusRequest as ApiSetClientStatusRequest,
    UpdateClientRequest as ApiUpdateClientRequest,
};
use contracts::wildon::auth::v1::{
    auth_service_client::AuthServiceClient, LogoutAllSessionsRequest,
};
use contracts::wildon::billing::v1::{
    BillingInvoice, BillingLedgerEntry, BillingPlan, BillingSubscription, BillingTransaction,
    CreatePlanRequest, CreateSubscriptionRequest, DeletePlanRequest, IngestBillingWebhookRequest,
    ListInvoicesRequest, ListLedgerEntriesRequest, ListPlansRequest, ListSubscriptionsRequest,
    ListTransactionsRequest, RefundTransactionRequest, UpdatePlanRequest,
    UpdateSubscriptionRequest,
};
use contracts::wildon::core::v1::{
    GetFeatureFlagRequest, NotificationChannel, SendNotificationRequest, SetFeatureFlagRequest,
};
use contracts::wildon::logs::v1::{
    AuditAccessPurpose, AuditActorType, AuditAuthMechanism, AuditDataSensitivityLevel,
    AuditLogRecord, AuditResult, GetAuditLogRequest, IngestAuditRequest, ListAuditLogsRequest,
};
use contracts::wildon::users::v1::{
    CreateUserRequest, DisableUserRequest, GetUserAuthStateRequest, GetUserAuthStateResponse,
    GetUserSettingsRequest, UpdateUserRolesRequest, UpdateUserScopesRequest,
    UpdateUserSettingsRequest,
};
use ipnet::IpNet;
use logs_sdk::AuditEventBuilder;
use redis::AsyncCommands;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{QueryBuilder, Row};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    str::FromStr,
};
use tonic::{Code as GrpcCode, Request as GrpcRequest};
use uuid::Uuid;

const CONTROL_OPENAPI_JSON: &str = include_str!("../../../docs/openapi/control-v1.json");
const SYSTEM_API_VERSION: &str = "1";
const SYSTEM_API_MAX_SKEW_SECONDS: i64 = 300;
const SYSTEM_API_NONCE_TTL_MINUTES: i64 = 10;
const SYSTEM_API_IDEMPOTENCY_TTL_HOURS: i64 = 24;

const ALLOWED_CONTROL_ROLES: [&str; 7] = [
    "user",
    "support",
    "partner",
    "manager",
    "auditor",
    "admin",
    "superadmin",
];

type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Debug, Clone)]
struct SystemApiClientContext {
    client_id: Uuid,
    public_key: String,
    scopes: HashSet<String>,
    request_id: String,
}

#[derive(Debug, Clone)]
struct SystemApiRequestMeta {
    request_id: String,
    endpoint: String,
    request_hash: String,
    idempotency_key: Option<String>,
}

#[derive(Debug)]
struct SystemApiAuthRecord {
    id: Uuid,
    public_key: String,
    secret_key: String,
    scopes: HashSet<String>,
}

#[derive(Debug, Serialize)]
struct SystemApiErrorEnvelope {
    error: SystemApiErrorBody,
}

#[derive(Debug, Serialize)]
struct SystemApiErrorBody {
    code: String,
    message: String,
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegionApiKeysResponse {
    public_key: String,
    secret_key_hint: String,
    last_rotated: String,
}

#[derive(Debug, Serialize)]
struct RegionServerResponse {
    cpu_cores: i32,
    cpu_usage_percent: f64,
    ram_gb: i32,
    ram_usage_percent: f64,
    storage_gb: i32,
    storage_usage_percent: f64,
    uptime_days: i32,
    api_latency_ms: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegionServiceEntry {
    name: String,
    url: String,
    port: Option<i32>,
}

#[derive(Debug, Serialize)]
struct RegionResponse {
    id: String,
    display_ref: String,
    name: String,
    country: String,
    country_code: String,
    flag: String,
    currency: String,
    currency_symbol: String,
    timezone: String,
    address: String,
    api_base_url: String,
    api_keys: RegionApiKeysResponse,
    server: RegionServerResponse,
    status: String,
    total_users: i64,
    total_devices: i64,
    total_organizations: i64,
    created_at: String,
    updated_at: String,
    services: Vec<RegionServiceEntry>,
}

#[derive(Debug, Serialize)]
struct RegionListResponse {
    items: Vec<RegionResponse>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct CreateRegionBody {
    name: String,
    country: String,
    country_code: String,
    flag: Option<String>,
    currency: Option<String>,
    currency_symbol: Option<String>,
    timezone: Option<String>,
    address: Option<String>,
    api_base_url: String,
    public_key: String,
    secret_key: String,
    services: Option<Vec<RegionServiceEntry>>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRegionBody {
    name: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    flag: Option<String>,
    currency: Option<String>,
    currency_symbol: Option<String>,
    timezone: Option<String>,
    address: Option<String>,
    api_base_url: Option<String>,
    public_key: Option<String>,
    secret_key: Option<String>,
    services: Option<Vec<RegionServiceEntry>>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestRegionConnectionBody {
    api_base_url: String,
    public_key: String,
    secret_key: String,
}

#[derive(Debug, Serialize)]
struct TestRegionConnectionResponse {
    connected: bool,
    server: RegionServerResponse,
    country: String,
    currency: String,
    services: Vec<RegionServiceEntry>,
}

#[derive(Debug, Serialize)]
struct RegionCredentialsResponse {
    id: String,
    name: String,
    api_base_url: String,
    public_key: String,
    secret_key: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
struct UpsertUserBody {
    active: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedUserViewResponse {
    id: String,
    email: String,
    phone: Option<String>,
    first_name: String,
    last_name: String,
    tier: String,
    status: String,
    email_verified: bool,
    phone_verified: bool,
    login_method: String,
    last_login_ip: Option<String>,
    country: Option<String>,
    patients_count: i64,
    devices_count: i64,
    alerts_count: i64,
    active_subscription_id: Option<String>,
    created_at: String,
    last_active_at: String,
    anonymized_at: Option<String>,
    roles: Vec<String>,
    scopes: Vec<String>,
    perm_rev: i64,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    user_id: String,
    status: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    perm_rev: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateManagedUserBody {
    user_id: Option<String>,
    email: String,
    password: String,
    first_name: Option<String>,
    last_name: Option<String>,
    middle_name: Option<String>,
    display_name: Option<String>,
    phone: Option<String>,
    tier: Option<String>,
    status: Option<String>,
    roles: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    email_verified: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PaginatedMetaResponse {
    total: i64,
    page: u32,
    per_page: u32,
    total_pages: u32,
}

#[derive(Debug, Serialize)]
struct ManagedUsersListResponse {
    data: Vec<ManagedUserViewResponse>,
    meta: PaginatedMetaResponse,
}

#[derive(Debug, Deserialize)]
struct ManagedUsersQuery {
    page: Option<u32>,
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateManagedUserBody {
    first_name: Option<String>,
    last_name: Option<String>,
    phone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateManagedUserStatusBody {
    status: String,
}

#[derive(Debug, Deserialize)]
struct UpdateManagedUserEmailVerificationBody {
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct SetManagedUserTempPasswordBody {
    password: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Debug, Clone)]
struct AuditAccountRecord {
    id: Uuid,
    user_id: Uuid,
    email: String,
    role: String,
    created_by: Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
    allowed_ips: Option<Vec<String>>,
    is_active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct CreateAuditorBody {
    email: String,
    password: String,
    expires_at: i64,
    allowed_ips: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ResetAuditorPasswordBody {
    password: String,
}

#[derive(Debug, Serialize)]
struct AuditorAccountResponse {
    id: String,
    user_id: String,
    email: String,
    role: String,
    created_by: String,
    expires_at: i64,
    allowed_ips: Option<Vec<String>>,
    is_active: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct AuditorAccountsListResponse {
    auditors: Vec<AuditorAccountResponse>,
}

#[derive(Debug, Serialize)]
struct AuditorMutationResponse {
    id: String,
    user_id: String,
    email: String,
    is_active: bool,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct GrantRoleBody {
    role: String,
}

#[derive(Debug, Serialize)]
struct RolesResponse {
    user_id: String,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GrantScopeBody {
    scope: String,
}

#[derive(Debug, Deserialize)]
struct UpdateScopesBody {
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScopesResponse {
    user_id: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScopeCatalogResponse {
    scopes: Vec<ScopeCatalogScopeResponse>,
    assignable_scopes: Vec<String>,
    admin_assignable_scopes: Vec<String>,
    actor_assignable_scopes: Vec<String>,
    role_default_scopes: Vec<RoleDefaultScopesResponse>,
}

#[derive(Debug, Serialize)]
struct ScopeCatalogScopeResponse {
    name: String,
    description: String,
    first_party_default: bool,
    third_party_required: bool,
}

#[derive(Debug, Serialize)]
struct RoleDefaultScopesResponse {
    role: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RoleCatalogItemResponse {
    role: String,
    default_scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RoleCatalogResponse {
    roles: Vec<RoleCatalogItemResponse>,
}

#[derive(Debug, Serialize)]
struct EffectivePermissionsResponse {
    user_id: String,
    status: String,
    roles: Vec<String>,
    assigned_scopes: Vec<String>,
    effective_scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BootstrapSuperadminBody {
    email: String,
    password: String,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapSuperadminResponse {
    user_id: String,
    email: String,
    roles: Vec<String>,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SetFeatureFlagBody {
    enabled: bool,
    updated_by: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct FeatureFlagResponse {
    key: String,
    enabled: bool,
    updated_by: String,
    reason: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct BillingWebhookBody {
    provider: String,
    event_id: String,
    user_id: String,
    amount_cents: i64,
    currency: String,
    signature: String,
    payload_json: String,
}

#[derive(Debug, Serialize)]
struct BillingWebhookResponse {
    accepted: bool,
    duplicate: bool,
    invoice_id: String,
    reason: String,
    transaction_id: String,
}

#[derive(Debug, Deserialize)]
struct BillingPlansQuery {
    status: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateBillingPlanBody {
    plan_code: String,
    name: String,
    description: Option<String>,
    priority: Option<i32>,
    interval: String,
    price_cents: i64,
    currency: Option<String>,
    device_limit: i32,
    storage_limit_bytes: i64,
    retention_days: i32,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateBillingPlanBody {
    plan_code: Option<String>,
    name: Option<String>,
    description: Option<String>,
    priority: Option<i32>,
    interval: Option<String>,
    price_cents: Option<i64>,
    currency: Option<String>,
    device_limit: Option<i32>,
    storage_limit_bytes: Option<i64>,
    retention_days: Option<i32>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct BillingPlanResponse {
    plan_id: String,
    plan_code: String,
    name: String,
    description: String,
    priority: i32,
    interval: String,
    price_cents: i64,
    currency: String,
    device_limit: i32,
    storage_limit_bytes: i64,
    retention_days: i32,
    status: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct BillingPlansListResponse {
    plans: Vec<BillingPlanResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Deserialize)]
struct BillingSubscriptionsQuery {
    user_id: Option<String>,
    status: Option<String>,
    plan_code: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateBillingSubscriptionBody {
    user_id: String,
    plan_id: Option<String>,
    plan_code: Option<String>,
    status: Option<String>,
    start_date: Option<i64>,
    end_date: Option<i64>,
    auto_renew: Option<bool>,
    device_count: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct UpdateBillingSubscriptionBody {
    plan_id: Option<String>,
    plan_code: Option<String>,
    status: Option<String>,
    end_date: Option<i64>,
    auto_renew: Option<bool>,
    device_count: Option<i32>,
}

#[derive(Debug, Serialize)]
struct BillingSubscriptionResponse {
    subscription_id: String,
    subscription_code: String,
    user_id: String,
    plan_id: String,
    plan_code: String,
    status: String,
    start_date: i64,
    end_date: i64,
    auto_renew: bool,
    device_count: i32,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct BillingSubscriptionsListResponse {
    subscriptions: Vec<BillingSubscriptionResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Deserialize)]
struct InvoiceSettingsBody {
    logo_url: String,
    logo_size_px: i32,
    business_name: String,
    business_legal_name: String,
    business_address: String,
    support_phone: String,
    invoice_email: String,
}

#[derive(Debug, Serialize)]
struct InvoiceSettingsResponse {
    logo_url: String,
    logo_size_px: i32,
    business_name: String,
    business_legal_name: String,
    business_address: String,
    support_phone: String,
    invoice_email: String,
    updated_by: String,
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DeviceValidationRule {
    metric: String,
    unit: String,
    min: i32,
    max: i32,
    action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DeviceConfigurationPayload {
    heartbeat_interval: i32,
    offline_threshold: i32,
    session_timeout: i32,
    stale_after_secs: i32,
    command_ack_timeout: i32,
    command_retry_max: i32,
    max_packets_per_sec: i32,
    outlier_rejection: bool,
    validation_rules: Vec<DeviceValidationRule>,
    low_battery_threshold: i32,
    fall_sensitivity: String,
    geofence_grace_period: i32,
    ack_timeout: i32,
    escalation_behavior: String,
    min_firmware_version: String,
    firmware_enforcement: String,
    system_timezone: String,
    timestamp_correction: bool,
    max_clock_drift: i32,
    auto_decommission_days: i32,
    require_model_assignment: bool,
    device_ingestion_enabled: bool,
    #[serde(default = "default_retention_days")]
    connection_log_retention_days: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_swept_at: Option<i64>,
}

fn default_retention_days() -> i32 { 30 }

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ApiIntegrationSettingsPayload {
    webhook_url: String,
    retry_attempts: i32,
    retry_backoff: i32,
    webhook_enabled: bool,
    allowed_origins: Vec<String>,
    access_token_expiration_hours: i32,
    refresh_token_expiration_days: i32,
}

#[derive(Debug, Deserialize)]
struct BillingListQuery {
    user_id: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BillingLedgerQuery {
    user_id: Option<String>,
    transaction_id: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditLogsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    action: Option<String>,
    consumer: Option<String>,
    user_id: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SystemSessionsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RefundTransactionBody {
    transaction_id: String,
    amount_cents: Option<i64>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct BillingTransactionResponse {
    transaction_id: String,
    user_id: String,
    invoice_id: String,
    status: String,
    amount_cents: i64,
    refunded_amount_cents: i64,
    currency: String,
    provider: String,
    external_txn_id: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct BillingInvoiceResponse {
    invoice_id: String,
    user_id: String,
    status: String,
    amount_cents: i64,
    refunded_amount_cents: i64,
    currency: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct BillingLedgerEntryResponse {
    ledger_id: String,
    user_id: String,
    transaction_id: String,
    invoice_id: String,
    entry_type: String,
    amount_cents: i64,
    currency: String,
    note: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct BillingTransactionsListResponse {
    transactions: Vec<BillingTransactionResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Serialize)]
struct BillingInvoicesListResponse {
    invoices: Vec<BillingInvoiceResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Serialize)]
struct BillingLedgerListResponse {
    entries: Vec<BillingLedgerEntryResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Serialize)]
struct AuditLogItemResponse {
    event_id: String,
    user_id: String,
    action: String,
    consumer: String,
    created_at: i64,
    payload: JsonValue,
}

#[derive(Debug, Serialize)]
struct AuditLogsPageResponse {
    limit: u32,
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct AuditLogsListResponse {
    items: Vec<AuditLogItemResponse>,
    page: AuditLogsPageResponse,
    total: u64,
}

#[derive(Debug, Serialize)]
struct AdminSessionResponse {
    session_id: String,
    user_id: String,
    user_email: String,
    user_name: String,
    role: String,
    ip_address: String,
    user_agent: String,
    device_hint: String,
    status: String,
    created_at: i64,
    last_active_at: i64,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
struct AdminSessionsListResponse {
    items: Vec<AdminSessionResponse>,
    page: AuditLogsPageResponse,
    total: i64,
}

#[derive(Debug, Serialize)]
struct RevokeSessionResponse {
    session_id: String,
    revoked: bool,
}

#[derive(Debug, Deserialize)]
struct ApiClientsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    status: Option<String>,
    environment: Option<String>,
    surface: Option<String>,
    platform: Option<String>,
    client_type: Option<String>,
    search: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiClientEventsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiClientPoliciesQuery {
    scope: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateApiClientBody {
    client_id: String,
    display_name: String,
    description: Option<String>,
    platform: String,
    surface: String,
    environment: String,
    client_type: String,
    status: Option<String>,
    #[serde(default)]
    allowed_audiences: Vec<String>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    ip_allowlist: Vec<String>,
    require_mtls: Option<bool>,
    is_version_enforced: Option<bool>,
    min_app_version: Option<String>,
    max_app_version: Option<String>,
    user_rate_policy: String,
    client_safety_policy: String,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateApiClientBody {
    display_name: Option<String>,
    description: Option<String>,
    platform: Option<String>,
    surface: Option<String>,
    environment: Option<String>,
    client_type: Option<String>,
    allowed_audiences: Option<Vec<String>>,
    allowed_origins: Option<Vec<String>>,
    ip_allowlist: Option<Vec<String>>,
    require_mtls: Option<bool>,
    is_version_enforced: Option<bool>,
    min_app_version: Option<String>,
    max_app_version: Option<String>,
    user_rate_policy: Option<String>,
    client_safety_policy: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetApiClientStatusBody {
    status: String,
}

#[derive(Debug, Deserialize)]
struct RotateApiClientSecretBody {
    expires_at_unix: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ApiClientRecordResponse {
    id: String,
    client_id: String,
    client_number: u64,
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
    created_at: i64,
    updated_at: i64,
    last_used_at: i64,
    created_by: String,
    updated_by: String,
    notes: String,
    has_active_secret: bool,
}

#[derive(Debug, Serialize)]
struct ApiClientsPageResponse {
    limit: u32,
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct ApiClientsListResponse {
    items: Vec<ApiClientRecordResponse>,
    page: ApiClientsPageResponse,
    total: u64,
}

#[derive(Debug, Serialize)]
struct ApiClientCreateResponse {
    client: ApiClientRecordResponse,
    secret_plaintext: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiClientRotateSecretResponse {
    client: ApiClientRecordResponse,
    secret_version: u32,
    secret_plaintext: String,
}

#[derive(Debug, Serialize)]
struct ApiClientEventResponse {
    event_id: String,
    client_id: String,
    event_type: String,
    actor_user_id: String,
    payload: JsonValue,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiClientEventsListResponse {
    items: Vec<ApiClientEventResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Serialize)]
struct RateLimitPolicyResponse {
    name: String,
    scope: String,
    route_group: String,
    requests_per_min: u32,
    requests_per_hour: u32,
    burst: u32,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct RateLimitPoliciesListResponse {
    items: Vec<RateLimitPolicyResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Serialize)]
struct RefundTransactionApiResponse {
    refunded: bool,
    reason: String,
    transaction: Option<BillingTransactionResponse>,
    invoice: Option<BillingInvoiceResponse>,
    ledger_entry: Option<BillingLedgerEntryResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlDashboardResponse {
    total_users: u64,
    active_users: u64,
    total_patients: u64,
    active_patients: u64,
    total_devices: u64,
    active_devices: u64,
    total_alerts: u64,
    critical_alerts: u64,
    revenue: ControlDashboardRevenueResponse,
    managed_users: u64,
    total_role_bindings: u64,
    revenue_cents_24h: i64,
    active_subscriptions: u64,
    generated_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlDashboardRevenueResponse {
    monthly: i64,
    yearly: i64,
}

#[derive(Debug, Serialize)]
struct AppStatsResponse {
    guests_count: i64,
    registered_users: i64,
    users_online: i64,
    peak_online_today: i64,
    avg_session_minutes: f64,
    crash_rate_percent: f64,
    api_status: String,
    api_latency_ms: i32,
    device_distribution: JsonValue,
}

#[derive(Debug, Serialize)]
struct AppRecordResponse {
    id: String,
    platform: String,
    display_name: String,
    description: String,
    status: String,
    app_version: String,
    api_version: String,
    min_supported_version: String,
    latest_available_version: Option<String>,
    force_update_version: Option<String>,
    last_updated_at: String,
    update_policy: String,
    stats: AppStatsResponse,
    release_channel: String,
    health_score: i32,
    last_incident_at: Option<String>,
    last_incident_type: Option<String>,
    uptime_percent: f64,
    features: JsonValue,
    supported_devices: JsonValue,
    bundle_id: Option<String>,
    store_url: Option<String>,
    environment: String,
    notes: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct AppVersionHistoryResponse {
    version: String,
    released_at: String,
    release_notes: String,
    api_version: String,
    rollout_percentage: i32,
    channel: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct AppDetailResponse {
    #[serde(flatten)]
    app: AppRecordResponse,
    version_history: Vec<AppVersionHistoryResponse>,
}

#[derive(Debug, Serialize)]
struct AppsOverviewResponse {
    total_registered_users: i64,
    total_users_online: i64,
    total_guests: i64,
    apps: Vec<AppRecordResponse>,
}

#[derive(Debug, Serialize)]
struct AppsListResponse {
    apps: Vec<AppRecordResponse>,
}

#[derive(Debug, Deserialize)]
struct AppListQuery {
    status: Option<String>,
    q: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAppPayload {
    display_name: Option<String>,
    description: Option<String>,
    status: Option<String>,
    update_policy: Option<String>,
    force_update_version: Option<String>,
    features: Option<JsonValue>,
    supported_devices: Option<JsonValue>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PushAppUpdatePayload {
    target_version: String,
    force: Option<bool>,
    rollout_percentage: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct BulkUpdateAppsPayload {
    platforms: Option<Vec<String>>,
    status: Option<String>,
    update_policy: Option<String>,
    api_version: Option<String>,
    features: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
struct BulkUpdateAppsResponse {
    updated: i64,
    message: String,
}

#[derive(Debug, Serialize)]
struct AnalyticsSeriesResponse {
    data: Vec<AnalyticsSeriesPointResponse>,
}

#[derive(Debug, Serialize)]
struct AnalyticsSeriesPointResponse {
    date: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct RevenueAnalyticsSeriesResponse {
    data: Vec<RevenueAnalyticsSeriesPointResponse>,
}

#[derive(Debug, Serialize)]
struct RevenueAnalyticsSeriesPointResponse {
    date: String,
    amount: f64,
}

#[derive(Debug, Serialize)]
struct AlertAnalyticsSeriesResponse {
    data: Vec<AlertAnalyticsSeriesPointResponse>,
}

#[derive(Debug, Serialize)]
struct AlertAnalyticsSeriesPointResponse {
    date: String,
    count: i64,
    critical: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceHealthAnalyticsResponse {
    online: i64,
    offline: i64,
    low_battery: i64,
    maintenance: i64,
}

#[derive(Debug, Serialize)]
struct RegionAnalyticsResponse {
    region: String,
    country: String,
    users: i64,
    devices: i64,
    patients: i64,
}

#[derive(Debug, Serialize)]
struct DeviceCategoryAnalyticsResponse {
    category: String,
    total: i64,
    active: i64,
    inactive: i64,
}

#[derive(Debug, Serialize)]
struct DeviceActivationTrendResponse {
    data: Vec<DeviceActivationTrendPointResponse>,
}

#[derive(Debug, Serialize)]
struct DeviceActivationTrendPointResponse {
    date: String,
    activations: i64,
    deactivations: i64,
}

#[derive(Debug, Serialize)]
struct TierDistributionAnalyticsResponse {
    tier: String,
    count: i64,
}

#[derive(Debug, Deserialize)]
struct AnalyticsPeriodQuery {
    period: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SupportTicketsQuery {
    page: Option<u32>,
    limit: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SupportTicketReplyBody {
    message: String,
}

#[derive(Debug, Deserialize)]
struct SupportTicketStatusBody {
    status: String,
}

#[derive(Debug, Clone, Serialize)]
struct SupportTicketReplyResponse {
    author: String,
    message: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct SupportTicketAttachmentResponse {
    id: String,
    filename: String,
    size: i64,
    mime_type: String,
    uploaded_by: String,
    uploaded_at: i64,
    url: String,
}

#[derive(Debug, Serialize)]
struct SupportTicketResponse {
    ticket_id: String,
    user_id: String,
    user_name: Option<String>,
    user_email: Option<String>,
    subject: String,
    message: String,
    status: String,
    priority: Option<String>,
    category: Option<String>,
    assigned_to: Option<String>,
    assigned_name: Option<String>,
    created_at: i64,
    updated_at: i64,
    replies: Vec<SupportTicketReplyResponse>,
    attachments: Vec<SupportTicketAttachmentResponse>,
}

#[derive(Debug, Serialize)]
struct SupportTicketsListResponse {
    data: Vec<SupportTicketResponse>,
    page: u32,
    limit: u32,
    total: i64,
    total_pages: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSupportTicketBody {
    user_id: String,
    subject: String,
    message: String,
    priority: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentMetaBody {
    filename: String,
    size: i64,
    mime_type: String,
    url: String,
    uploaded_by: String,
}

#[derive(Debug, Serialize)]
struct SupportSummaryResponse {
    open_tickets: i64,
    closed_tickets: i64,
    total_tickets: i64,
}

#[derive(Debug, Serialize)]
struct AdminPingResponse {
    status: &'static str,
    surface: &'static str,
}

#[derive(Debug, Deserialize)]
struct SendNotificationBody {
    user_id: String,
    channel: String,
    destination: String,
    subject: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct SendNotificationApiResponse {
    delivered: bool,
    provider_used: String,
    attempted_providers: Vec<String>,
    failure_reason: String,
}

#[derive(Debug, Deserialize)]
struct UpsertEmailTemplateBody {
    subject_template: String,
    html_template: String,
    updated_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmailTemplateResponse {
    name: String,
    trigger_endpoints: Vec<String>,
    description: String,
    subject_template: String,
    html_template: String,
    placeholders: Vec<String>,
    created_at: i64,
    updated_at: i64,
    updated_by: String,
}

#[derive(Debug, Serialize)]
struct EmailTemplateListResponse {
    templates: Vec<EmailTemplateResponse>,
    page: AuditLogsPageResponse,
}

#[derive(Debug, Deserialize)]
struct EmailTemplatesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenderTemplateBody {
    #[serde(default)]
    variables: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct RenderTemplateResponse {
    name: String,
    subject: String,
    html: String,
}

#[derive(Debug, Deserialize)]
struct SendTemplatedEmailBody {
    user_id: String,
    destination: String,
    template_name: String,
    #[serde(default)]
    variables: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SendTemplatedEmailResponse {
    delivered: bool,
    provider_used: String,
    attempted_providers: Vec<String>,
    failure_reason: String,
    template_name: String,
    rendered_subject: String,
}

#[derive(Debug, Serialize)]
struct EmailTemplateMappingsResponse {
    mappings: Vec<EmailTemplateMappingItem>,
}

#[derive(Debug, Serialize)]
struct EmailTemplateMappingItem {
    template_name: String,
    trigger_endpoint: String,
    description: String,
}

pub fn router(state: AppState) -> Router {
    let public_router = Router::new()
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/openapi/control-v1.json", get(openapi_control))
        .route("/health", get(health))
        .route("/v1/system/bootstrap/superadmin", post(bootstrap_superadmin));

    let control_router = Router::new()
        .route("/v1/system/ping", get(admin_ping))
        .route(
            "/v1/system/users",
            post(create_managed_user).get(list_managed_users),
        )
        .route(
            "/v1/system/auditors",
            post(create_auditor).get(list_auditors),
        )
        .route("/v1/system/auditors/:id", delete(revoke_auditor))
        .route(
            "/v1/system/auditors/:id/reset-password",
            post(reset_auditor_password),
        )
        .route("/v1/system/dashboard/summary", get(get_dashboard_summary))
        .route("/v1/system/apps/overview", get(get_apps_overview))
        .route("/v1/system/apps", get(list_apps))
        .route(
            "/v1/system/apps/:platform",
            get(get_app).patch(update_app),
        )
        .route("/v1/system/apps/:platform/stats", get(get_app_stats))
        .route(
            "/v1/system/apps/:platform/push-update",
            post(push_app_update),
        )
        .route("/v1/system/apps/bulk-update", post(bulk_update_apps))
        .route("/v1/system/analytics/stats", get(get_platform_stats))
        .route("/v1/system/analytics/user-growth", get(get_user_growth))
        .route("/v1/system/analytics/revenue", get(get_revenue_stats))
        .route("/v1/system/analytics/regions", get(get_region_stats))
        .route(
            "/v1/system/analytics/tier-distribution",
            get(get_tier_distribution),
        )
        .route("/v1/system/support/tickets", get(list_support_tickets).post(create_support_ticket))
        .route("/v1/system/support/tickets/:id", get(get_support_ticket))
        .route(
            "/v1/system/support/tickets/:id/reply",
            post(reply_support_ticket),
        )
        .route(
            "/v1/system/support/tickets/:id/attachments",
            post(record_support_attachment),
        )
        .route(
            "/v1/system/support/tickets/:id/status",
            axum::routing::patch(update_support_ticket_status),
        )
        .route("/v1/system/support/summary", get(get_support_summary))
        .route(
            "/v1/system/users/:user_id",
            put(upsert_user).patch(update_managed_user).get(get_user),
        )
        .route("/v1/system/users/:user_id/status", put(update_managed_user_status))
        .route(
            "/v1/system/users/:user_id/email-verification",
            put(update_managed_user_email_verification),
        )
        .route(
            "/v1/system/users/:user_id/request-password-reset",
            post(request_managed_user_password_reset),
        )
        .route(
            "/v1/system/users/:user_id/temp-password",
            post(set_managed_user_temp_password),
        )
        .route("/v1/system/users/:user_id/anonymize", post(anonymize_managed_user))
        .route(
            "/v1/system/users/:user_id/effective-permissions",
            get(get_user_effective_permissions),
        )
        .route("/v1/system/roles/catalog", get(get_role_catalog))
        .route("/v1/system/roles/:user_id", post(grant_role).get(get_roles))
        .route("/v1/system/roles/:user_id/:role", axum::routing::delete(revoke_role))
        .route("/v1/system/scopes/catalog", get(get_scope_catalog))
        .route("/v1/system/scopes/:user_id/grant", post(grant_scope))
        .route(
            "/v1/system/scopes/:user_id",
            put(update_scopes).get(get_scopes),
        )
        .route("/v1/system/scopes/:user_id/:scope", axum::routing::delete(revoke_scope))
        .route(
            "/v1/system/feature-flags/:key",
            put(set_feature_flag).get(get_feature_flag),
        )
        .route(
            "/v1/system/billing/webhooks/ingest",
            post(ingest_billing_webhook),
        )
        .route(
            "/v1/system/billing/plans",
            get(list_billing_plans).post(create_billing_plan),
        )
        .route(
            "/v1/system/billing/plans/:plan_id",
            get(get_billing_plan)
                .patch(update_billing_plan)
                .delete(delete_billing_plan),
        )
        .route(
            "/v1/system/billing/subscriptions",
            get(list_billing_subscriptions).post(create_billing_subscription),
        )
        .route(
            "/v1/system/billing/subscriptions/:subscription_id",
            get(get_billing_subscription).patch(update_billing_subscription),
        )
        .route(
            "/v1/system/settings/invoice",
            get(get_invoice_settings).put(upsert_invoice_settings),
        )
        .route(
            "/v1/system/settings/device-config",
            get(get_device_config).put(upsert_device_config),
        )
        .route(
            "/v1/system/settings/api-integrations",
            get(get_api_integration_settings).put(upsert_api_integration_settings),
        )
        .route("/v1/system/billing/refunds", post(refund_transaction))
        .route(
            "/v1/system/billing/transactions",
            get(list_billing_transactions),
        )
        .route("/v1/system/billing/invoices", get(list_billing_invoices))
        .route(
            "/v1/system/billing/ledger",
            get(list_billing_ledger_entries),
        )
        .route("/v1/system/audit-logs", get(list_audit_logs))
        .route("/v1/system/audit-logs/:event_id", get(get_audit_log))
        .route("/v1/system/sessions", get(list_system_sessions))
        .route(
            "/v1/system/sessions/:session_id/revoke",
            post(revoke_system_session),
        )
        .route(
            "/v1/system/api-clients/policies",
            get(list_api_client_policies),
        )
        .route(
            "/v1/system/api-clients",
            get(list_api_clients).post(create_api_client),
        )
        .route(
            "/v1/system/api-clients/ref/:client_ref",
            get(get_api_client_by_ref),
        )
        .route(
            "/v1/system/api-clients/:id",
            get(get_api_client_by_id).patch(update_api_client),
        )
        .route(
            "/v1/system/api-clients/:id/status",
            post(set_api_client_status),
        )
        .route(
            "/v1/system/api-clients/:id/rotate-secret",
            post(rotate_api_client_secret),
        )
        .route(
            "/v1/system/api-clients/:id/events",
            get(list_api_client_events),
        )
        .route(
            "/v1/system/notification-templates/email",
            get(list_email_templates),
        )
        .route(
            "/v1/system/notification-templates/email/mappings",
            get(get_email_template_mappings),
        )
        .route(
            "/v1/system/notification-templates/email/:name",
            put(upsert_email_template)
                .get(get_email_template)
                .delete(delete_email_template),
        )
        .route(
            "/v1/system/notification-templates/email/:name/render",
            post(render_email_template),
        )
        .route("/v1/system/notifications/send", post(send_notification))
        .route(
            "/v1/system/notifications/send-templated/email",
            post(send_templated_email),
        )
        .route(
            "/v1/system/organizations",
            get(list_organizations).post(create_organization),
        )
        .route(
            "/v1/system/organizations/:id",
            get(get_organization).patch(update_organization),
        )
        .route(
            "/v1/system/organizations/:id/verify",
            axum::routing::patch(verify_organization),
        )
        .route(
            "/v1/system/organizations/:id/professionals",
            get(list_organization_professionals),
        )
        .route(
            "/v1/system/professionals",
            get(list_professionals).post(create_professional),
        )
        .route(
            "/v1/system/professionals/:id",
            get(get_professional).patch(update_professional),
        )
        .route(
            "/v1/system/professionals/:id/verify",
            axum::routing::patch(verify_professional),
        )
        .route("/v1/system/regions", get(list_regions).post(create_region))
        .route(
            "/v1/system/regions/test-connection",
            post(test_region_connection),
        )
        .route(
            "/v1/system/regions/:id",
            get(get_region).patch(update_region),
        )
        .route(
            "/v1/system/regions/:id/rotate-keys",
            post(rotate_region_keys),
        )
        .route(
            "/v1/system/regions/:id/sync",
            post(sync_region),
        )
        .route(
            "/v1/system/internal/regions/:id/credentials",
            get(get_region_credentials),
        )
        .route("/v1/system/dashboard/activity", get(dashboard_activity))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_control_authz,
        ));

    let regional_system_router = Router::new()
        // Device Categories
        .route(
            "/v1/system/device-categories",
            get(list_device_categories).post(create_device_category),
        )
        .route(
            "/v1/system/device-categories/:id",
            get(get_device_category)
                .patch(update_device_category)
                .delete(delete_device_category),
        )
        // Device Models
        .route(
            "/v1/system/device-models",
            get(list_device_models).post(create_device_model),
        )
        .route(
            "/v1/system/device-models/:id",
            get(get_device_model)
                .patch(update_device_model)
                .delete(delete_device_model),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_control_authz,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit_control_mutations,
        ))
        .layer(axum::middleware::from_fn(::middleware::inject_request_id))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_system_client_authz,
        ));

    Router::new()
        .merge(public_router)
        .merge(control_router)
        .merge(regional_system_router)
        .with_state(state)
}

async fn swagger_ui() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Wildon Control API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/openapi/control-v1.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
      });
    </script>
  </body>
</html>"##,
    )
}

async fn openapi_control() -> impl axum::response::IntoResponse {
    (
        [(CONTENT_TYPE, "application/json; charset=utf-8")],
        CONTROL_OPENAPI_JSON,
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn admin_ping() -> Json<AdminPingResponse> {
    Json(AdminPingResponse {
        status: "ok",
        surface: "control",
    })
}

async fn build_dashboard_summary(state: &AppState) -> ControlDashboardResponse {
    let summary = {
        let data = state.data.lock().await;
        dashboard::summarize(&data)
    };

    let total_users = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM auth.users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
        .max(0) as u64;
    let active_users = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM users_app.users
         WHERE LOWER(COALESCE(status, 'active')) = 'active'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(summary.active_users as i64)
    .max(0) as u64;
    let total_patients: u64 = 0;
    let active_patients: u64 = 0;
    let total_devices: u64 = 0;
    let active_devices: u64 = 0;
    let total_alerts: u64 = 0;
    let critical_alerts: u64 = 0;

    // TODO: delegate to billing-service stats endpoint when one exists
    let revenue_monthly = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM billing_app.invoices
         WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0)
    .max(0);

    let revenue_yearly = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM billing_app.invoices
         WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '1 year'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0)
    .max(0);

    ControlDashboardResponse {
        total_users,
        active_users,
        total_patients,
        active_patients,
        total_devices,
        active_devices,
        total_alerts,
        critical_alerts,
        revenue: ControlDashboardRevenueResponse {
            monthly: revenue_monthly,
            yearly: revenue_yearly,
        },
        managed_users: summary.managed_users,
        total_role_bindings: summary.total_role_bindings,
        revenue_cents_24h: summary.revenue_cents_24h,
        active_subscriptions: summary.active_subscriptions,
        generated_at: summary.generated_at,
    }
}

async fn get_dashboard_summary(State(state): State<AppState>) -> Json<ControlDashboardResponse> {
    Json(build_dashboard_summary(&state).await)
}

async fn get_platform_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ControlDashboardResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;
    Ok(Json(build_dashboard_summary(&state).await))
}

async fn get_user_growth(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AnalyticsPeriodQuery>,
) -> Result<Json<AnalyticsSeriesResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;
    let data = load_count_series(
        &state,
        query.period.as_deref(),
        "auth.users",
        "created_at",
        None,
    )
    .await?;
    Ok(Json(AnalyticsSeriesResponse { data }))
}

async fn get_revenue_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AnalyticsPeriodQuery>,
) -> Result<Json<RevenueAnalyticsSeriesResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;

    let (mode, buckets) = analytics_period_spec(query.period.as_deref());
    let bucket_labels = analytics_bucket_labels(mode, buckets);
    let mut totals = bucket_labels
        .iter()
        .map(|label| (label.clone(), 0_f64))
        .collect::<HashMap<_, _>>();

    let window_start = analytics_window_start(mode, buckets);
    let mut cursor = String::new();
    for _ in 0..20 {
        let response = {
            let mut billing_client = state.billing_client.lock().await;
            let mut request = GrpcRequest::new(ListTransactionsRequest {
                user_id: String::new(),
                limit: 500,
                cursor: cursor.clone(),
            });
            let _ = inject_internal_metadata(&mut request, "control-service", None, None);
            billing_client
                .list_transactions(request)
                .await
                .map_err(|err| (StatusCode::BAD_GATEWAY, format!("billing grpc error: {err}")))?
                .into_inner()
        };

        for tx in response.transactions {
            if tx.created_at < window_start.timestamp() {
                continue;
            }
            if let Some(label) = analytics_bucket_label_from_unix(mode, tx.created_at) {
                let cents = (tx.amount_cents - tx.refunded_amount_cents).max(0) as f64;
                let current = totals.entry(label).or_insert(0.0);
                *current += cents / 100.0;
            }
        }

        if !response.has_more || response.next_cursor.trim().is_empty() {
            break;
        }
        cursor = response.next_cursor;
    }

    let data = bucket_labels
        .into_iter()
        .map(|label| RevenueAnalyticsSeriesPointResponse {
            amount: *totals.get(&label).unwrap_or(&0.0),
            date: label,
        })
        .collect::<Vec<_>>();

    Ok(Json(RevenueAnalyticsSeriesResponse { data }))
}

async fn get_region_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<RegionAnalyticsResponse>>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;

    let rows = sqlx::query(
        "SELECT name, country,
                COALESCE(total_users, 0) AS total_users,
                COALESCE(total_devices, 0) AS total_devices
         FROM control_app.regions
         ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let data = rows
        .into_iter()
        .map(|row| RegionAnalyticsResponse {
            region: row.get::<String, _>("name"),
            country: row.get::<String, _>("country"),
            users: row.get::<i64, _>("total_users"),
            devices: row.get::<i64, _>("total_devices"),
            patients: 0,
        })
        .collect();

    Ok(Json(data))
}

async fn get_tier_distribution(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<TierDistributionAnalyticsResponse>>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;

    let rows = sqlx::query(
        "WITH tiered_users AS (
             SELECT u.id,
                    CASE
                        WHEN s.user_id IS NULL THEN 'free'
                        WHEN LOWER(s.plan_key) LIKE '%enterprise%' THEN 'enterprise'
                        WHEN LOWER(s.plan_key) LIKE '%pro%' THEN 'pro'
                        WHEN LOWER(s.plan_key) LIKE '%basic%' THEN 'basic'
                        ELSE 'free'
                    END AS tier
             FROM auth.users u
             LEFT JOIN billing_app.subscriptions s
               ON s.user_id = u.id
              AND LOWER(s.status) IN ('active', 'trial', 'trialing', 'past_due')
         )
         SELECT tier, COUNT(*)::bigint AS count
         FROM tiered_users
         GROUP BY tier",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let mut counts = HashMap::from([
        ("free".to_string(), 0_i64),
        ("basic".to_string(), 0_i64),
        ("pro".to_string(), 0_i64),
        ("enterprise".to_string(), 0_i64),
    ]);

    for row in rows {
        let tier = row.get::<String, _>("tier");
        let count = row.get::<i64, _>("count");
        if let Some(slot) = counts.get_mut(&tier) {
            *slot = count;
        }
    }

    let data = ["free", "basic", "pro", "enterprise"]
        .into_iter()
        .map(|tier| TierDistributionAnalyticsResponse {
            tier: tier.to_string(),
            count: counts.get(tier).copied().unwrap_or(0),
        })
        .collect();

    Ok(Json(data))
}

async fn enforce_control_authz(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS
        || request.uri().path() == "/health"
        || request.uri().path() == "/docs"
        || request.uri().path() == "/docs/"
        || request.uri().path() == "/openapi/control-v1.json"
    {
        return next.run(request).await;
    }

    if !is_allowed_control_host(
        &state,
        request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
    ) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    if request.uri().path() == "/v1/system/bootstrap/superadmin" {
        let expected_token = state.bootstrap_token.trim();
        if !expected_token.is_empty() {
            let provided = request
                .headers()
                .get("x-bootstrap-token")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .unwrap_or_default();
            if provided != expected_token {
                return (StatusCode::UNAUTHORIZED, "invalid bootstrap token").into_response();
            }
        }
        return next.run(request).await;
    }

    let header_value = match request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value,
        None => return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response(),
    };

    let claims = match jwt::parse_bearer_header(header_value) {
        Ok(claims) => claims,
        Err(err) => {
            return (StatusCode::UNAUTHORIZED, format!("invalid token: {err}")).into_response()
        }
    };

    if let Err(err) = jwt::validate_claims(&claims) {
        return (StatusCode::UNAUTHORIZED, format!("invalid claims: {err}")).into_response();
    }
    if claims.iss != state.expected_issuer {
        return (StatusCode::UNAUTHORIZED, "invalid issuer").into_response();
    }
    if claims.aud != "control" || claims.realm != "control" {
        return (
            StatusCode::FORBIDDEN,
            "token audience/realm must be control".to_string(),
        )
            .into_response();
    }
    if !claims
        .roles
        .iter()
        .any(|role| matches!(role.as_str(), "manager" | "auditor" | "admin" | "superadmin"))
    {
        return (
            StatusCode::FORBIDDEN,
            "role is not allowed for control surface".to_string(),
        )
            .into_response();
    }

    request.extensions_mut().insert(claims);
    next.run(request).await
}

async fn audit_control_mutations(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if should_skip_control_route(path.as_str()) {
        return next.run(request).await;
    }
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0.clone())
        .or_else(|| header_value(request.headers(), "x-request-id"));
    let traceparent = header_value(request.headers(), "traceparent");
    let host = header_value(request.headers(), "host");
    let user_agent = header_value(request.headers(), "user-agent");
    let forwarded_for = header_value(request.headers(), "x-forwarded-for");
    let claims = request
        .extensions()
        .get::<Claims>()
        .cloned()
        .or_else(|| parse_control_claims(request.headers()));

    let response = next.run(request).await;
    let status = response.status();
    if !should_capture_control(&method, status, matched_path.as_str()) {
        return response;
    }

    let actor_user_id = claims.as_ref().map(|value| value.sub.clone());
    let action = classify_control_action(status);
    let audit_user_id = actor_user_id
        .clone()
        .unwrap_or_else(|| "bootstrap".to_string());
    let payload_json = serde_json::json!({
        "layer": "http",
        "service": "control-service",
        "method": method.as_str(),
        "path": path,
        "matched_path": matched_path,
        "status_code": status.as_u16(),
        "success": status.is_success(),
        "request_id": request_id,
        "host": host,
        "user_agent": user_agent,
        "forwarded_for": forwarded_for,
        "reason": denial_reason(status),
        "actor": {
            "user_id": actor_user_id,
            "roles": claims.as_ref().map(|value| value.roles.clone()).unwrap_or_default(),
            "scopes": claims.as_ref().map(|value| value.scopes.clone()).unwrap_or_default(),
            "audience": claims.as_ref().map(|value| value.aud.clone()).unwrap_or_default(),
            "realm": claims.as_ref().map(|value| value.realm.clone()).unwrap_or_default(),
            "authenticated": claims.is_some(),
            "session_id": claims.and_then(|value| value.sid.clone()).unwrap_or_default(),
        },
    })
    .to_string();

    tokio::spawn(async move {
        publish_control_audit(
            state,
            request_id,
            traceparent,
            audit_user_id,
            action,
            matched_path,
            payload_json,
        )
        .await;
    });

    response
}

async fn publish_control_audit(
    state: AppState,
    request_id: Option<String>,
    traceparent: Option<String>,
    user_id: String,
    action: String,
    resource_id: String,
    payload_json: String,
) {
    let actor_type = if user_id == "bootstrap" {
        AuditActorType::System
    } else {
        AuditActorType::User
    };
    let actor_role = if user_id == "bootstrap" {
        "system"
    } else {
        "admin"
    };
    let result = if action.ends_with(".denied") {
        AuditResult::Denied
    } else if action.ends_with(".failed") {
        AuditResult::Failure
    } else {
        AuditResult::Success
    };
    let mut request = GrpcRequest::new(
        AuditEventBuilder::new("control-service", action, "route", resource_id.clone())
            .event_id(Uuid::new_v4().to_string())
            .actor(actor_type, user_id, actor_role, AuditAuthMechanism::Jwt)
            .context(
                request_id.as_deref(),
                traceparent.as_deref(),
                None,
                None,
                None,
                None,
                Some(resource_id.as_str()),
                None,
                AuditAccessPurpose::Audit,
            )
            .result(result)
            .sensitivity(infer_control_sensitivity(
                resource_id.as_str(),
                payload_json.as_str(),
            ))
            .metadata_json(payload_json)
            .into_ingest_request(),
    );

    if let Err(err) = inject_internal_metadata(
        &mut request,
        "control-service",
        request_id.as_deref(),
        traceparent.as_deref(),
    ) {
        tracing::warn!(error = %err, resource_id = resource_id, "failed to build control audit metadata");
        return;
    }

    let mut logs_client = state.logs_client.lock().await;
    if let Err(err) = logs_client.ingest_audit(request).await {
        tracing::warn!(error = %err, resource_id = resource_id, "failed to publish control audit event");
    }
}

fn should_audit_control_route(method: &Method, path: &str) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && !should_skip_control_route(path)
}

fn should_skip_control_route(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/docs" | "/docs/" | "/openapi/control-v1.json"
    )
}

fn should_capture_control(method: &Method, status: StatusCode, path: &str) -> bool {
    should_audit_control_route(method, path)
        || matches!(
            status,
            StatusCode::BAD_REQUEST
                | StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::TOO_MANY_REQUESTS
        )
}

fn action_suffix(path: &str) -> String {
    let mut normalized = String::new();
    let mut last_separator = false;

    for ch in path.trim_matches('/').chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_separator = false;
        } else if !last_separator {
            normalized.push('.');
            last_separator = true;
        }
    }

    let normalized = normalized.trim_matches('.').to_string();
    if normalized.is_empty() {
        "root".to_string()
    } else {
        normalized
    }
}

fn classify_control_action(status: StatusCode) -> String {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        "control.request.denied".to_string()
    } else if status.is_client_error() || status.is_server_error() {
        "control.request.failed".to_string()
    } else {
        "control.request.completed".to_string()
    }
}

fn denial_reason(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "malformed_request",
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "permission_denied",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        _ => "",
    }
}

fn parse_control_claims(headers: &axum::http::HeaderMap) -> Option<Claims> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| jwt::parse_bearer_header(value).ok())
}

fn infer_control_sensitivity(resource_id: &str, payload_json: &str) -> AuditDataSensitivityLevel {
    let marker = format!("{resource_id} {payload_json}").to_ascii_lowercase();
    if marker.contains("audit") || marker.contains("auditor") || marker.contains("billing") {
        AuditDataSensitivityLevel::Critical
    } else {
        AuditDataSensitivityLevel::Sensitive
    }
}

fn header_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

async fn consume_control_rate_limit(
    conn: &mut redis::aio::MultiplexedConnection,
    key: &str,
    limit: i64,
    window_seconds: i64,
) -> redis::RedisResult<bool> {
    let count = conn.incr::<_, _, i64>(key, 1).await?;
    if count == 1 {
        let _ = conn.expire::<_, bool>(key, window_seconds).await?;
    }
    Ok(count <= limit)
}

fn is_auditor_claims(claims: &Claims) -> bool {
    claims.roles.iter().any(|role| role == "auditor")
}

fn ensure_scope_or_auditor_read(
    claims: &Claims,
    required: &str,
) -> Result<(), (StatusCode, String)> {
    if is_auditor_claims(claims) && claims.scopes.iter().any(|scope| scope == "audit_only") {
        return Ok(());
    }
    ensure_scope(claims, required)
}

fn extract_request_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    for header in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers.get(header).and_then(|value| value.to_str().ok()) {
            if let Some(ip) = value
                .split(',')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Some(ip.to_string());
            }
        }
    }
    None
}

fn validate_allowed_ip_entry(value: &str) -> Result<(), String> {
    if value.contains('/') {
        value
            .parse::<IpNet>()
            .map(|_| ())
            .map_err(|_| format!("invalid allowed_ips entry '{value}'"))
    } else {
        IpAddr::from_str(value)
            .map(|_| ())
            .map_err(|_| format!("invalid allowed_ips entry '{value}'"))
    }
}

fn normalize_allowed_ips(values: Option<Vec<String>>) -> Result<Option<Vec<String>>, String> {
    let Some(values) = values else {
        return Ok(None);
    };

    let mut normalized = Vec::new();
    for value in values {
        let candidate = value.trim();
        if candidate.is_empty() {
            continue;
        }
        validate_allowed_ip_entry(candidate)?;
        normalized.push(candidate.to_string());
    }
    normalized.sort();
    normalized.dedup();

    if normalized.is_empty() {
        Ok(None)
    } else {
        Ok(Some(normalized))
    }
}

fn parse_allowed_ips_json(
    value: Option<JsonValue>,
) -> Result<Option<Vec<String>>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value.as_array().ok_or((
        StatusCode::BAD_GATEWAY,
        "audit_accounts.allowed_ips must be a JSON array".to_string(),
    ))?;
    let mut allowed = Vec::with_capacity(items.len());
    for item in items {
        let candidate = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or((
                StatusCode::BAD_GATEWAY,
                "audit_accounts.allowed_ips entries must be strings".to_string(),
            ))?;
        validate_allowed_ip_entry(candidate).map_err(|err| (StatusCode::BAD_GATEWAY, err))?;
        allowed.push(candidate.to_string());
    }
    Ok(if allowed.is_empty() {
        None
    } else {
        Some(allowed)
    })
}

fn ip_matches_any_allowed(ip: &str, allowed_ips: &[String]) -> bool {
    let Ok(request_ip) = IpAddr::from_str(ip.trim()) else {
        return false;
    };
    allowed_ips.iter().any(|candidate| {
        let candidate = candidate.trim();
        if candidate.contains('/') {
            candidate
                .parse::<IpNet>()
                .map(|network| network.contains(&request_ip))
                .unwrap_or(false)
        } else {
            IpAddr::from_str(candidate)
                .map(|allowed| allowed == request_ip)
                .unwrap_or(false)
        }
    })
}

async fn enforce_system_client_authz(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    if !is_allowed_control_host(
        &state,
        request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
    ) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    if request.headers().contains_key(AUTHORIZATION) {
        return system_api_error_response(
            StatusCode::FORBIDDEN,
            "JWT_NOT_ALLOWED",
            "user JWTs are not allowed on /v1/system device endpoints",
            None,
        );
    }

    let request_id = match required_header(request.headers(), "x-request-id") {
        Ok(value) => value.to_string(),
        Err(response) => return response,
    };
    let api_version = match required_header(request.headers(), "x-api-version") {
        Ok(value) => value.to_string(),
        Err(_) => {
            return system_api_error_response(
                StatusCode::BAD_REQUEST,
                "MISSING_API_VERSION",
                "missing X-API-Version header",
                Some(request_id),
            )
        }
    };
    if api_version != SYSTEM_API_VERSION {
        return system_api_error_response(
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED_API_VERSION",
            "unsupported API version",
            Some(request_id),
        );
    }

    let timestamp_raw = match required_header(request.headers(), "x-api-timestamp") {
        Ok(value) => value.to_string(),
        Err(_) => {
            return system_api_error_response(
                StatusCode::BAD_REQUEST,
                "MISSING_TIMESTAMP",
                "missing X-API-Timestamp header",
                Some(request_id),
            )
        }
    };
    let public_key = match required_header(request.headers(), "x-api-key") {
        Ok(value) => value.to_string(),
        Err(_) => {
            return system_api_error_response(
                StatusCode::UNAUTHORIZED,
                "MISSING_API_KEY",
                "missing X-API-Key header",
                Some(request_id),
            )
        }
    };
    let signature = match required_header(request.headers(), "x-api-signature") {
        Ok(value) => value.to_string(),
        Err(_) => {
            return system_api_error_response(
                StatusCode::UNAUTHORIZED,
                "MISSING_SIGNATURE",
                "missing X-API-Signature header",
                Some(request_id),
            )
        }
    };
    let nonce = request
        .headers()
        .get("x-api-nonce")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let idempotency_key = request
        .headers()
        .get("x-idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let timestamp = match timestamp_raw.parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            return system_api_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_TIMESTAMP",
                "invalid X-API-Timestamp header",
                Some(request_id),
            )
        }
    };
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > SYSTEM_API_MAX_SKEW_SECONDS {
        return system_api_error_response(
            StatusCode::UNAUTHORIZED,
            "STALE_TIMESTAMP",
            "request timestamp is outside the allowed clock skew window",
            Some(request_id),
        );
    }

    if is_mutating_system_method(request.method()) && nonce.is_none() {
        return system_api_error_response(
            StatusCode::BAD_REQUEST,
            "MISSING_NONCE",
            "missing X-API-Nonce header",
            Some(request_id),
        );
    }

    if requires_idempotency_key(request.method(), request.uri().path()) && idempotency_key.is_none() {
        return system_api_error_response(
            StatusCode::BAD_REQUEST,
            "MISSING_IDEMPOTENCY_KEY",
            "missing X-Idempotency-Key header",
            Some(request_id),
        );
    }

    let auth_record = match fetch_system_api_client(&state, &public_key).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return system_api_error_response(
                StatusCode::UNAUTHORIZED,
                "UNKNOWN_API_KEY",
                "system API client not found",
                Some(request_id),
            )
        }
        Err(_) => {
            return system_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_LOOKUP_FAILED",
                "failed to validate system API client",
                Some(request_id),
            )
        }
    };

    let body = std::mem::take(request.body_mut());
    let body_bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return system_api_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_BODY",
                "failed to read request body",
                Some(request_id),
            )
        }
    };
    let canonical_body = match canonical_body_from_bytes(request.headers(), &body_bytes) {
        Ok(value) => value,
        Err(message) => {
            return system_api_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_BODY",
                &message,
                Some(request_id),
            )
        }
    };
    let path_with_query = canonical_path_with_query(request.uri());
    let payload = build_system_signature_payload(
        &timestamp_raw,
        request.method().as_str(),
        &path_with_query,
        &canonical_body,
        nonce.as_deref().unwrap_or(""),
        &api_version,
    );
    if !verify_system_signature(&auth_record.secret_key, &payload, &signature) {
        return system_api_error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIGNATURE",
            "system API signature validation failed",
            Some(request_id),
        );
    }

    if let Some(nonce_value) = nonce.as_deref() {
        let nonce_result = store_system_nonce(
            &state,
            auth_record.id,
            nonce_value,
            &request_id,
            request.method().as_str(),
            request.uri().path(),
        )
        .await;
        match nonce_result {
            Ok(true) => {}
            Ok(false) => {
                return system_api_error_response(
                    StatusCode::FORBIDDEN,
                    "REPLAYED_NONCE",
                    "request nonce has already been used",
                    Some(request_id),
                )
            }
            Err(_) => {
                return system_api_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NONCE_STORE_FAILED",
                    "failed to validate request nonce",
                    Some(request_id),
                )
            }
        }
    }

    let request_hash = sha256_hex(&canonical_body);
    if let Some(key) = idempotency_key.as_deref() {
        match fetch_idempotent_response(&state, auth_record.id, request.uri().path(), key).await {
            Ok(Some((stored_hash, status, body))) => {
                if stored_hash != request_hash {
                    return system_api_error_response(
                        StatusCode::CONFLICT,
                        "IDEMPOTENCY_CONFLICT",
                        "idempotency key has already been used with a different request body",
                        Some(request_id),
                    );
                }
                let mut response = (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), Json(body))
                    .into_response();
                if let Ok(value) = request_id.parse() {
                    response.headers_mut().insert("x-request-id", value);
                }
                return response;
            }
            Ok(None) => {}
            Err(_) => {
                return system_api_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "IDEMPOTENCY_LOOKUP_FAILED",
                    "failed to validate idempotency key",
                    Some(request_id),
                )
            }
        }
    }

    let _ = sqlx::query(
        "UPDATE control_app.system_api_clients
         SET last_used_at = NOW(), updated_at = NOW()
         WHERE id = $1",
    )
    .bind(auth_record.id)
    .execute(&state.db)
    .await;

    let endpoint_path = request.uri().path().to_string();
    request.extensions_mut().insert(SystemApiClientContext {
        client_id: auth_record.id,
        public_key: auth_record.public_key,
        scopes: auth_record.scopes,
        request_id: request_id.clone(),
    });
    request.extensions_mut().insert(SystemApiRequestMeta {
        request_id: request_id.clone(),
        endpoint: endpoint_path,
        request_hash,
        idempotency_key,
    });
    *request.body_mut() = Body::from(body_bytes);

    let mut response = next.run(request).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn system_api_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: Option<String>,
) -> Response {
    (
        status,
        Json(SystemApiErrorEnvelope {
            error: SystemApiErrorBody {
                code: code.to_string(),
                message: message.to_string(),
                request_id,
            },
        }),
    )
        .into_response()
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Response> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            system_api_error_response(
                StatusCode::BAD_REQUEST,
                "MISSING_HEADER",
                &format!("missing required header: {name}"),
                None,
            )
        })
}

fn is_mutating_system_method(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
}

fn requires_idempotency_key(method: &Method, path: &str) -> bool {
    *method == Method::POST && matches!(path, "/v1/system/devices" | "/v1/system/devices/bulk")
}

fn canonical_path_with_query(uri: &axum::http::Uri) -> String {
    let path = uri.path();
    let Some(query) = uri.query() else {
        return path.to_string();
    };
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut iter = segment.splitn(2, '=');
            (
                iter.next().unwrap_or_default().to_string(),
                iter.next().unwrap_or_default().to_string(),
            )
        })
        .collect();
    parts.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    if parts.is_empty() {
        return path.to_string();
    }
    let serialized = parts
        .into_iter()
        .map(|(key, value)| {
            if value.is_empty() {
                key
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{serialized}")
}

fn build_system_signature_payload(
    timestamp: &str,
    method: &str,
    path_with_query: &str,
    canonical_body: &str,
    nonce: &str,
    api_version: &str,
) -> String {
    format!(
        "{timestamp}\n{}\n{path_with_query}\n{canonical_body}\n{nonce}\n{api_version}",
        method.to_ascii_uppercase()
    )
}

fn canonical_body_from_bytes(
    headers: &HeaderMap,
    body_bytes: &[u8],
) -> Result<String, String> {
    if body_bytes.is_empty() {
        return Ok(String::new());
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if content_type.starts_with("application/json") {
        let value: JsonValue =
            serde_json::from_slice(body_bytes).map_err(|_| "request body is not valid JSON".to_string())?;
        return Ok(canonical_json_string(&value));
    }

    if content_type.starts_with("multipart/form-data") {
        return Ok(sha256_hex_bytes(body_bytes));
    }

    String::from_utf8(body_bytes.to_vec())
        .map_err(|_| "request body must be valid UTF-8".to_string())
}

fn canonical_json_string(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            serde_json::to_string(value).unwrap_or_default()
        }
        JsonValue::Array(items) => {
            let serialized = items
                .iter()
                .map(canonical_json_string)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{serialized}]")
        }
        JsonValue::Object(map) => {
            let mut items = map.iter().collect::<Vec<_>>();
            items.sort_by(|left, right| left.0.cmp(right.0));
            let serialized = items
                .into_iter()
                .map(|(key, item)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json_string(item)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{serialized}}}")
        }
    }
}

fn verify_system_signature(secret: &str, payload: &str, signature_hex: &str) -> bool {
    let Ok(expected_bytes) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok()
}

async fn fetch_system_api_client(
    state: &AppState,
    public_key: &str,
) -> Result<Option<SystemApiAuthRecord>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, public_key, secret_key, scopes
         FROM control_app.system_api_clients
         WHERE public_key = $1 AND status = 'active'
         LIMIT 1",
    )
    .bind(public_key)
    .fetch_optional(&state.db)
    .await?;

    Ok(row.map(|row| SystemApiAuthRecord {
        id: row.get("id"),
        public_key: row.get("public_key"),
        secret_key: row.get("secret_key"),
        scopes: row
            .get::<Vec<String>, _>("scopes")
            .into_iter()
            .collect::<HashSet<_>>(),
    }))
}

async fn store_system_nonce(
    state: &AppState,
    client_id: Uuid,
    nonce: &str,
    request_id: &str,
    method: &str,
    path: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query("DELETE FROM control_app.system_api_nonces WHERE expires_at < NOW()")
        .execute(&state.db)
        .await?;

    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(SYSTEM_API_NONCE_TTL_MINUTES);
    let result = sqlx::query(
        "INSERT INTO control_app.system_api_nonces
            (client_id, nonce, request_id, method, path, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT DO NOTHING",
    )
    .bind(client_id)
    .bind(nonce)
    .bind(request_id)
    .bind(method)
    .bind(path)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(result.rows_affected() > 0)
}

async fn fetch_idempotent_response(
    state: &AppState,
    client_id: Uuid,
    endpoint: &str,
    idempotency_key: &str,
) -> Result<Option<(String, u16, JsonValue)>, sqlx::Error> {
    sqlx::query("DELETE FROM control_app.system_api_idempotency WHERE expires_at < NOW()")
        .execute(&state.db)
        .await?;

    let row = sqlx::query(
        "SELECT request_hash, response_status, response_body
         FROM control_app.system_api_idempotency
         WHERE client_id = $1 AND endpoint = $2 AND idempotency_key = $3
         LIMIT 1",
    )
    .bind(client_id)
    .bind(endpoint)
    .bind(idempotency_key)
    .fetch_optional(&state.db)
    .await?;

    Ok(row.map(|row| {
        (
            row.get("request_hash"),
            row.get::<i32, _>("response_status") as u16,
            row.get("response_body"),
        )
    }))
}

async fn store_idempotent_response(
    state: &AppState,
    client_id: Uuid,
    endpoint: &str,
    idempotency_key: &str,
    request_hash: &str,
    response_status: StatusCode,
    response_body: &JsonValue,
) -> Result<(), sqlx::Error> {
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(SYSTEM_API_IDEMPOTENCY_TTL_HOURS);
    sqlx::query(
        "INSERT INTO control_app.system_api_idempotency
            (client_id, endpoint, idempotency_key, request_hash, response_status, response_body, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (client_id, endpoint, idempotency_key)
         DO UPDATE SET
            request_hash = EXCLUDED.request_hash,
            response_status = EXCLUDED.response_status,
            response_body = EXCLUDED.response_body,
            expires_at = EXCLUDED.expires_at",
    )
    .bind(client_id)
    .bind(endpoint)
    .bind(idempotency_key)
    .bind(request_hash)
    .bind(response_status.as_u16() as i32)
    .bind(response_body)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(())
}

fn is_allowed_control_host(state: &AppState, host_header: Option<&str>) -> bool {
    let Some(host_header) = host_header else {
        return false;
    };
    let host = host_header
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    state.allowed_hosts.contains(host.as_str())
}

async fn bootstrap_superadmin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<BootstrapSuperadminBody>,
) -> Result<Json<BootstrapSuperadminResponse>, (StatusCode, String)> {
    let expected_token = state.bootstrap_token.trim();
    if !expected_token.is_empty() {
        let provided = headers
            .get("x-bootstrap-token")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        if provided != expected_token {
            return Err((StatusCode::UNAUTHORIZED, "invalid bootstrap token".to_string()));
        }
    }

    let email = normalize_email(&payload.email).ok_or((
        StatusCode::BAD_REQUEST,
        "valid email is required".to_string(),
    ))?;
    let roles = vec!["superadmin".to_string()];
    let scopes = scope_names_to_strings(scope_catalog::role_default_scopes("superadmin"));

    let existing = sqlx::query_scalar::<_, String>(
        "SELECT value
         FROM control_app.service_bootstrap
         WHERE key = 'superadmin_user_id'
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    if let Some(existing_user_id) = existing {
        if Uuid::parse_str(existing_user_id.trim()).is_ok() {
            if let Some(row) = sqlx::query(
                "SELECT id::text AS user_id, email
                 FROM auth.users
                 WHERE id = $1::UUID
                 LIMIT 1",
            )
            .bind(existing_user_id.trim())
            .fetch_optional(&state.db)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?
            {
                let user_id: String = row.get("user_id");
                let stored_email: Option<String> = row.get("email");
                if let Some(stored_email) = &stored_email {
                    if !stored_email.eq_ignore_ascii_case(&email) {
                        return Err((
                            StatusCode::CONFLICT,
                            format!(
                                "superadmin already bootstrapped for different email: {stored_email}"
                            ),
                        ));
                    }
                }
                let canonical_email = stored_email.unwrap_or_else(|| email.clone());
                let user_uuid = Uuid::parse_str(&user_id).map_err(|_| {
                    (
                        StatusCode::BAD_GATEWAY,
                        "invalid bootstrap user_id state".to_string(),
                    )
                })?;

                ensure_users_identity(
                    &state,
                    user_uuid,
                    &canonical_email,
                    payload.first_name.clone().unwrap_or_default(),
                    payload.last_name.clone().unwrap_or_default(),
                    roles.clone(),
                    scopes.clone(),
                )
                .await?;

                record_control_cache_user(&state, &user_id, "active", &roles).await;
                return Ok(Json(BootstrapSuperadminResponse {
                    user_id,
                    email: canonical_email,
                    roles,
                    scopes,
                }));
            }
        }

        sqlx::query(
            "DELETE FROM control_app.service_bootstrap
             WHERE key = 'superadmin_user_id'",
        )
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    }

    if payload.password.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "password is required".to_string()));
    }
    validate_password_policy(&payload.password)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let user_id = Uuid::new_v4();

    create_auth_identity(&state, user_id, &email, &payload.password, true).await?;
    ensure_users_identity(
        &state,
        user_id,
        &email,
        payload.first_name.unwrap_or_default(),
        payload.last_name.unwrap_or_default(),
        roles.clone(),
        scopes.clone(),
    )
    .await?;

    sqlx::query(
        "INSERT INTO control_app.service_bootstrap (key, value)
         VALUES ('superadmin_user_id', $1)
         ON CONFLICT (key) DO UPDATE
         SET value = EXCLUDED.value, created_at = NOW()",
    )
    .bind(user_id.to_string())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    record_control_cache_user(&state, &user_id.to_string(), "active", &roles).await;

    Ok(Json(BootstrapSuperadminResponse {
        user_id: user_id.to_string(),
        email,
        roles,
        scopes,
    }))
}

async fn create_managed_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateManagedUserBody>,
) -> Result<Json<ManagedUserViewResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:add")?;

    let email = normalize_email(&payload.email).ok_or((
        StatusCode::BAD_REQUEST,
        "valid email is required".to_string(),
    ))?;
    validate_password_policy(&payload.password)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let mut roles = normalize_roles(payload.roles).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    if roles.is_empty() {
        roles.push("user".to_string());
    }
    validate_role_assignment_actor(&claims, &roles)?;

    let scopes = normalize_scopes(payload.scopes).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    validate_scope_assignment_actor(&claims, &scopes)?;

    let user_id = match payload.user_id {
        Some(raw) if !raw.trim().is_empty() => Uuid::parse_str(raw.trim()).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "user_id must be a valid UUID".to_string(),
            )
        })?,
        _ => Uuid::new_v4(),
    };

    let email_verified = payload.email_verified.unwrap_or(true);
    create_auth_identity(&state, user_id, &email, &payload.password, email_verified).await?;
    let full_name = compose_display_name(
        payload.first_name.as_deref(),
        payload.last_name.as_deref(),
        payload.display_name.as_deref(),
    );
    ensure_users_identity(
        &state,
        user_id,
        &email,
        payload.first_name.unwrap_or_default(),
        payload.last_name.unwrap_or_default(),
        roles.clone(),
        scopes.clone(),
    )
    .await?;

    if !full_name.is_empty() || payload.phone.as_deref().is_some() {
        update_user_settings_profile(
            &state,
            &user_id.to_string(),
            if full_name.is_empty() { None } else { Some(full_name) },
            payload.phone.clone(),
        )
        .await?;
    }

    if let Some(status) = payload.status.as_deref() {
        apply_user_status(&state, &user_id.to_string(), status).await?;
    }

    record_control_cache_user(&state, &user_id.to_string(), "active", &roles).await;

    let view = load_managed_user_view(&state, &user_id.to_string()).await?;
    audit_control(
        &state,
        &claims.sub,
        "user.created",
        serde_json::json!({ "user_id": user_id, "roles": roles }),
    )
    .await;
    Ok(Json(view))
}

async fn create_auditor(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    Json(payload): Json<CreateAuditorBody>,
) -> Result<Json<AuditorMutationResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;
    require_admin_or_superadmin(&claims)?;

    let email = normalize_email(&payload.email).ok_or((
        StatusCode::BAD_REQUEST,
        "valid email is required".to_string(),
    ))?;
    validate_password_policy(&payload.password)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let expires_at = parse_unix_timestamp(payload.expires_at, "expires_at")?;
    if expires_at <= chrono::Utc::now() {
        return Err((
            StatusCode::BAD_REQUEST,
            "expires_at must be in the future".to_string(),
        ));
    }
    let allowed_ips =
        normalize_allowed_ips(payload.allowed_ips).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let created_by = Uuid::parse_str(claims.sub.trim()).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "authenticated subject must be a valid UUID".to_string(),
        )
    })?;
    let user_id = Uuid::new_v4();
    let auditor_roles = vec!["auditor".to_string()];
    let auditor_scopes = vec!["audit_only".to_string()];

    create_auth_identity(&state, user_id, &email, &payload.password, true).await?;
    ensure_users_identity(
        &state,
        user_id,
        &email,
        "Auditor".to_string(),
        email.clone(),
        auditor_roles.clone(),
        auditor_scopes,
    )
    .await?;
    let account =
        insert_audit_account(&state, user_id, &email, created_by, expires_at, allowed_ips).await?;
    record_control_cache_user(&state, &user_id.to_string(), "active", &auditor_roles).await;

    emit_semantic_control_audit(
        state,
        Some(request_id.0.clone()),
        claims.sub.clone(),
        "auditor.created",
        account.id.to_string(),
        serde_json::json!({
            "auditor_id": account.id,
            "user_id": account.user_id,
            "email": account.email,
            "expires_at": account.expires_at.timestamp(),
            "allowed_ips": account.allowed_ips,
            "created_by": claims.sub,
        }),
    );

    Ok(Json(AuditorMutationResponse {
        id: account.id.to_string(),
        user_id: account.user_id.to_string(),
        email: account.email,
        is_active: account.is_active,
        expires_at: account.expires_at.timestamp(),
    }))
}

async fn list_auditors(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<AuditorAccountsListResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;
    require_admin_or_superadmin(&claims)?;

    let rows = sqlx::query(
        "SELECT
            id,
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active,
            created_at,
            updated_at
         FROM control_app.audit_accounts
         ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let mut auditors = Vec::with_capacity(rows.len());
    for row in rows {
        auditors.push(audit_account_response(read_audit_account_row(&row)?));
    }

    Ok(Json(AuditorAccountsListResponse { auditors }))
}

async fn revoke_auditor(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    Path(id): Path<String>,
) -> Result<Json<AuditorMutationResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;
    require_admin_or_superadmin(&claims)?;
    let auditor_id = Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auditor id must be a UUID".to_string(),
        )
    })?;

    let row = sqlx::query(
        "UPDATE control_app.audit_accounts
         SET is_active = FALSE,
             updated_at = NOW()
         WHERE id = $1
         RETURNING
            id,
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active,
            created_at,
            updated_at",
    )
    .bind(auditor_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "auditor not found".to_string()));
    };
    let account = read_audit_account_row(&row)?;

    {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(DisableUserRequest {
            user_id: account.user_id.to_string(),
            reason: "auditor_revoked".to_string(),
        });
        let _ =
            inject_internal_metadata(&mut request, "control-service", Some(&request_id.0), None);
        users_client
            .disable_user(request)
            .await
            .map_err(|err| map_users_service_error(err, "disable auditor failed"))?;
    }
    revoke_subject_sessions(&state, &account.user_id.to_string(), &request_id.0).await?;

    emit_semantic_control_audit(
        state,
        Some(request_id.0.clone()),
        claims.sub.clone(),
        "auditor.revoked",
        account.id.to_string(),
        serde_json::json!({
            "auditor_id": account.id,
            "user_id": account.user_id,
            "email": account.email,
            "revoked_by": claims.sub,
        }),
    );

    Ok(Json(AuditorMutationResponse {
        id: account.id.to_string(),
        user_id: account.user_id.to_string(),
        email: account.email,
        is_active: account.is_active,
        expires_at: account.expires_at.timestamp(),
    }))
}

async fn reset_auditor_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(request_id): Extension<RequestId>,
    Path(id): Path<String>,
    Json(payload): Json<ResetAuditorPasswordBody>,
) -> Result<Json<AuditorMutationResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;
    require_admin_or_superadmin(&claims)?;
    validate_password_policy(&payload.password)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let auditor_id = Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auditor id must be a UUID".to_string(),
        )
    })?;

    let account_row = sqlx::query(
        "SELECT
            id,
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active,
            created_at,
            updated_at
         FROM control_app.audit_accounts
         WHERE id = $1",
    )
    .bind(auditor_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    let Some(account_row) = account_row else {
        return Err((StatusCode::NOT_FOUND, "auditor not found".to_string()));
    };
    let mut account = read_audit_account_row(&account_row)?;

    let password_hash = hash_password(&payload.password).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("password hashing failed: {err}"),
        )
    })?;
    sqlx::query(
        "UPDATE auth.credentials_password
         SET password_hash = $2,
             password_updated_at = NOW()
         WHERE user_id = $1",
    )
    .bind(account.user_id)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    sqlx::query(
        "UPDATE control_app.audit_accounts
         SET updated_at = NOW()
         WHERE id = $1",
    )
    .bind(account.id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    revoke_subject_sessions(&state, &account.user_id.to_string(), &request_id.0).await?;
    account.updated_at = chrono::Utc::now();

    emit_semantic_control_audit(
        state,
        Some(request_id.0.clone()),
        claims.sub.clone(),
        "auditor.password_reset",
        account.id.to_string(),
        serde_json::json!({
            "auditor_id": account.id,
            "user_id": account.user_id,
            "email": account.email,
            "reset_by": claims.sub,
        }),
    );

    Ok(Json(AuditorMutationResponse {
        id: account.id.to_string(),
        user_id: account.user_id.to_string(),
        email: account.email,
        is_active: account.is_active,
        expires_at: account.expires_at.timestamp(),
    }))
}

async fn list_managed_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ManagedUsersQuery>,
) -> Result<Json<ManagedUsersListResponse>, (StatusCode, String)> {
    ensure_scope_or_auditor_read(&claims, "control:users:list")?;
    let limit = normalize_admin_limit(query.limit);
    let page = query.page.unwrap_or(1).max(1);
    let q = query.q.as_ref().map(|value| value.trim()).filter(|value| !value.is_empty());
    let status_filter = query
        .status
        .as_ref()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    let cursor = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let offset = if query.cursor.is_some() {
        cursor as i64
    } else {
        i64::from(limit) * i64::from(page.saturating_sub(1))
    };

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM auth.users auth
         LEFT JOIN users_app.users users ON users.user_id = auth.id
         WHERE ($1::TEXT IS NULL
                OR auth.email ILIKE '%' || $1 || '%'
                OR COALESCE(users.full_name, '') ILIKE '%' || $1 || '%'
                OR auth.id::TEXT ILIKE '%' || $1 || '%')
           AND ($2::TEXT IS NULL OR LOWER(COALESCE(NULLIF(BTRIM(users.status), ''), 'active')) = $2)",
    )
    .bind(q)
    .bind(status_filter.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let rows = sqlx::query(
        "SELECT auth.id::text AS user_id
         FROM auth.users auth
         LEFT JOIN users_app.users users ON users.user_id = auth.id
         WHERE ($1::TEXT IS NULL
                OR auth.email ILIKE '%' || $1 || '%'
                OR COALESCE(users.full_name, '') ILIKE '%' || $1 || '%'
                OR auth.id::TEXT ILIKE '%' || $1 || '%')
           AND ($2::TEXT IS NULL OR LOWER(COALESCE(NULLIF(BTRIM(users.status), ''), 'active')) = $2)
         ORDER BY auth.created_at DESC
         LIMIT $3
         OFFSET $4",
    )
    .bind(q)
    .bind(status_filter.as_deref())
    .bind(i64::from(limit))
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let user_id_str: String = row.get("user_id");
        users.push(load_managed_user_view(&state, &user_id_str).await?);
    }

    let total_pages = if total == 0 {
        0
    } else {
        ((total as f64) / f64::from(limit)).ceil() as u32
    };

    Ok(Json(ManagedUsersListResponse {
        data: users,
        meta: PaginatedMetaResponse {
            total,
            page,
            per_page: limit,
            total_pages,
        },
    }))
}

async fn upsert_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpsertUserBody>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }

    let existing = load_user_auth_state(&state, user_id.trim()).await?;
    if payload.active {
        if !is_active_user_status(&existing.status) {
            return Err((
                StatusCode::CONFLICT,
                "enabling disabled users is not yet supported".to_string(),
            ));
        }
        ensure_scope(&claims, "control:users:list")?;
        return Ok(Json(UserResponse {
            user_id: existing.user_id,
            status: existing.status,
            roles: existing.roles,
            scopes: existing.scopes,
            perm_rev: existing.perm_rev,
        }));
    }

    ensure_scope(&claims, "control:users:remove")?;

    let disable_response = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(DisableUserRequest {
            user_id: user_id.clone(),
            reason: "disabled_by_control_admin".to_string(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .disable_user(request)
            .await
            .map_err(|err| map_users_service_error(err, "disable user failed"))?
            .into_inner()
    };

    record_control_cache_user(&state, &user_id, &disable_response.status, &existing.roles).await;

    Ok(Json(UserResponse {
        user_id: disable_response.user_id,
        status: disable_response.status,
        roles: existing.roles,
        scopes: existing.scopes,
        perm_rev: disable_response.perm_rev,
    }))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<ManagedUserViewResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:list")?;
    Ok(Json(load_managed_user_view(&state, user_id.trim()).await?))
}

async fn update_managed_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateManagedUserBody>,
) -> Result<Json<ManagedUserViewResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:add")?;
    let full_name = compose_display_name(
        payload.first_name.as_deref(),
        payload.last_name.as_deref(),
        None,
    );
    update_user_settings_profile(
        &state,
        user_id.trim(),
        if full_name.is_empty() { None } else { Some(full_name) },
        payload.phone,
    )
    .await?;
    let view = load_managed_user_view(&state, user_id.trim()).await?;
    audit_control(
        &state,
        &claims.sub,
        "user.updated",
        serde_json::json!({ "user_id": user_id }),
    )
    .await;
    Ok(Json(view))
}

async fn update_managed_user_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateManagedUserStatusBody>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:remove")?;
    apply_user_status(&state, user_id.trim(), payload.status.as_str()).await?;
    audit_control(
        &state,
        &claims.sub,
        "user.status.updated",
        serde_json::json!({ "user_id": user_id, "status": payload.status }),
    )
    .await;
    Ok(Json(MessageResponse {
        message: "user status updated".to_string(),
    }))
}

async fn update_managed_user_email_verification(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateManagedUserEmailVerificationBody>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:add")?;
    sqlx::query(
        "UPDATE auth.users
         SET email_verified = $2,
             email_verified_at = CASE WHEN $2 THEN NOW() ELSE NULL END,
             updated_at = NOW()
         WHERE id = $1::UUID",
    )
    .bind(user_id.trim())
    .bind(payload.verified)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    audit_control(
        &state,
        &claims.sub,
        "user.email_verification.updated",
        serde_json::json!({ "user_id": user_id, "verified": payload.verified }),
    )
    .await;
    Ok(Json(MessageResponse {
        message: "email verification updated".to_string(),
    }))
}

async fn request_managed_user_password_reset(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:add")?;
    record_auth_security_event(
        &state,
        "control.password_reset_requested",
        Some(user_id.trim()),
        serde_json::json!({
            "requested_by": claims.sub,
        }),
    )
    .await?;
    audit_control(
        &state,
        &claims.sub,
        "user.password_reset.requested",
        serde_json::json!({ "user_id": user_id }),
    )
    .await;
    Ok(Json(MessageResponse {
        message: "password reset requested".to_string(),
    }))
}

async fn set_managed_user_temp_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<SetManagedUserTempPasswordBody>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:add")?;
    validate_password_policy(&payload.password)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("password hashing failed: {err}"),
            )
        })?
        .to_string();
    sqlx::query(
        "INSERT INTO auth.credentials_password (user_id, password_hash, password_updated_at, created_at)
         VALUES ($1::UUID, $2, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             password_updated_at = NOW()",
    )
    .bind(user_id.trim())
    .bind(password_hash)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    revoke_auth_sessions(&state, user_id.trim(), "temporary_password_set").await?;
    record_auth_security_event(
        &state,
        "control.temp_password_set",
        Some(user_id.trim()),
        serde_json::json!({
            "requested_by": claims.sub,
        }),
    )
    .await?;
    audit_control(
        &state,
        &claims.sub,
        "user.password.reset",
        serde_json::json!({ "user_id": user_id }),
    )
    .await;
    Ok(Json(MessageResponse {
        message: "temporary password updated".to_string(),
    }))
}

async fn anonymize_managed_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:users:remove")?;
    apply_user_status(&state, user_id.trim(), "anonymized").await?;
    let anonymized_email = format!(
        "anon-{}@wildon.local",
        user_id.trim().chars().take(8).collect::<String>()
    );
    sqlx::query(
        "UPDATE auth.users
         SET email = $2,
             email_verified = FALSE,
             email_verified_at = NULL,
             updated_at = NOW()
         WHERE id = $1::UUID",
    )
    .bind(user_id.trim())
    .bind(&anonymized_email)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    sqlx::query(
        "UPDATE users_app.users
         SET email = $2,
             full_name = 'Anonymized User',
             username = CONCAT('anon_', SUBSTRING($1::TEXT FROM 1 FOR 8)),
             phone = NULL,
             bio = NULL,
             updated_at = NOW(),
             settings_updated_at = NOW(),
             settings_version = settings_version + 1
         WHERE user_id = $1::UUID",
    )
    .bind(user_id.trim())
    .bind(&anonymized_email)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    revoke_auth_sessions(&state, user_id.trim(), "user_anonymized").await?;
    record_auth_security_event(
        &state,
        "user.anonymized",
        Some(user_id.trim()),
        serde_json::json!({
            "requested_by": claims.sub,
        }),
    )
    .await?;
    audit_control(
        &state,
        &claims.sub,
        "user.anonymized",
        serde_json::json!({ "user_id": user_id }),
    )
    .await;
    Ok(Json(MessageResponse {
        message: "user anonymized".to_string(),
    }))
}

async fn grant_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<GrantRoleBody>,
) -> Result<Json<RolesResponse>, (StatusCode, String)> {
    ensure_role_assignment_access(&claims)?;
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }
    let role = normalize_role(&payload.role).map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let mut auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    if !auth_state.roles.iter().any(|existing| existing == &role) {
        auth_state.roles.push(role);
    }
    auth_state.roles.sort();
    auth_state.roles.dedup();
    validate_role_assignment_actor(&claims, &auth_state.roles)?;

    let roles = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserRolesRequest {
            user_id: user_id.clone(),
            roles: auth_state.roles.clone(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_roles(request)
            .await
            .map_err(|err| map_users_service_error(err, "update roles failed"))?
            .into_inner()
            .roles
    };
    record_control_cache_user(&state, user_id.trim(), &auth_state.status, &roles).await;
    audit_control(
        &state,
        &claims.sub,
        "user.role.granted",
        serde_json::json!({ "user_id": user_id, "roles": roles }),
    )
    .await;
    Ok(Json(RolesResponse { user_id, roles }))
}

async fn get_roles(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<RolesResponse>, (StatusCode, String)> {
    ensure_role_catalog_read_access(&claims)?;
    let auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    Ok(Json(RolesResponse {
        user_id,
        roles: auth_state.roles,
    }))
}

async fn revoke_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((user_id, role)): Path<(String, String)>,
) -> Result<Json<RolesResponse>, (StatusCode, String)> {
    ensure_role_assignment_access(&claims)?;
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }

    let normalized_role = normalize_role(&role).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let mut auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    auth_state.roles.retain(|existing| existing != &normalized_role);
    validate_role_assignment_actor(&claims, &auth_state.roles)?;

    let roles = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserRolesRequest {
            user_id: user_id.clone(),
            roles: auth_state.roles.clone(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_roles(request)
            .await
            .map_err(|err| map_users_service_error(err, "revoke role failed"))?
            .into_inner()
            .roles
    };

    record_control_cache_user(&state, user_id.trim(), &auth_state.status, &roles).await;
    audit_control(
        &state,
        &claims.sub,
        "user.role.revoked",
        serde_json::json!({ "user_id": user_id, "role": normalized_role, "roles": roles }),
    )
    .await;
    Ok(Json(RolesResponse { user_id, roles }))
}

async fn get_role_catalog(
    Extension(claims): Extension<Claims>,
) -> Result<Json<RoleCatalogResponse>, (StatusCode, String)> {
    ensure_role_catalog_read_access(&claims)?;

    Ok(Json(RoleCatalogResponse {
        roles: scope_catalog::role_scope_defaults()
            .iter()
            .map(|defaults| RoleCatalogItemResponse {
                role: defaults.role.to_string(),
                default_scopes: scope_names_to_strings(defaults.scopes),
            })
            .collect(),
    }))
}

async fn update_scopes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateScopesBody>,
) -> Result<Json<ScopesResponse>, (StatusCode, String)> {
    ensure_scope_assignment_access(&claims)?;
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }

    let scopes = normalize_scopes(payload.scopes).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    validate_scope_assignment_actor(&claims, &scopes)?;

    let response = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserScopesRequest {
            user_id: user_id.clone(),
            scopes,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_scopes(request)
            .await
            .map_err(|err| map_users_service_error(err, "update scopes failed"))?
            .into_inner()
    };

    Ok(Json(ScopesResponse {
        user_id: response.user_id,
        scopes: response.scopes,
    }))
}

async fn grant_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(payload): Json<GrantScopeBody>,
) -> Result<Json<ScopesResponse>, (StatusCode, String)> {
    ensure_scope_assignment_access(&claims)?;
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }

    let mut auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    let normalized_scope =
        normalize_scopes(vec![payload.scope]).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    auth_state.scopes.extend(normalized_scope);
    auth_state.scopes.sort();
    auth_state.scopes.dedup();
    validate_scope_assignment_actor(&claims, &auth_state.scopes)?;

    let response = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserScopesRequest {
            user_id: user_id.clone(),
            scopes: auth_state.scopes.clone(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_scopes(request)
            .await
            .map_err(|err| map_users_service_error(err, "grant scope failed"))?
            .into_inner()
    };

    Ok(Json(ScopesResponse {
        user_id: response.user_id,
        scopes: response.scopes,
    }))
}

async fn get_scopes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<ScopesResponse>, (StatusCode, String)> {
    ensure_scope_catalog_read_access(&claims)?;
    let auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    Ok(Json(ScopesResponse {
        user_id: auth_state.user_id,
        scopes: auth_state.scopes,
    }))
}

async fn revoke_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((user_id, scope)): Path<(String, String)>,
) -> Result<Json<ScopesResponse>, (StatusCode, String)> {
    ensure_scope_assignment_access(&claims)?;
    if user_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }

    let normalized_scope =
        normalize_scopes(vec![scope]).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let mut auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    auth_state
        .scopes
        .retain(|existing| !normalized_scope.iter().any(|scope| scope == existing));

    let response = {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserScopesRequest {
            user_id: user_id.clone(),
            scopes: auth_state.scopes.clone(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_scopes(request)
            .await
            .map_err(|err| map_users_service_error(err, "revoke scope failed"))?
            .into_inner()
    };

    Ok(Json(ScopesResponse {
        user_id: response.user_id,
        scopes: response.scopes,
    }))
}

async fn get_scope_catalog(
    Extension(claims): Extension<Claims>,
) -> Result<Json<ScopeCatalogResponse>, (StatusCode, String)> {
    ensure_scope_catalog_read_access(&claims)?;

    Ok(Json(ScopeCatalogResponse {
        scopes: scope_catalog::scopes()
            .iter()
            .map(|scope| ScopeCatalogScopeResponse {
                name: scope.name.to_string(),
                description: scope.description.to_string(),
                first_party_default: scope.first_party_default,
                third_party_required: scope.third_party_required,
            })
            .collect(),
        assignable_scopes: scope_names_to_strings(scope_catalog::ASSIGNABLE_CONTROL_SCOPES),
        admin_assignable_scopes: scope_names_to_strings(
            scope_catalog::ADMIN_ASSIGNABLE_CONTROL_SCOPES,
        ),
        actor_assignable_scopes: scope_names_to_strings(actor_assignable_control_scopes(&claims)),
        role_default_scopes: scope_catalog::role_scope_defaults()
            .iter()
            .map(|defaults| RoleDefaultScopesResponse {
                role: defaults.role.to_string(),
                scopes: scope_names_to_strings(defaults.scopes),
            })
            .collect(),
    }))
}

async fn get_user_effective_permissions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<EffectivePermissionsResponse>, (StatusCode, String)> {
    ensure_user_management_read_access(&claims)?;

    let auth_state = load_user_auth_state(&state, user_id.trim()).await?;
    let mut effective_scopes = auth_state.scopes.clone();
    for role in &auth_state.roles {
        effective_scopes.extend(
            scope_catalog::role_default_scopes(role)
                .iter()
                .map(|scope| (*scope).to_string()),
        );
    }
    effective_scopes.sort();
    effective_scopes.dedup();

    Ok(Json(EffectivePermissionsResponse {
        user_id: auth_state.user_id,
        status: auth_state.status,
        roles: auth_state.roles,
        assigned_scopes: auth_state.scopes,
        effective_scopes,
    }))
}

fn ensure_scope(claims: &Claims, required: &str) -> Result<(), (StatusCode, String)> {
    if claims.scopes.iter().any(|scope| scope == required)
        || claims.roles.iter().any(|role| role == "superadmin")
    {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        format!("missing required scope: {required}"),
    ))
}

fn json_response_for_claims<T: Serialize>(
    claims: &Claims,
    value: &T,
) -> Result<Response, (StatusCode, String)> {
    let mut json = serde_json::to_value(value).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialization error: {err}"),
        )
    })?;
    if is_auditor_claims(claims) {
        mask_json_value(&mut json, None);
    }
    Ok(Json(json).into_response())
}

fn mask_json_value(value: &mut JsonValue, field_name: Option<&str>) {
    match value {
        JsonValue::Object(map) => {
            let keys = map.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                let normalized = key.trim().to_ascii_lowercase();
                if is_secret_field_name(&normalized) {
                    map.insert(key, JsonValue::String("[redacted]".to_string()));
                    continue;
                }
                if let Some(child) = map.get_mut(key.as_str()) {
                    mask_json_value(child, Some(&normalized));
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                mask_json_value(item, field_name);
            }
        }
        JsonValue::String(text) => {
            if field_name.is_some_and(is_email_field_name) || looks_like_email(text) {
                *text = mask_email(text);
            } else if field_name.is_some_and(is_phone_field_name) {
                *text = mask_phone(text);
            }
        }
        _ => {}
    }
}

fn is_secret_field_name(field_name: &str) -> bool {
    field_name == "password"
        || field_name == "password_hash"
        || field_name == "token"
        || field_name == "access_token"
        || field_name == "refresh_token"
        || field_name == "reset_token"
        || field_name == "secret"
        || field_name == "secret_plaintext"
        || field_name.ends_with("_token")
        || field_name.ends_with("_secret")
}

fn is_email_field_name(field_name: &str) -> bool {
    field_name == "email" || field_name.ends_with("_email")
}

fn is_phone_field_name(field_name: &str) -> bool {
    field_name == "phone" || field_name.ends_with("_phone") || field_name.contains("phone_")
}

fn looks_like_email(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.')
}

fn mask_email(value: &str) -> String {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "[redacted]".to_string();
    };
    let visible = local.chars().take(2).collect::<String>();
    let prefix = if visible.is_empty() {
        "*".to_string()
    } else {
        visible
    };
    format!("{prefix}***@{domain}")
}

fn mask_phone(value: &str) -> String {
    let digits = value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return "[redacted]".to_string();
    }
    let last4 = digits
        .iter()
        .rev()
        .take(4)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    if value.trim().starts_with("+1") || digits.len() == 11 && digits.first() == Some(&'1') {
        format!("+1 *** *** {last4}")
    } else if value.trim().starts_with('+') {
        let country = digits
            .iter()
            .take(digits.len().saturating_sub(10).max(1))
            .collect::<String>();
        format!("+{country} *** *** {last4}")
    } else {
        format!("*** *** {last4}")
    }
}

fn ensure_any_scope(claims: &Claims, required: &[&str]) -> Result<(), (StatusCode, String)> {
    if claims.roles.iter().any(|role| role == "superadmin")
        || required.iter().any(|scope| claims.scopes.iter().any(|present| present == scope))
    {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        format!("missing required scope: {}", required.join(" or ")),
    ))
}

fn ensure_apps_read_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:apps:read"])
}

fn ensure_user_management_read_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "auditor", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:users:list"])
}

fn ensure_role_catalog_read_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "auditor", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:roles:list", "control:users:list"])
}

fn ensure_scope_catalog_read_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "auditor", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:scopes:list", "control:users:list"])
}

fn ensure_role_assignment_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:roles:assign", "control:users:add"])
}

fn ensure_scope_assignment_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:scopes:assign", "control:users:add"])
}

fn ensure_apps_write_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:apps:write"])
}

fn ensure_billing_read_access(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["manager", "admin", "superadmin"]) {
        return Ok(());
    }
    ensure_any_scope(claims, &["control:billing:read"])
}

fn ensure_support_read_scope(claims: &Claims) -> Result<(), (StatusCode, String)> {
    ensure_any_scope(
        claims,
        &[
            "platform:support",
            "control:admin",
            "control:users:list",
            "system.support.read",
            "system.control.read",
        ],
    )
}

fn ensure_support_write_scope(claims: &Claims) -> Result<(), (StatusCode, String)> {
    ensure_any_scope(
        claims,
        &[
            "platform:support",
            "control:admin",
            "system.support.write",
            "system.control.write",
        ],
    )
}

fn ensure_system_scope(
    client: &SystemApiClientContext,
    required: &str,
) -> Result<(), (StatusCode, String)> {
    if client.scopes.contains(required) {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        format!("missing required system API scope: {required}"),
    ))
}

fn normalize_admin_limit(limit: Option<u32>) -> u32 {
    match limit.unwrap_or(50) {
        0 => 50,
        value => value.min(200),
    }
}

fn normalize_app_platform(value: &str) -> Result<String, (StatusCode, String)> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "android" | "ios" | "web-users" | "web-support" | "web-admins"
    ) {
        Ok(normalized)
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid app platform".to_string()))
    }
}

fn validate_app_status(value: &str) -> Result<(), (StatusCode, String)> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "online" | "maintenance" | "degraded" | "offline") {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid app status".to_string()))
    }
}

fn validate_update_policy(value: &str) -> Result<(), (StatusCode, String)> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "silent" | "recommended" | "required" | "disabled"
    ) {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid update policy".to_string()))
    }
}

fn app_record_from_row(row: &sqlx::postgres::PgRow) -> Result<AppRecordResponse, (StatusCode, String)> {
    let stats = AppStatsResponse {
        guests_count: row.get::<i64, _>("stats_guests_count"),
        registered_users: row.get::<i64, _>("stats_registered_users"),
        users_online: row.get::<i64, _>("stats_users_online"),
        peak_online_today: row.get::<i64, _>("stats_peak_online_today"),
        avg_session_minutes: row.get::<f64, _>("stats_avg_session_minutes"),
        crash_rate_percent: row.get::<f64, _>("stats_crash_rate_percent"),
        api_status: row.get::<String, _>("stats_api_status"),
        api_latency_ms: row.get::<i32, _>("stats_api_latency_ms"),
        device_distribution: row.get::<JsonValue, _>("stats_device_distribution"),
    };

    Ok(AppRecordResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        platform: row.get::<String, _>("platform"),
        display_name: row.get::<String, _>("display_name"),
        description: row.get::<String, _>("description"),
        status: row.get::<String, _>("status"),
        app_version: row.get::<String, _>("app_version"),
        api_version: row.get::<String, _>("api_version"),
        min_supported_version: row.get::<String, _>("min_supported_version"),
        latest_available_version: row.get::<Option<String>, _>("latest_available_version"),
        force_update_version: row.get::<Option<String>, _>("force_update_version"),
        last_updated_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("last_updated_at")
            .to_rfc3339(),
        update_policy: row.get::<String, _>("update_policy"),
        stats,
        release_channel: row.get::<String, _>("release_channel"),
        health_score: row.get::<i32, _>("health_score"),
        last_incident_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_incident_at")
            .map(|value| value.to_rfc3339()),
        last_incident_type: row.get::<Option<String>, _>("last_incident_type"),
        uptime_percent: row.get::<f64, _>("uptime_percent"),
        features: row.get::<JsonValue, _>("features"),
        supported_devices: row.get::<JsonValue, _>("supported_devices"),
        bundle_id: row.get::<Option<String>, _>("bundle_id"),
        store_url: row.get::<Option<String>, _>("store_url"),
        environment: row.get::<String, _>("environment"),
        notes: row.get::<String, _>("notes"),
        created_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
        updated_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .to_rfc3339(),
    })
}

fn session_primary_role(roles: &[String]) -> String {
    const ROLE_PRIORITY: [&str; 7] = [
        "superadmin",
        "admin",
        "manager",
        "auditor",
        "support",
        "partner",
        "user",
    ];
    for role in ROLE_PRIORITY {
        if roles.iter().any(|existing| existing.eq_ignore_ascii_case(role)) {
            return role.to_string();
        }
    }
    roles
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

fn session_device_hint(user_agent: &str, client_id: &str) -> String {
    let user_agent_lc = user_agent.to_ascii_lowercase();
    if user_agent_lc.contains("android") {
        return "Android".to_string();
    }
    if user_agent_lc.contains("iphone") || user_agent_lc.contains("ipad") || user_agent_lc.contains("ios") {
        return "iOS".to_string();
    }
    if user_agent_lc.contains("windows") {
        return "Windows".to_string();
    }
    if user_agent_lc.contains("macintosh") || user_agent_lc.contains("mac os") {
        return "macOS".to_string();
    }
    if user_agent_lc.contains("linux") {
        return "Linux".to_string();
    }
    if !client_id.trim().is_empty() {
        return client_id.trim().to_string();
    }
    "Unknown".to_string()
}

fn billing_transaction_response(record: BillingTransaction) -> BillingTransactionResponse {
    BillingTransactionResponse {
        transaction_id: record.transaction_id,
        user_id: record.user_id,
        invoice_id: record.invoice_id,
        status: record.status,
        amount_cents: record.amount_cents,
        refunded_amount_cents: record.refunded_amount_cents,
        currency: record.currency,
        provider: record.provider,
        external_txn_id: record.external_txn_id,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn billing_invoice_response(record: BillingInvoice) -> BillingInvoiceResponse {
    BillingInvoiceResponse {
        invoice_id: record.invoice_id,
        user_id: record.user_id,
        status: record.status,
        amount_cents: record.amount_cents,
        refunded_amount_cents: record.refunded_amount_cents,
        currency: record.currency,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn billing_ledger_entry_response(record: BillingLedgerEntry) -> BillingLedgerEntryResponse {
    BillingLedgerEntryResponse {
        ledger_id: record.ledger_id,
        user_id: record.user_id,
        transaction_id: record.transaction_id,
        invoice_id: record.invoice_id,
        entry_type: record.entry_type,
        amount_cents: record.amount_cents,
        currency: record.currency,
        note: record.note,
        created_at: record.created_at,
    }
}

fn billing_plan_response(record: BillingPlan) -> BillingPlanResponse {
    BillingPlanResponse {
        plan_id: record.plan_id,
        plan_code: record.plan_code,
        name: record.name,
        description: record.description,
        priority: record.priority,
        interval: record.interval,
        price_cents: record.price_cents,
        currency: record.currency,
        device_limit: record.device_limit,
        storage_limit_bytes: record.storage_limit_bytes,
        retention_days: record.retention_days,
        status: record.status,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn billing_subscription_response(record: BillingSubscription) -> BillingSubscriptionResponse {
    BillingSubscriptionResponse {
        subscription_id: record.subscription_id,
        subscription_code: record.subscription_code,
        user_id: record.user_id,
        plan_id: record.plan_id,
        plan_code: record.plan_code,
        status: record.status,
        start_date: record.start_date,
        end_date: record.end_date,
        auto_renew: record.auto_renew,
        device_count: record.device_count,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn audit_log_item_response(record: AuditLogRecord) -> AuditLogItemResponse {
    let AuditLogRecord {
        event_id,
        user_id,
        action,
        payload_json,
        consumer,
        created_at,
        ..
    } = record;
    let payload = match serde_json::from_str::<JsonValue>(&payload_json) {
        Ok(JsonValue::Object(map)) => JsonValue::Object(map),
        Ok(value) => serde_json::json!({ "value": value }),
        Err(_) => serde_json::json!({ "raw": payload_json }),
    };
    AuditLogItemResponse {
        event_id,
        user_id,
        action,
        consumer,
        created_at,
        payload,
    }
}

fn api_client_record_response(record: ApiClient) -> ApiClientRecordResponse {
    ApiClientRecordResponse {
        id: record.id,
        client_id: record.client_id,
        client_number: record.client_number,
        client_ref: record.client_ref,
        display_name: record.display_name,
        description: record.description,
        platform: record.platform,
        surface: record.surface,
        environment: record.environment,
        client_type: api_client_type_label(record.client_type).to_string(),
        status: api_client_status_label(record.status).to_string(),
        allowed_audiences: record.allowed_audiences,
        allowed_origins: record.allowed_origins,
        ip_allowlist: record.ip_allowlist,
        require_mtls: record.require_mtls,
        is_version_enforced: record.is_version_enforced,
        min_app_version: record.min_app_version,
        max_app_version: record.max_app_version,
        user_rate_policy: record.user_rate_policy,
        client_safety_policy: record.client_safety_policy,
        created_at: record.created_at,
        updated_at: record.updated_at,
        last_used_at: record.last_used_at,
        created_by: record.created_by,
        updated_by: record.updated_by,
        notes: record.notes,
        has_active_secret: record.has_active_secret,
    }
}

fn api_client_event_response(record: ClientEvent) -> ApiClientEventResponse {
    let payload = match serde_json::from_str::<JsonValue>(&record.payload_json) {
        Ok(JsonValue::Object(map)) => JsonValue::Object(map),
        Ok(value) => serde_json::json!({ "value": value }),
        Err(_) => serde_json::json!({ "raw": record.payload_json }),
    };
    ApiClientEventResponse {
        event_id: record.event_id,
        client_id: record.client_id,
        event_type: record.event_type,
        actor_user_id: record.actor_user_id,
        payload,
        created_at: record.created_at,
    }
}

fn has_any_role(claims: &Claims, required_roles: &[&str]) -> bool {
    claims
        .roles
        .iter()
        .any(|role| required_roles.iter().any(|required| role == required))
}

fn scope_names_to_strings(scopes: &[&str]) -> Vec<String> {
    scopes.iter().map(|scope| (*scope).to_string()).collect()
}

fn actor_assignable_control_scopes(claims: &Claims) -> &'static [&'static str] {
    if has_any_role(claims, &["superadmin"]) {
        scope_catalog::ASSIGNABLE_CONTROL_SCOPES
    } else if has_any_role(claims, &["admin"]) {
        scope_catalog::ADMIN_ASSIGNABLE_CONTROL_SCOPES
    } else {
        &[]
    }
}

fn non_empty(raw: &str) -> Option<&str> {
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        None
    } else {
        Some(email)
    }
}

fn normalize_email_template_name(raw: &str) -> Result<String, String> {
    notification_templates::normalize_and_validate_template_name(raw)
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

fn normalize_role(role: &str) -> Result<String, String> {
    let role = role.trim().to_lowercase();
    if role.is_empty() {
        return Err("role is required".to_string());
    }
    if !ALLOWED_CONTROL_ROLES.contains(&role.as_str()) {
        return Err(format!("unsupported role '{role}'"));
    }
    Ok(role)
}

fn normalize_roles(roles: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = Vec::with_capacity(roles.len());
    for role in roles {
        normalized.push(normalize_role(&role)?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_scopes(scopes: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = scopes
        .into_iter()
        .map(|scope| scope.trim().to_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();

    let invalid = normalized
        .iter()
        .find(|scope| !scope_catalog::is_assignable_control_scope(scope));
    if let Some(scope) = invalid {
        return Err(format!("unsupported scope '{scope}'"));
    }
    Ok(normalized)
}

fn validate_role_assignment_actor(
    claims: &Claims,
    target_roles: &[String],
) -> Result<(), (StatusCode, String)> {
    let actor_is_superadmin = has_any_role(claims, &["superadmin"]);
    let actor_is_admin = has_any_role(claims, &["admin"]);

    if actor_is_superadmin {
        return Ok(());
    }
    if actor_is_admin {
        if target_roles
            .iter()
            .any(|role| role == "auditor" || role == "admin" || role == "superadmin")
        {
            return Err((
                StatusCode::FORBIDDEN,
                "admin cannot assign auditor, admin, or superadmin roles".to_string(),
            ));
        }
        return Ok(());
    }

    if target_roles.iter().any(|role| {
        role == "auditor" || role == "manager" || role == "admin" || role == "superadmin"
    }) {
        return Err((
            StatusCode::FORBIDDEN,
            "manager can only create or assign user/support/partner roles".to_string(),
        ));
    }
    Ok(())
}

fn validate_scope_assignment_actor(
    claims: &Claims,
    scopes: &[String],
) -> Result<(), (StatusCode, String)> {
    if scopes.is_empty() {
        return Ok(());
    }
    let assignable = actor_assignable_control_scopes(claims);
    if assignable.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            "only admin or superadmin can assign scopes".to_string(),
        ));
    }
    if has_any_role(claims, &["superadmin"]) {
        return Ok(());
    }
    for scope in scopes {
        if !scope_catalog::is_admin_assignable_control_scope(scope) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("admin cannot assign scope '{scope}'"),
            ));
        }
    }
    Ok(())
}

fn require_admin_or_superadmin(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if has_any_role(claims, &["admin", "superadmin"]) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "only admin or superadmin can manage auditor accounts".to_string(),
        ))
    }
}

fn parse_unix_timestamp(
    timestamp: i64,
    field_name: &str,
) -> Result<chrono::DateTime<chrono::Utc>, (StatusCode, String)> {
    chrono::DateTime::from_timestamp(timestamp, 0).ok_or((
        StatusCode::BAD_REQUEST,
        format!("{field_name} must be a valid unix timestamp"),
    ))
}

fn emit_semantic_control_audit(
    state: AppState,
    request_id: Option<String>,
    user_id: String,
    action: &str,
    resource_id: String,
    payload: JsonValue,
) {
    let action = action.to_string();
    tokio::spawn(async move {
        publish_control_audit(
            state,
            request_id,
            None,
            user_id,
            action,
            resource_id,
            payload.to_string(),
        )
        .await;
    });
}

fn map_users_service_error(err: tonic::Status, context: &str) -> (StatusCode, String) {
    let status = match err.code() {
        GrpcCode::InvalidArgument => StatusCode::BAD_REQUEST,
        GrpcCode::NotFound => StatusCode::NOT_FOUND,
        GrpcCode::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_GATEWAY,
    };
    (status, format!("{context}: {err}"))
}

fn map_auth_service_error(err: tonic::Status, context: &str) -> (StatusCode, String) {
    let status = match err.code() {
        GrpcCode::InvalidArgument => StatusCode::BAD_REQUEST,
        GrpcCode::NotFound => StatusCode::NOT_FOUND,
        GrpcCode::PermissionDenied => StatusCode::FORBIDDEN,
        GrpcCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        _ => StatusCode::BAD_GATEWAY,
    };
    (status, format!("{context}: {err}"))
}

fn map_api_clients_service_error(err: tonic::Status, context: &str) -> (StatusCode, String) {
    let status = match err.code() {
        GrpcCode::InvalidArgument => StatusCode::BAD_REQUEST,
        GrpcCode::NotFound => StatusCode::NOT_FOUND,
        GrpcCode::PermissionDenied => StatusCode::FORBIDDEN,
        GrpcCode::AlreadyExists => StatusCode::CONFLICT,
        _ => StatusCode::BAD_GATEWAY,
    };
    (status, format!("{context}: {err}"))
}

fn parse_api_client_type(raw: &str) -> Result<i32, (StatusCode, String)> {
    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "public" => Ok(ApiClientType::Public as i32),
        "confidential" => Ok(ApiClientType::Confidential as i32),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported client_type '{value}'"),
        )),
    }
}

fn parse_api_client_status(raw: &str) -> Result<i32, (StatusCode, String)> {
    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "active" => Ok(ApiClientStatus::Active as i32),
        "suspended" | "disabled" => Ok(ApiClientStatus::Suspended as i32),
        "revoked" | "deprecated" => Ok(ApiClientStatus::Revoked as i32),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported status '{value}'"),
        )),
    }
}

fn api_client_type_label(value: i32) -> &'static str {
    match ApiClientType::try_from(value).unwrap_or(ApiClientType::Unspecified) {
        ApiClientType::Public => "public",
        ApiClientType::Confidential => "confidential",
        ApiClientType::Unspecified => "unspecified",
    }
}

fn api_client_status_label(value: i32) -> &'static str {
    match ApiClientStatus::try_from(value).unwrap_or(ApiClientStatus::Unspecified) {
        ApiClientStatus::Active => "active",
        ApiClientStatus::Disabled | ApiClientStatus::Suspended => "suspended",
        ApiClientStatus::Deprecated | ApiClientStatus::Revoked => "revoked",
        ApiClientStatus::Unspecified => "unspecified",
    }
}

async fn get_api_client_by_id_grpc(
    state: &AppState,
    id: &str,
) -> Result<ApiClient, (StatusCode, String)> {
    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(GetClientByIdRequest { id: id.to_string() });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .get_client_by_id(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "get api client by id failed"))?
            .into_inner()
    };

    response
        .client
        .ok_or((StatusCode::BAD_GATEWAY, "missing api client".to_string()))
}

async fn create_auth_identity(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    password: &str,
    email_verified: bool,
) -> Result<(), (StatusCode, String)> {
    let user_id_text = user_id.to_string();
    let password_hash = hash_password(password).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("password hashing failed: {err}"),
        )
    })?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let duplicate_email = sqlx::query_scalar::<_, i64>(
        "SELECT 1
         FROM auth.users
         WHERE email = $1
         LIMIT 1",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    if duplicate_email.is_some() {
        tx.rollback().await.ok();
        return Err((StatusCode::CONFLICT, "email already exists".to_string()));
    }

    let duplicate_user = sqlx::query_scalar::<_, i64>(
        "SELECT 1
         FROM auth.users
         WHERE id = $1::UUID
         LIMIT 1",
    )
    .bind(&user_id_text)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    if duplicate_user.is_some() {
        tx.rollback().await.ok();
        return Err((StatusCode::CONFLICT, "user_id already exists".to_string()));
    }

    sqlx::query(
        "INSERT INTO auth.users (
            id, email, email_verified, email_verified_at, created_at, updated_at
         ) VALUES (
            $1::UUID, $2, $3, CASE WHEN $3 THEN NOW() ELSE NULL END, NOW(), NOW()
         )",
    )
    .bind(&user_id_text)
    .bind(email)
    .bind(email_verified)
    .execute(&mut *tx)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    sqlx::query(
        "INSERT INTO auth.credentials_password (
            user_id, password_hash, password_updated_at, created_at
         ) VALUES (
            $1::UUID, $2, NOW(), NOW()
         )",
    )
    .bind(&user_id_text)
    .bind(password_hash)
    .execute(&mut *tx)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    tx.commit()
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    Ok(())
}

async fn insert_audit_account(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    created_by: Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
    allowed_ips: Option<Vec<String>>,
) -> Result<AuditAccountRecord, (StatusCode, String)> {
    let allowed_ips_json = allowed_ips.map(|ips| sqlx::types::Json(serde_json::json!(ips)));
    let row = sqlx::query(
        "INSERT INTO control_app.audit_accounts (
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active
         ) VALUES ($1, $2, 'auditor', $3, $4, $5, TRUE)
         RETURNING
            id,
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active,
            created_at,
            updated_at",
    )
    .bind(user_id)
    .bind(email)
    .bind(created_by)
    .bind(expires_at)
    .bind(allowed_ips_json)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    read_audit_account_row(&row)
}

async fn ensure_users_identity(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    first_name: String,
    last_name: String,
    roles: Vec<String>,
    scopes: Vec<String>,
) -> Result<(), (StatusCode, String)> {
    {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(CreateUserRequest {
            user_id: user_id.to_string(),
            email: email.to_string(),
            first_name,
            last_name,
            middle_name: String::new(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .create_user(request)
            .await
            .map_err(|err| map_users_service_error(err, "create user failed"))?;
    }

    {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserRolesRequest {
            user_id: user_id.to_string(),
            roles,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_roles(request)
            .await
            .map_err(|err| map_users_service_error(err, "update roles failed"))?;
    }

    {
        let mut users_client = state.users_client.lock().await;
        let mut request = GrpcRequest::new(UpdateUserScopesRequest {
            user_id: user_id.to_string(),
            scopes,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        users_client
            .update_user_scopes(request)
            .await
            .map_err(|err| map_users_service_error(err, "update scopes failed"))?;
    }

    Ok(())
}

async fn load_user_auth_state(
    state: &AppState,
    user_id: &str,
) -> Result<GetUserAuthStateResponse, (StatusCode, String)> {
    let mut users_client = state.users_client.lock().await;
    let mut request = GrpcRequest::new(GetUserAuthStateRequest {
        user_id: user_id.to_string(),
    });
    let _ = inject_internal_metadata(&mut request, "control-service", None, None);
    users_client
        .get_user_auth_state(request)
        .await
        .map(|response| response.into_inner())
        .map_err(|err| map_users_service_error(err, "load user failed"))
}

async fn load_audit_account_by_subject(
    state: &AppState,
    subject: &str,
) -> Result<Option<AuditAccountRecord>, (StatusCode, String)> {
    let user_id = Uuid::parse_str(subject.trim()).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "authenticated subject must be a valid UUID".to_string(),
        )
    })?;
    let row = sqlx::query(
        "SELECT
            id,
            user_id,
            email,
            role,
            created_by,
            expires_at,
            allowed_ips,
            is_active,
            created_at,
            updated_at
         FROM control_app.audit_accounts
         WHERE user_id = $1
         AND is_active = TRUE
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    match row {
        Some(row) => Ok(Some(read_audit_account_row(&row)?)),
        None => Ok(None),
    }
}

async fn load_user_settings(
    state: &AppState,
    user_id: &str,
) -> Result<contracts::wildon::users::v1::UserSettings, (StatusCode, String)> {
    let mut users_client = state.users_client.lock().await;
    let mut request = GrpcRequest::new(GetUserSettingsRequest {
        user_id: user_id.to_string(),
    });
    let _ = inject_internal_metadata(&mut request, "control-service", Some(user_id), None);
    users_client
        .get_user_settings(request)
        .await
        .map_err(|err| map_users_service_error(err, "load user settings failed"))?
        .into_inner()
        .settings
        .ok_or((StatusCode::BAD_GATEWAY, "missing user settings".to_string()))
}

async fn update_user_settings_profile(
    state: &AppState,
    user_id: &str,
    full_name: Option<String>,
    phone: Option<String>,
) -> Result<(), (StatusCode, String)> {
    let mut users_client = state.users_client.lock().await;
    let mut request = GrpcRequest::new(UpdateUserSettingsRequest {
        user_id: user_id.to_string(),
        full_name,
        username: None,
        phone,
        profile_photo_object_key: None,
        bio: None,
        language: None,
        timezone: None,
        date_format: None,
        clock_format: None,
        distance_unit: None,
        temperature_unit: None,
        first_name: None,
        last_name: None,
        middle_name: None,
        preferred_name: None,
        display_name: None,
    });
    let _ = inject_internal_metadata(&mut request, "control-service", Some(user_id), None);
    users_client
        .update_user_settings(request)
        .await
        .map_err(|err| map_users_service_error(err, "update user settings failed"))?;
    Ok(())
}

async fn load_managed_user_view(
    state: &AppState,
    user_id: &str,
) -> Result<ManagedUserViewResponse, (StatusCode, String)> {
    let auth_state = load_user_auth_state(state, user_id).await?;
    let settings = load_user_settings(state, user_id).await?;

    let auth_row = sqlx::query(
        "SELECT email, email_verified, created_at
         FROM auth.users
         WHERE id = $1::UUID",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "user not found".to_string()))?;

    let user_row = sqlx::query(
        "SELECT status, updated_at
         FROM users_app.users
         WHERE user_id = $1::UUID",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let session_row = sqlx::query(
        "SELECT last_activity_at, ip_address::TEXT AS ip_address
         FROM auth.sessions
         WHERE user_id = $1::UUID
         ORDER BY last_activity_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let provider_row = sqlx::query(
        "SELECT provider
         FROM auth.oauth_provider_accounts
         WHERE user_id = $1::UUID
         ORDER BY created_at ASC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let full_name = settings.full_name.trim();
    let (first_name, last_name) = split_full_name(full_name);
    let created_at: chrono::DateTime<chrono::Utc> = auth_row.get("created_at");
    let last_activity_at = session_row
        .as_ref()
        .map(|row| row.get::<chrono::DateTime<chrono::Utc>, _>("last_activity_at"))
        .unwrap_or(created_at);
    let status = user_row
        .as_ref()
        .map(|row| row.get::<String, _>("status"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| auth_state.status.clone());
    let anonymized_at = if status == "anonymized" {
        user_row
            .as_ref()
            .map(|row| row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339())
    } else {
        None
    };

    Ok(ManagedUserViewResponse {
        id: user_id.to_string(),
        email: auth_row.get::<String, _>("email"),
        phone: optional_trimmed(settings.phone),
        first_name,
        last_name,
        tier: "free".to_string(),
        status,
        email_verified: auth_row.get::<bool, _>("email_verified"),
        phone_verified: false,
        login_method: provider_row
            .as_ref()
            .map(|row| row.get::<String, _>("provider"))
            .unwrap_or_else(|| "email".to_string()),
        last_login_ip: session_row
            .as_ref()
            .and_then(|row| row.try_get::<Option<String>, _>("ip_address").ok().flatten()),
        country: None,
        patients_count: 0,
        devices_count: 0,
        alerts_count: 0,
        active_subscription_id: None,
        created_at: created_at.to_rfc3339(),
        last_active_at: last_activity_at.to_rfc3339(),
        anonymized_at,
        roles: auth_state.roles,
        scopes: auth_state.scopes,
        perm_rev: auth_state.perm_rev,
    })
}

fn read_audit_account_row(
    row: &sqlx::postgres::PgRow,
) -> Result<AuditAccountRecord, (StatusCode, String)> {
    Ok(AuditAccountRecord {
        id: row.get("id"),
        user_id: row.get("user_id"),
        email: row.get("email"),
        role: row.get("role"),
        created_by: row.get("created_by"),
        expires_at: row.get("expires_at"),
        allowed_ips: parse_allowed_ips_json(row.get::<Option<JsonValue>, _>("allowed_ips"))?,
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn audit_account_response(record: AuditAccountRecord) -> AuditorAccountResponse {
    AuditorAccountResponse {
        id: record.id.to_string(),
        user_id: record.user_id.to_string(),
        email: record.email,
        role: record.role,
        created_by: record.created_by.to_string(),
        expires_at: record.expires_at.timestamp(),
        allowed_ips: record.allowed_ips,
        is_active: record.is_active,
        created_at: record.created_at.timestamp(),
        updated_at: record.updated_at.timestamp(),
    }
}

async fn revoke_subject_sessions(
    state: &AppState,
    subject: &str,
    request_id: &str,
) -> Result<(), (StatusCode, String)> {
    let mut request = GrpcRequest::new(LogoutAllSessionsRequest {
        reason: "auditor_revoked_or_password_reset".to_string(),
    });
    inject_internal_metadata(&mut request, "control-service", Some(request_id), None).map_err(
        |err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to build auth metadata: {err}"),
            )
        },
    )?;
    let subject_value = subject.parse().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode auth subject metadata: {err}"),
        )
    })?;
    request.metadata_mut().insert("x-auth-sub", subject_value);

    let mut auth_client: tokio::sync::MutexGuard<'_, AuthServiceClient<tonic::transport::Channel>> =
        state.auth_client.lock().await;
    auth_client
        .logout_all_sessions(request)
        .await
        .map_err(|err| map_auth_service_error(err, "revoke auditor sessions failed"))?;
    Ok(())
}

async fn fetch_audit_logs_response(
    state: &AppState,
    query: AuditLogsQuery,
) -> Result<AuditLogsListResponse, (StatusCode, String)> {
    let limit = normalize_admin_limit(query.limit);
    let response = {
        let mut logs_client = state.logs_client.lock().await;
        let mut request = GrpcRequest::new(ListAuditLogsRequest {
            limit,
            cursor: query.cursor.unwrap_or_default(),
            action: query.action.unwrap_or_default(),
            consumer: query.consumer.unwrap_or_default(),
            user_id: query.user_id.unwrap_or_default(),
            from_unix: query.from.unwrap_or_default(),
            to_unix: query.to.unwrap_or_default(),
            ..Default::default()
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        logs_client
            .list_audit_logs(request)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("logs grpc error: {err}")))?
            .into_inner()
    };

    Ok(AuditLogsListResponse {
        items: response
            .items
            .into_iter()
            .map(audit_log_item_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: if response.next_cursor.trim().is_empty() {
                None
            } else {
                Some(response.next_cursor)
            },
            has_more: response.has_more,
        },
        total: response.total,
    })
}

fn compose_display_name(
    first_name: Option<&str>,
    last_name: Option<&str>,
    display_name: Option<&str>,
) -> String {
    let first = first_name.unwrap_or_default().trim();
    let last = last_name.unwrap_or_default().trim();
    let combined = format!("{first} {last}").trim().to_string();
    if !combined.is_empty() {
        combined
    } else {
        display_name.unwrap_or_default().trim().to_string()
    }
}

fn split_full_name(full_name: &str) -> (String, String) {
    let trimmed = full_name.trim();
    if trimmed.is_empty() {
        return ("Wildon".to_string(), "User".to_string());
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts.next().unwrap_or("Wildon").to_string();
    let last = parts.collect::<Vec<_>>().join(" ");
    if last.is_empty() {
        (first, "User".to_string())
    } else {
        (first, last)
    }
}

fn optional_trimmed(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

async fn apply_user_status(
    state: &AppState,
    user_id: &str,
    status: &str,
) -> Result<(), (StatusCode, String)> {
    let normalized = status.trim().to_lowercase();
    match normalized.as_str() {
        "active" | "pending" => {}
        "suspended" | "banned" | "anonymized" => {
            let mut users_client = state.users_client.lock().await;
            let mut request = GrpcRequest::new(DisableUserRequest {
                user_id: user_id.to_string(),
                reason: format!("status_changed_to_{normalized}"),
            });
            let _ = inject_internal_metadata(&mut request, "control-service", None, None);
            users_client
                .disable_user(request)
                .await
                .map_err(|err| map_users_service_error(err, "disable user failed"))?;
        }
        _ => {
            return Err((StatusCode::BAD_REQUEST, "unsupported status".to_string()));
        }
    }

    sqlx::query(
        "UPDATE users_app.users
         SET status = $2, updated_at = NOW()
         WHERE user_id = $1::UUID",
    )
    .bind(user_id)
    .bind(normalized)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    Ok(())
}

async fn revoke_auth_sessions(
    state: &AppState,
    user_id: &str,
    reason: &str,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "UPDATE auth.sessions
         SET revoked_at = NOW(), revoked_reason = $2
         WHERE user_id = $1::UUID AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(reason)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    sqlx::query(
        "UPDATE auth.refresh_tokens
         SET revoked_at = NOW(), revoked_reason = $2
         WHERE session_id IN (SELECT id FROM auth.sessions WHERE user_id = $1::UUID)
           AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(reason)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    Ok(())
}

async fn record_auth_security_event(
    state: &AppState,
    event_type: &str,
    user_id: Option<&str>,
    details: JsonValue,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO auth.security_events (event_type, user_id, details)
         VALUES ($1, $2::UUID, $3::JSONB)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(details)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;
    Ok(())
}

fn is_active_user_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("active")
}

async fn record_control_cache_user(
    state: &AppState,
    user_id: &str,
    status: &str,
    roles: &[String],
) {
    let mut data = state.data.lock().await;
    data.users.insert(
        user_id.to_string(),
        AdminUserRecord {
            user_id: user_id.to_string(),
            active: is_active_user_status(status),
            updated_at: chrono::Utc::now().timestamp(),
        },
    );
    let mut deduped = HashSet::new();
    data.roles.insert(
        user_id.to_string(),
        roles
            .iter()
            .filter(|role| deduped.insert((*role).clone()))
            .cloned()
            .collect(),
    );
}

async fn set_feature_flag(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(payload): Json<SetFeatureFlagBody>,
) -> Result<Json<FeatureFlagResponse>, (StatusCode, String)> {
    let normalized_key = feature_flags::normalize_key(&key);
    if normalized_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "feature flag key is required".to_string(),
        ));
    }

    let response = {
        let mut core_client = state.core_client.lock().await;
        let mut request = GrpcRequest::new(SetFeatureFlagRequest {
            key: normalized_key,
            enabled: payload.enabled,
            updated_by: payload.updated_by,
            reason: payload.reason,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        core_client
            .set_feature_flag(request)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("core grpc error: {err}")))?
            .into_inner()
    };

    let flag = response
        .flag
        .ok_or((StatusCode::BAD_GATEWAY, "missing feature flag".to_string()))?;

    Ok(Json(FeatureFlagResponse {
        key: flag.key,
        enabled: flag.enabled,
        updated_by: flag.updated_by,
        reason: flag.reason,
        updated_at: flag.updated_at,
    }))
}

async fn get_feature_flag(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<FeatureFlagResponse>, (StatusCode, String)> {
    let normalized_key = feature_flags::normalize_key(&key);
    if normalized_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "feature flag key is required".to_string(),
        ));
    }

    let response = {
        let mut core_client = state.core_client.lock().await;
        let mut request = GrpcRequest::new(GetFeatureFlagRequest {
            key: normalized_key,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        core_client
            .get_feature_flag(request)
            .await
            .map_err(|err| {
                let code = if err.code() == tonic::Code::NotFound {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::BAD_GATEWAY
                };
                (code, format!("core grpc error: {err}"))
            })?
            .into_inner()
    };

    let flag = response
        .flag
        .ok_or((StatusCode::BAD_GATEWAY, "missing feature flag".to_string()))?;

    Ok(Json(FeatureFlagResponse {
        key: flag.key,
        enabled: flag.enabled,
        updated_by: flag.updated_by,
        reason: flag.reason,
        updated_at: flag.updated_at,
    }))
}

async fn ingest_billing_webhook(
    State(state): State<AppState>,
    Json(payload): Json<BillingWebhookBody>,
) -> Result<Json<BillingWebhookResponse>, (StatusCode, String)> {
    if payload.event_id.trim().is_empty() || payload.user_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "event_id and user_id are required".to_string(),
        ));
    }

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(IngestBillingWebhookRequest {
            provider: payload.provider,
            event_id: payload.event_id,
            user_id: payload.user_id,
            amount_cents: payload.amount_cents,
            currency: payload.currency,
            signature: payload.signature,
            payload_json: payload.payload_json,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .ingest_billing_webhook(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingWebhookResponse {
        accepted: response.accepted,
        duplicate: response.duplicate,
        invoice_id: response.invoice_id,
        reason: response.reason,
        transaction_id: response.transaction_id,
    }))
}

async fn list_billing_plans(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<BillingPlansQuery>,
) -> Result<Json<BillingPlansListResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;
    let limit = normalize_admin_limit(query.limit);

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListPlansRequest {
            status: query.status.unwrap_or_default(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_plans(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingPlansListResponse {
        plans: response
            .plans
            .into_iter()
            .map(billing_plan_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn create_billing_plan(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateBillingPlanBody>,
) -> Result<Json<BillingPlanResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(CreatePlanRequest {
            plan_code: payload.plan_code,
            name: payload.name,
            description: payload.description.unwrap_or_default(),
            priority: payload.priority.unwrap_or_default(),
            interval: payload.interval,
            price_cents: payload.price_cents,
            currency: payload.currency.unwrap_or_default(),
            device_limit: payload.device_limit,
            storage_limit_bytes: payload.storage_limit_bytes,
            retention_days: payload.retention_days,
            status: payload.status.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .create_plan(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let plan = response.plan.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing plan in response".to_string(),
    ))?;
    audit_control(
        &state,
        &claims.sub,
        "billing.plan.created",
        serde_json::json!({ "plan_id": plan.plan_id }),
    )
    .await;
    Ok(Json(billing_plan_response(plan)))
}

async fn update_billing_plan(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(plan_id): Path<String>,
    Json(payload): Json<UpdateBillingPlanBody>,
) -> Result<Json<BillingPlanResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;
    if plan_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "plan_id is required".to_string()));
    }

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(UpdatePlanRequest {
            plan_id,
            plan_code: payload.plan_code,
            name: payload.name,
            description: payload.description,
            priority: payload.priority,
            interval: payload.interval,
            price_cents: payload.price_cents,
            currency: payload.currency,
            device_limit: payload.device_limit,
            storage_limit_bytes: payload.storage_limit_bytes,
            retention_days: payload.retention_days,
            status: payload.status,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .update_plan(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let plan = response.plan.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing plan in response".to_string(),
    ))?;
    audit_control(
        &state,
        &claims.sub,
        "billing.plan.updated",
        serde_json::json!({ "plan_id": plan.plan_id }),
    )
    .await;
    Ok(Json(billing_plan_response(plan)))
}

async fn delete_billing_plan(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(plan_id): Path<String>,
) -> Result<Json<BillingPlanResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;
    if plan_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "plan_id is required".to_string()));
    }

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(DeletePlanRequest { plan_id });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .delete_plan(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let plan = response.plan.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing plan in response".to_string(),
    ))?;
    audit_control(
        &state,
        &claims.sub,
        "billing.plan.deleted",
        serde_json::json!({ "plan_id": plan.plan_id }),
    )
    .await;
    Ok(Json(billing_plan_response(plan)))
}

async fn list_billing_subscriptions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<BillingSubscriptionsQuery>,
) -> Result<Json<BillingSubscriptionsListResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;
    let limit = normalize_admin_limit(query.limit);

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListSubscriptionsRequest {
            user_id: query.user_id.unwrap_or_default(),
            status: query.status.unwrap_or_default(),
            plan_code: query.plan_code.unwrap_or_default(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_subscriptions(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingSubscriptionsListResponse {
        subscriptions: response
            .subscriptions
            .into_iter()
            .map(billing_subscription_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn create_billing_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateBillingSubscriptionBody>,
) -> Result<Json<BillingSubscriptionResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(CreateSubscriptionRequest {
            user_id: payload.user_id,
            plan_id: payload.plan_id.unwrap_or_default(),
            plan_code: payload.plan_code.unwrap_or_default(),
            status: payload.status.unwrap_or_default(),
            start_date: payload.start_date.unwrap_or_default(),
            end_date: payload.end_date.unwrap_or_default(),
            auto_renew: payload.auto_renew,
            device_count: payload.device_count,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .create_subscription(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let subscription = response.subscription.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing subscription in response".to_string(),
    ))?;
    audit_control(
        &state,
        &claims.sub,
        "subscription.created",
        serde_json::json!({ "subscription_id": subscription.subscription_id, "user_id": subscription.user_id }),
    )
    .await;
    Ok(Json(billing_subscription_response(subscription)))
}

async fn update_billing_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(subscription_id): Path<String>,
    Json(payload): Json<UpdateBillingSubscriptionBody>,
) -> Result<Json<BillingSubscriptionResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;
    if subscription_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subscription_id is required".to_string(),
        ));
    }

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(UpdateSubscriptionRequest {
            subscription_id,
            plan_id: payload.plan_id,
            plan_code: payload.plan_code,
            status: payload.status,
            end_date: payload.end_date,
            auto_renew: payload.auto_renew,
            device_count: payload.device_count,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .update_subscription(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let subscription = response.subscription.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing subscription in response".to_string(),
    ))?;
    audit_control(
        &state,
        &claims.sub,
        "subscription.updated",
        serde_json::json!({ "subscription_id": subscription.subscription_id }),
    )
    .await;
    Ok(Json(billing_subscription_response(subscription)))
}

async fn get_invoice_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<InvoiceSettingsResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;

    let row = sqlx::query(
        "SELECT logo_url, logo_size_px, business_name, business_legal_name, business_address,
                support_phone, invoice_email, updated_by, updated_at
         FROM control_app.invoice_settings
         WHERE singleton = TRUE
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let response = if let Some(row) = row {
        let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
        InvoiceSettingsResponse {
            logo_url: row.get("logo_url"),
            logo_size_px: row.get("logo_size_px"),
            business_name: row.get("business_name"),
            business_legal_name: row.get("business_legal_name"),
            business_address: row.get("business_address"),
            support_phone: row.get("support_phone"),
            invoice_email: row.get("invoice_email"),
            updated_by: row.get("updated_by"),
            updated_at: updated_at.timestamp(),
        }
    } else {
        InvoiceSettingsResponse {
            logo_url: String::new(),
            logo_size_px: 96,
            business_name: "Wildon".to_string(),
            business_legal_name: "Wildon Inc.".to_string(),
            business_address: String::new(),
            support_phone: String::new(),
            invoice_email: "billing@wildon.local".to_string(),
            updated_by: "system".to_string(),
            updated_at: 0,
        }
    };

    Ok(Json(response))
}

async fn upsert_invoice_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<InvoiceSettingsBody>,
) -> Result<Json<InvoiceSettingsResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:settings")?;

    if payload.logo_size_px < 16 || payload.logo_size_px > 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "logo_size_px must be between 16 and 1024".to_string(),
        ));
    }
    if payload.business_name.trim().is_empty()
        || payload.business_legal_name.trim().is_empty()
        || payload.business_address.trim().is_empty()
        || payload.support_phone.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "business_name, business_legal_name, business_address, and support_phone are required"
                .to_string(),
        ));
    }
    let normalized_email = normalize_email(&payload.invoice_email).ok_or((
        StatusCode::BAD_REQUEST,
        "invoice_email must be a valid email".to_string(),
    ))?;

    let updated_by = claims.sub.clone();
    let row = sqlx::query(
        "INSERT INTO control_app.invoice_settings (
            singleton, logo_url, logo_size_px, business_name, business_legal_name, business_address,
            support_phone, invoice_email, updated_by, updated_at
         ) VALUES (
            TRUE, $1, $2, $3, $4, $5, $6, $7, $8, NOW()
         )
         ON CONFLICT (singleton) DO UPDATE SET
            logo_url = EXCLUDED.logo_url,
            logo_size_px = EXCLUDED.logo_size_px,
            business_name = EXCLUDED.business_name,
            business_legal_name = EXCLUDED.business_legal_name,
            business_address = EXCLUDED.business_address,
            support_phone = EXCLUDED.support_phone,
            invoice_email = EXCLUDED.invoice_email,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
         RETURNING logo_url, logo_size_px, business_name, business_legal_name, business_address,
                   support_phone, invoice_email, updated_by, updated_at",
    )
    .bind(payload.logo_url.trim())
    .bind(payload.logo_size_px)
    .bind(payload.business_name.trim())
    .bind(payload.business_legal_name.trim())
    .bind(payload.business_address.trim())
    .bind(payload.support_phone.trim())
    .bind(normalized_email)
    .bind(updated_by)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    Ok(Json(InvoiceSettingsResponse {
        logo_url: row.get("logo_url"),
        logo_size_px: row.get("logo_size_px"),
        business_name: row.get("business_name"),
        business_legal_name: row.get("business_legal_name"),
        business_address: row.get("business_address"),
        support_phone: row.get("support_phone"),
        invoice_email: row.get("invoice_email"),
        updated_by: row.get("updated_by"),
        updated_at: updated_at.timestamp(),
    }))
}

async fn get_device_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DeviceConfigurationPayload>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin", "manager"]) {
        return Err((StatusCode::FORBIDDEN, "device configuration requires manager role or higher".to_string()));
    }

    let row = sqlx::query(
        "SELECT config
         FROM control_app.device_configuration
         WHERE singleton = TRUE
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    if let Some(row) = row {
        let config: JsonValue = row.get("config");
        let payload = serde_json::from_value::<DeviceConfigurationPayload>(config).unwrap_or_else(|_| default_device_config());
        return Ok(Json(payload));
    }

    Ok(Json(default_device_config()))
}

async fn upsert_device_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<DeviceConfigurationPayload>,
) -> Result<Json<DeviceConfigurationPayload>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin", "manager"]) {
        return Err((StatusCode::FORBIDDEN, "device configuration requires manager role or higher".to_string()));
    }

    let config = serde_json::to_value(&payload)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("invalid device configuration: {err}")))?;

    sqlx::query(
        "INSERT INTO control_app.device_configuration (
            singleton, config, updated_by, updated_at
         ) VALUES (
            TRUE, $1, $2, NOW()
         )
         ON CONFLICT (singleton) DO UPDATE SET
            config = control_app.device_configuration.config || EXCLUDED.config,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()",
    )
    .bind(config)
    .bind(claims.sub.clone())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    Ok(Json(payload))
}

fn default_device_config() -> DeviceConfigurationPayload {
    DeviceConfigurationPayload {
        heartbeat_interval: 30,
        offline_threshold: 3,
        session_timeout: 300,
        stale_after_secs: 90,
        command_ack_timeout: 30,
        command_retry_max: 3,
        max_packets_per_sec: 10,
        outlier_rejection: true,
        validation_rules: vec![
            DeviceValidationRule {
                metric: "Heart Rate".to_string(),
                unit: "bpm".to_string(),
                min: 30,
                max: 250,
                action: "flag".to_string(),
            },
            DeviceValidationRule {
                metric: "SpO2".to_string(),
                unit: "%".to_string(),
                min: 70,
                max: 100,
                action: "flag".to_string(),
            },
            DeviceValidationRule {
                metric: "Temperature".to_string(),
                unit: "°C".to_string(),
                min: 30,
                max: 45,
                action: "ignore".to_string(),
            },
            DeviceValidationRule {
                metric: "Systolic BP".to_string(),
                unit: "mmHg".to_string(),
                min: 70,
                max: 200,
                action: "flag".to_string(),
            },
            DeviceValidationRule {
                metric: "Diastolic BP".to_string(),
                unit: "mmHg".to_string(),
                min: 40,
                max: 130,
                action: "flag".to_string(),
            },
        ],
        low_battery_threshold: 20,
        fall_sensitivity: "medium".to_string(),
        geofence_grace_period: 10,
        ack_timeout: 60,
        escalation_behavior: "notify_all".to_string(),
        min_firmware_version: "1.8.0".to_string(),
        firmware_enforcement: "warn".to_string(),
        system_timezone: "UTC".to_string(),
        timestamp_correction: true,
        max_clock_drift: 30,
        auto_decommission_days: 90,
        require_model_assignment: true,
        device_ingestion_enabled: true,
        connection_log_retention_days: 30,
        last_swept_at: None,
    }
}

async fn get_api_integration_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiIntegrationSettingsPayload>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin", "manager"]) {
        return Err((
            StatusCode::FORBIDDEN,
            "api integration settings require manager role or higher".to_string(),
        ));
    }

    let row = sqlx::query(
        "SELECT config
         FROM control_app.api_integration_settings
         WHERE singleton = TRUE
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    if let Some(row) = row {
        let config: JsonValue = row.get("config");
        let payload = serde_json::from_value::<ApiIntegrationSettingsPayload>(config)
            .unwrap_or_else(|_| default_api_integration_settings());
        return Ok(Json(payload));
    }

    Ok(Json(default_api_integration_settings()))
}

async fn upsert_api_integration_settings(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(mut payload): Json<ApiIntegrationSettingsPayload>,
) -> Result<Json<ApiIntegrationSettingsPayload>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin", "manager"]) {
        return Err((
            StatusCode::FORBIDDEN,
            "api integration settings require manager role or higher".to_string(),
        ));
    }

    if payload.webhook_url.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "webhook_url is required".to_string()));
    }
    if payload.retry_attempts < 0 || payload.retry_attempts > 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            "retry_attempts must be between 0 and 10".to_string(),
        ));
    }
    if payload.retry_backoff < 1 || payload.retry_backoff > 3600 {
        return Err((
            StatusCode::BAD_REQUEST,
            "retry_backoff must be between 1 and 3600 seconds".to_string(),
        ));
    }
    if payload.access_token_expiration_hours < 1 || payload.access_token_expiration_hours > 168 {
        return Err((
            StatusCode::BAD_REQUEST,
            "access_token_expiration_hours must be between 1 and 168".to_string(),
        ));
    }
    if payload.refresh_token_expiration_days < 1 || payload.refresh_token_expiration_days > 365 {
        return Err((
            StatusCode::BAD_REQUEST,
            "refresh_token_expiration_days must be between 1 and 365".to_string(),
        ));
    }

    payload.allowed_origins = payload
        .allowed_origins
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();

    let config = serde_json::to_value(&payload)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("invalid api integration settings: {err}")))?;

    sqlx::query(
        "INSERT INTO control_app.api_integration_settings (
            singleton, config, updated_by, updated_at
         ) VALUES (
            TRUE, $1, $2, NOW()
         )
         ON CONFLICT (singleton) DO UPDATE SET
            config = EXCLUDED.config,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()",
    )
    .bind(config)
    .bind(claims.sub.clone())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("database error: {err}")))?;

    Ok(Json(payload))
}

fn default_api_integration_settings() -> ApiIntegrationSettingsPayload {
    ApiIntegrationSettingsPayload {
        webhook_url: "https://api.wildon.com.au/webhooks/events".to_string(),
        retry_attempts: 3,
        retry_backoff: 30,
        webhook_enabled: true,
        allowed_origins: vec![
            "https://my.wildon.com.au".to_string(),
            "https://control.wildon.com.au".to_string(),
            "https://support.wildon.com.au".to_string(),
        ],
        access_token_expiration_hours: 24,
        refresh_token_expiration_days: 30,
    }
}

async fn list_billing_transactions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<BillingListQuery>,
) -> Result<Json<BillingTransactionsListResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;
    let limit = normalize_admin_limit(query.limit);

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListTransactionsRequest {
            user_id: query.user_id.unwrap_or_default(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_transactions(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingTransactionsListResponse {
        transactions: response
            .transactions
            .into_iter()
            .map(billing_transaction_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn list_billing_invoices(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<BillingListQuery>,
) -> Result<Json<BillingInvoicesListResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;
    let limit = normalize_admin_limit(query.limit);

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListInvoicesRequest {
            user_id: query.user_id.unwrap_or_default(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_invoices(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingInvoicesListResponse {
        invoices: response
            .invoices
            .into_iter()
            .map(billing_invoice_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn list_billing_ledger_entries(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<BillingLedgerQuery>,
) -> Result<Json<BillingLedgerListResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;
    let limit = normalize_admin_limit(query.limit);

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListLedgerEntriesRequest {
            user_id: query.user_id.unwrap_or_default(),
            transaction_id: query.transaction_id.unwrap_or_default(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_ledger_entries(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(BillingLedgerListResponse {
        entries: response
            .entries
            .into_iter()
            .map(billing_ledger_entry_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn refund_transaction(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<RefundTransactionBody>,
) -> Result<Json<RefundTransactionApiResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:billing:refund")?;

    if payload.transaction_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "transaction_id is required".to_string(),
        ));
    }
    if payload.amount_cents.unwrap_or_default() < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "amount_cents cannot be negative".to_string(),
        ));
    }

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(RefundTransactionRequest {
            transaction_id: payload.transaction_id,
            amount_cents: payload.amount_cents.unwrap_or_default(),
            reason: payload.reason.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .refund_transaction(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    Ok(Json(RefundTransactionApiResponse {
        refunded: response.refunded,
        reason: response.reason,
        transaction: response.transaction.map(billing_transaction_response),
        invoice: response.invoice.map(billing_invoice_response),
        ledger_entry: response.ledger_entry.map(billing_ledger_entry_response),
    }))
}

/// Fire-and-forget audit event. Errors are logged but never fail the request.
async fn audit_control(state: &AppState, actor_id: &str, action: &str, payload: serde_json::Value) {
    let mut logs_client = state.logs_client.lock().await;
    let mut request = GrpcRequest::new(IngestAuditRequest {
        event_id: Uuid::new_v4().to_string(),
        user_id: actor_id.to_string(),
        action: action.to_string(),
        payload_json: payload.to_string(),
        consumer: "control-service".to_string(),
        canonical_event: None,
    });
    let _ = inject_internal_metadata(&mut request, "control-service", None, None);
    match logs_client.ingest_audit(request).await {
        Ok(_) => tracing::debug!(action, actor_id, "audit event published"),
        Err(e) => tracing::warn!(error = %e, action, "failed to publish audit event"),
    }
}

async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Json<AuditLogsListResponse>, (StatusCode, String)> {
    ensure_any_scope(&claims, &["control:audit:read", "control:admin"])?;

    let limit = normalize_admin_limit(query.limit);
    let response = {
        let mut logs_client = state.logs_client.lock().await;
        let mut request = GrpcRequest::new(ListAuditLogsRequest {
            limit,
            cursor: query.cursor.unwrap_or_default(),
            action: query.action.unwrap_or_default(),
            consumer: query.consumer.unwrap_or_default(),
            user_id: query.user_id.unwrap_or_default(),
            from_unix: query.from.unwrap_or_default(),
            to_unix: query.to.unwrap_or_default(),
            ..Default::default()
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        logs_client
            .list_audit_logs(request)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("logs grpc error: {err}")))?
            .into_inner()
    };

    Ok(Json(AuditLogsListResponse {
        items: response
            .items
            .into_iter()
            .map(audit_log_item_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: if response.next_cursor.trim().is_empty() {
                None
            } else {
                Some(response.next_cursor)
            },
            has_more: response.has_more,
        },
        total: response.total,
    }))
}

async fn list_auditor_logs(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Response, (StatusCode, String)> {
    ensure_scope_or_auditor_read(&claims, "control:admin")?;
    let response = fetch_audit_logs_response(&state, query).await?;
    json_response_for_claims(&claims, &response)
}

async fn list_auditor_audit_trail(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Response, (StatusCode, String)> {
    ensure_scope_or_auditor_read(&claims, "control:admin")?;
    let response = fetch_audit_logs_response(&state, query).await?;
    json_response_for_claims(&claims, &response)
}

async fn get_audit_log(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(event_id): Path<String>,
) -> Result<Json<AuditLogItemResponse>, (StatusCode, String)> {
    ensure_any_scope(&claims, &["control:audit:read", "control:admin"])?;
    if event_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "event_id is required".to_string()));
    }

    let response = {
        let mut logs_client = state.logs_client.lock().await;
        let mut request = GrpcRequest::new(GetAuditLogRequest {
            event_id: event_id.clone(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        logs_client
            .get_audit_log(request)
            .await
            .map_err(|err| match err.code() {
                GrpcCode::NotFound => (StatusCode::NOT_FOUND, "audit log not found".to_string()),
                GrpcCode::InvalidArgument => (StatusCode::BAD_REQUEST, err.message().to_string()),
                _ => (StatusCode::BAD_GATEWAY, format!("logs grpc error: {err}")),
            })?
            .into_inner()
    };

    let item = response
        .item
        .map(audit_log_item_response)
        .ok_or((StatusCode::NOT_FOUND, "audit log not found".to_string()))?;

    Ok(Json(item))
}

async fn list_system_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<SystemSessionsQuery>,
) -> Result<Json<AdminSessionsListResponse>, (StatusCode, String)> {
    ensure_any_scope(&claims, &["control:audit:read", "control:admin", "control:users:list"])?;

    let limit = normalize_admin_limit(query.limit);
    let offset = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))? as i64;

    let normalized_status = query
        .status
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(status) = normalized_status.as_deref() {
        if !matches!(status, "active" | "expired" | "revoked") {
            return Err((StatusCode::BAD_REQUEST, "invalid status".to_string()));
        }
    }

    let q = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"));

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM auth.sessions s
         LEFT JOIN users_app.users u ON u.user_id = s.user_id
         WHERE ($1::TEXT IS NULL
                OR s.id::TEXT ILIKE $1
                OR s.user_id::TEXT ILIKE $1
                OR COALESCE(u.email, '') ILIKE $1
                OR COALESCE(u.full_name, '') ILIKE $1
                OR COALESCE(s.ip_address::TEXT, '') ILIKE $1
                OR COALESCE(s.user_agent, '') ILIKE $1)
           AND ($2::TEXT IS NULL OR
                CASE
                    WHEN s.revoked_at IS NOT NULL THEN 'revoked'
                    WHEN s.expires_at <= NOW() THEN 'expired'
                    ELSE 'active'
                END = $2)",
    )
    .bind(q.as_deref())
    .bind(normalized_status.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let rows = sqlx::query(
        "SELECT s.id::TEXT AS session_id,
                s.user_id::TEXT AS user_id,
                COALESCE(u.email, '') AS user_email,
                COALESCE(NULLIF(BTRIM(u.full_name), ''), 'Unknown User') AS user_name,
                COALESCE(s.ip_address::TEXT, '') AS ip_address,
                COALESCE(s.user_agent, '') AS user_agent,
                COALESCE(s.client_id, '') AS client_id,
                EXTRACT(EPOCH FROM s.created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM s.last_activity_at)::BIGINT AS last_active_at,
                EXTRACT(EPOCH FROM s.expires_at)::BIGINT AS expires_at,
                CASE
                    WHEN s.revoked_at IS NOT NULL THEN 'revoked'
                    WHEN s.expires_at <= NOW() THEN 'expired'
                    ELSE 'active'
                END AS status,
                ARRAY_REMOVE(ARRAY_AGG(DISTINCT r.role), NULL) AS roles
         FROM auth.sessions s
         LEFT JOIN users_app.users u ON u.user_id = s.user_id
         LEFT JOIN users_app.role_assignments r ON r.user_id = s.user_id
         WHERE ($1::TEXT IS NULL
                OR s.id::TEXT ILIKE $1
                OR s.user_id::TEXT ILIKE $1
                OR COALESCE(u.email, '') ILIKE $1
                OR COALESCE(u.full_name, '') ILIKE $1
                OR COALESCE(s.ip_address::TEXT, '') ILIKE $1
                OR COALESCE(s.user_agent, '') ILIKE $1)
           AND ($2::TEXT IS NULL OR
                CASE
                    WHEN s.revoked_at IS NOT NULL THEN 'revoked'
                    WHEN s.expires_at <= NOW() THEN 'expired'
                    ELSE 'active'
                END = $2)
         GROUP BY s.id, s.user_id, u.email, u.full_name, s.ip_address, s.user_agent, s.client_id, s.created_at, s.last_activity_at, s.expires_at, s.revoked_at
         ORDER BY s.last_activity_at DESC
         LIMIT $3 OFFSET $4",
    )
    .bind(q.as_deref())
    .bind(normalized_status.as_deref())
    .bind(i64::from(limit) + 1)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let has_more = rows.len() as u32 > limit;
    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| {
            let user_agent = row.get::<String, _>("user_agent");
            let roles = row.get::<Vec<String>, _>("roles");
            AdminSessionResponse {
                session_id: row.get::<String, _>("session_id"),
                user_id: row.get::<String, _>("user_id"),
                user_email: row.get::<String, _>("user_email"),
                user_name: row.get::<String, _>("user_name"),
                role: session_primary_role(&roles),
                ip_address: row.get::<String, _>("ip_address"),
                user_agent: user_agent.clone(),
                device_hint: session_device_hint(user_agent.as_str(), row.get::<String, _>("client_id").as_str()),
                status: row.get::<String, _>("status"),
                created_at: row.get::<i64, _>("created_at"),
                last_active_at: row.get::<i64, _>("last_active_at"),
                expires_at: row.get::<i64, _>("expires_at"),
            }
        })
        .collect::<Vec<_>>();

    Ok(Json(AdminSessionsListResponse {
        items,
        page: AuditLogsPageResponse {
            limit,
            next_cursor: has_more.then(|| (offset + i64::from(limit)).to_string()),
            has_more,
        },
        total,
    }))
}

async fn revoke_system_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(session_id): Path<String>,
) -> Result<Json<RevokeSessionResponse>, (StatusCode, String)> {
    ensure_any_scope(
        &claims,
        &["control:audit:read", "control:admin", "control:users:manage"],
    )?;
    if session_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "session_id is required".to_string()));
    }

    let result = sqlx::query(
        "UPDATE auth.sessions
         SET revoked_at = NOW()
         WHERE id::TEXT = $1
           AND revoked_at IS NULL",
    )
    .bind(session_id.trim())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    if result.rows_affected() == 0 {
        let exists: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE
             FROM auth.sessions
             WHERE id::TEXT = $1
             LIMIT 1",
        )
        .bind(session_id.trim())
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

        if exists.is_none() {
            return Err((StatusCode::NOT_FOUND, "session not found".to_string()));
        }
    }

    audit_control(
        &state,
        &claims.sub,
        "session.revoked",
        serde_json::json!({ "session_id": session_id }),
    )
    .await;
    Ok(Json(RevokeSessionResponse {
        session_id: session_id.trim().to_string(),
        revoked: true,
    }))
}

async fn list_api_clients(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ApiClientsQuery>,
) -> Result<Json<ApiClientsListResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:read")?;

    let limit = normalize_admin_limit(query.limit).min(200);
    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ListClientsRequest {
            limit,
            cursor: query.cursor.unwrap_or_default(),
            status: query.status.unwrap_or_default(),
            environment: query.environment.unwrap_or_default(),
            surface: query.surface.unwrap_or_default(),
            platform: query.platform.unwrap_or_default(),
            client_type: query.client_type.unwrap_or_default(),
            search: query.search.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .list_clients(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "list api clients failed"))?
            .into_inner()
    };

    Ok(Json(ApiClientsListResponse {
        items: response
            .items
            .into_iter()
            .map(api_client_record_response)
            .collect(),
        page: ApiClientsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
        total: response.total,
    }))
}

async fn get_api_client_by_id(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<ApiClientRecordResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:read")?;
    let client = get_api_client_by_id_grpc(&state, &id).await?;
    Ok(Json(api_client_record_response(client)))
}

async fn get_api_client_by_ref(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(client_ref): Path<String>,
) -> Result<Json<ApiClientRecordResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:read")?;

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(GetClientByRefRequest { client_ref });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .get_client_by_ref(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "get api client by ref failed"))?
            .into_inner()
    };

    let client = response
        .client
        .ok_or((StatusCode::BAD_GATEWAY, "missing api client".to_string()))?;
    Ok(Json(api_client_record_response(client)))
}

async fn create_api_client(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateApiClientBody>,
) -> Result<Json<ApiClientCreateResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:write")?;

    let client_type = parse_api_client_type(payload.client_type.as_str())?;
    let status = payload
        .status
        .as_deref()
        .map(parse_api_client_status)
        .transpose()?
        .unwrap_or(ApiClientStatus::Active as i32);

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ApiCreateClientRequest {
            client_id: payload.client_id,
            display_name: payload.display_name,
            description: payload.description.unwrap_or_default(),
            platform: payload.platform,
            surface: payload.surface,
            environment: payload.environment,
            client_type,
            status,
            allowed_audiences: payload.allowed_audiences,
            allowed_origins: payload.allowed_origins,
            ip_allowlist: payload.ip_allowlist,
            require_mtls: payload.require_mtls.unwrap_or(false),
            is_version_enforced: payload.is_version_enforced.unwrap_or(false),
            min_app_version: payload.min_app_version.unwrap_or_default(),
            max_app_version: payload.max_app_version.unwrap_or_default(),
            user_rate_policy: payload.user_rate_policy,
            client_safety_policy: payload.client_safety_policy,
            created_by: claims.sub.clone(),
            notes: payload.notes.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .create_client(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "create api client failed"))?
            .into_inner()
    };

    let client = response
        .client
        .ok_or((StatusCode::BAD_GATEWAY, "missing api client".to_string()))?;

    audit_control(
        &state,
        &claims.sub,
        "api_client.created",
        serde_json::json!({ "client_id": client.client_id }),
    )
    .await;
    Ok(Json(ApiClientCreateResponse {
        client: api_client_record_response(client),
        secret_plaintext: non_empty(response.secret_plaintext.as_str()).map(ToString::to_string),
    }))
}

async fn update_api_client(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateApiClientBody>,
) -> Result<Json<ApiClientRecordResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:write")?;

    let existing = get_api_client_by_id_grpc(&state, &id).await?;

    let client_type = payload
        .client_type
        .as_deref()
        .map(parse_api_client_type)
        .transpose()?
        .unwrap_or(existing.client_type);

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ApiUpdateClientRequest {
            id: existing.id.clone(),
            display_name: payload
                .display_name
                .unwrap_or_else(|| existing.display_name.clone()),
            description: payload.description.unwrap_or(existing.description.clone()),
            platform: payload.platform.unwrap_or(existing.platform.clone()),
            surface: payload.surface.unwrap_or(existing.surface.clone()),
            environment: payload.environment.unwrap_or(existing.environment.clone()),
            client_type,
            allowed_audiences: payload
                .allowed_audiences
                .unwrap_or_else(|| existing.allowed_audiences.clone()),
            allowed_origins: payload
                .allowed_origins
                .unwrap_or_else(|| existing.allowed_origins.clone()),
            ip_allowlist: payload
                .ip_allowlist
                .unwrap_or_else(|| existing.ip_allowlist.clone()),
            require_mtls: payload.require_mtls.unwrap_or(existing.require_mtls),
            is_version_enforced: payload
                .is_version_enforced
                .unwrap_or(existing.is_version_enforced),
            min_app_version: payload
                .min_app_version
                .unwrap_or(existing.min_app_version.clone()),
            max_app_version: payload
                .max_app_version
                .unwrap_or(existing.max_app_version.clone()),
            user_rate_policy: payload
                .user_rate_policy
                .unwrap_or(existing.user_rate_policy.clone()),
            client_safety_policy: payload
                .client_safety_policy
                .unwrap_or(existing.client_safety_policy.clone()),
            updated_by: claims.sub.clone(),
            notes: payload.notes.unwrap_or(existing.notes.clone()),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .update_client(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "update api client failed"))?
            .into_inner()
    };

    let client = response
        .client
        .ok_or((StatusCode::BAD_GATEWAY, "missing api client".to_string()))?;
    audit_control(
        &state,
        &claims.sub,
        "api_client.updated",
        serde_json::json!({ "client_id": client.client_id }),
    )
    .await;
    Ok(Json(api_client_record_response(client)))
}

async fn set_api_client_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<SetApiClientStatusBody>,
) -> Result<Json<ApiClientRecordResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:status")?;
    let status = parse_api_client_status(payload.status.as_str())?;
    let existing = get_api_client_by_id_grpc(&state, &id).await?;

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ApiSetClientStatusRequest {
            client_id: existing.client_id.clone(),
            status,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .set_client_status(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "set api client status failed"))?
            .into_inner()
    };

    let policy = response.policy.ok_or((
        StatusCode::BAD_GATEWAY,
        "missing api client policy".to_string(),
    ))?;
    let updated = get_api_client_by_id_grpc(&state, &id).await?;
    if policy.client_id != updated.client_id {
        return Err((
            StatusCode::BAD_GATEWAY,
            "status update returned mismatched client".to_string(),
        ));
    }
    audit_control(
        &state,
        &claims.sub,
        "api_client.status.updated",
        serde_json::json!({ "client_id": updated.client_id, "status": payload.status }),
    )
    .await;
    Ok(Json(api_client_record_response(updated)))
}

async fn rotate_api_client_secret(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<RotateApiClientSecretBody>,
) -> Result<Json<ApiClientRotateSecretResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:secrets:rotate")?;

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(RotateClientSecretRequest {
            id,
            rotated_by: claims.sub.clone(),
            expires_at_unix: payload.expires_at_unix.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .rotate_client_secret(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "rotate api client secret failed"))?
            .into_inner()
    };

    let client = response
        .client
        .ok_or((StatusCode::BAD_GATEWAY, "missing api client".to_string()))?;

    audit_control(
        &state,
        &claims.sub,
        "api_client.secret.rotated",
        serde_json::json!({ "client_id": client.client_id }),
    )
    .await;
    Ok(Json(ApiClientRotateSecretResponse {
        client: api_client_record_response(client),
        secret_version: response.secret_version,
        secret_plaintext: response.secret_plaintext,
    }))
}

async fn list_api_client_events(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Query(query): Query<ApiClientEventsQuery>,
) -> Result<Json<ApiClientEventsListResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:audit:read")?;

    let client = get_api_client_by_id_grpc(&state, &id).await?;
    let limit = normalize_admin_limit(query.limit).min(200);
    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ListClientEventsRequest {
            client_id: client.client_id.clone(),
            limit,
            cursor: query.cursor.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .list_client_events(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "list api client events failed"))?
            .into_inner()
    };

    Ok(Json(ApiClientEventsListResponse {
        items: response
            .items
            .into_iter()
            .map(api_client_event_response)
            .collect(),
        page: AuditLogsPageResponse {
            limit,
            next_cursor: non_empty(response.next_cursor.as_str()).map(ToString::to_string),
            has_more: response.has_more,
        },
    }))
}

async fn list_api_client_policies(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ApiClientPoliciesQuery>,
) -> Result<Json<RateLimitPoliciesListResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:clients:read")?;
    let limit = normalize_admin_limit(query.limit).min(200);
    let cursor = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let response = {
        let mut api_clients_client = state.api_clients_client.lock().await;
        let mut request = GrpcRequest::new(ListRateLimitPoliciesRequest {
            scope: query.scope.unwrap_or_default(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        api_clients_client
            .list_rate_limit_policies(request)
            .await
            .map_err(|err| map_api_clients_service_error(err, "list rate policies failed"))?
            .into_inner()
    };

    let mut items = response
        .items
        .into_iter()
        .map(|policy| RateLimitPolicyResponse {
            name: policy.name,
            scope: policy.scope,
            route_group: policy.route_group,
            requests_per_min: policy.requests_per_min,
            requests_per_hour: policy.requests_per_hour,
            burst: policy.burst,
            created_at: policy.created_at,
        })
        .skip(cursor)
        .take((limit as usize).saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = items.len() > limit as usize;
    if has_more {
        items.truncate(limit as usize);
    }

    Ok(Json(RateLimitPoliciesListResponse {
        items,
        page: AuditLogsPageResponse {
            limit,
            next_cursor: if has_more {
                Some(cursor.saturating_add(limit as usize).to_string())
            } else {
                None
            },
            has_more,
        },
    }))
}

async fn list_email_templates(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<EmailTemplatesQuery>,
) -> Result<Json<EmailTemplateListResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;
    let limit = normalize_admin_limit(query.limit);
    let cursor = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let templates = sqlx::query(
        "SELECT template_name, subject_template, html_template, placeholders, created_at, updated_at, updated_by
         FROM control_app.email_templates
         ORDER BY template_name
         LIMIT $1
         OFFSET $2",
    )
    .bind(i64::from(limit + 1))
    .bind(cursor as i64)
    .fetch_all(&state.db)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(email_template_from_row)
            .collect::<Vec<_>>()
    })
    .map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("database error listing templates: {err}"),
        )
    })?;

    let mut templates = templates;
    let has_more = templates.len() > limit as usize;
    if has_more {
        templates.truncate(limit as usize);
    }

    Ok(Json(EmailTemplateListResponse {
        templates,
        page: AuditLogsPageResponse {
            limit,
            next_cursor: if has_more {
                Some(cursor.saturating_add(limit as usize).to_string())
            } else {
                None
            },
            has_more,
        },
    }))
}

async fn get_email_template_mappings(
    Extension(claims): Extension<Claims>,
) -> Result<Json<EmailTemplateMappingsResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;

    let mut mappings = Vec::new();
    for name in notification_templates::SUPPORTED_EMAIL_TEMPLATE_NAMES {
        let Some(description) = notification_templates::template_description(name) else {
            continue;
        };
        let Some(trigger_endpoints) = notification_templates::template_trigger_endpoints(name)
        else {
            continue;
        };

        for endpoint in trigger_endpoints {
            mappings.push(EmailTemplateMappingItem {
                template_name: name.to_string(),
                trigger_endpoint: endpoint.to_string(),
                description: description.to_string(),
            });
        }
    }

    Ok(Json(EmailTemplateMappingsResponse { mappings }))
}

async fn get_email_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(name): Path<String>,
) -> Result<Json<EmailTemplateResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;

    let normalized_name =
        normalize_email_template_name(&name).map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let template = load_email_template(&state, &normalized_name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "template not found".to_string()))?;

    Ok(Json(email_template_response(&template)))
}

async fn upsert_email_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(name): Path<String>,
    Json(payload): Json<UpsertEmailTemplateBody>,
) -> Result<Json<EmailTemplateResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;

    let normalized_name =
        normalize_email_template_name(&name).map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let updated_by = payload
        .updated_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| claims.sub.clone());

    let subject_template =
        notification_templates::sanitize_subject_template(&payload.subject_template)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let html_template = notification_templates::sanitize_html_template(&payload.html_template)
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let placeholders =
        notification_templates::collect_placeholders(&subject_template, &html_template);
    let row = sqlx::query(
        "INSERT INTO control_app.email_templates (
            template_name, subject_template, html_template, placeholders, updated_by, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, NOW(), NOW()
         )
         ON CONFLICT (template_name)
         DO UPDATE SET
            subject_template = EXCLUDED.subject_template,
            html_template = EXCLUDED.html_template,
            placeholders = EXCLUDED.placeholders,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
         RETURNING template_name, subject_template, html_template, placeholders, created_at, updated_at, updated_by",
    )
    .bind(&normalized_name)
    .bind(&subject_template)
    .bind(&html_template)
    .bind(&placeholders)
    .bind(updated_by)
    .fetch_one(&state.db)
    .await
    .map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("database error saving template: {err}"),
        )
    })?;

    Ok(Json(email_template_from_row(row)))
}

async fn delete_email_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;

    let normalized_name =
        normalize_email_template_name(&name).map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let deleted = sqlx::query(
        "DELETE FROM control_app.email_templates
         WHERE template_name = $1",
    )
    .bind(&normalized_name)
    .execute(&state.db)
    .await
    .map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("database error deleting template: {err}"),
        )
    })?;

    if deleted.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "template not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn render_email_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(name): Path<String>,
    Json(payload): Json<RenderTemplateBody>,
) -> Result<Json<RenderTemplateResponse>, (StatusCode, String)> {
    ensure_scope(&claims, "control:admin")?;

    let normalized_name =
        normalize_email_template_name(&name).map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    notification_templates::validate_variables(&payload.variables)
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let template = load_email_template(&state, &normalized_name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "template not found".to_string()))?;

    let subject =
        notification_templates::render_subject(&template.subject_template, &payload.variables)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let html = notification_templates::render_html(&template.html_template, &payload.variables)
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    Ok(Json(RenderTemplateResponse {
        name: template.name,
        subject,
        html,
    }))
}

async fn send_notification(
    State(state): State<AppState>,
    Json(payload): Json<SendNotificationBody>,
) -> Result<Json<SendNotificationApiResponse>, (StatusCode, String)> {
    let channel = match payload.channel.trim().to_lowercase().as_str() {
        "email" => NotificationChannel::Email,
        "sms" => NotificationChannel::Sms,
        "push" => NotificationChannel::Push,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "channel must be one of: email, sms, push".to_string(),
            ))
        }
    };

    let response = dispatch_notification(
        &state,
        payload.user_id,
        channel,
        payload.destination,
        payload.subject,
        payload.message,
    )
    .await?;

    Ok(Json(response))
}

async fn send_templated_email(
    State(state): State<AppState>,
    Json(payload): Json<SendTemplatedEmailBody>,
) -> Result<Json<SendTemplatedEmailResponse>, (StatusCode, String)> {
    if payload.user_id.trim().is_empty() || payload.destination.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "user_id and destination are required".to_string(),
        ));
    }
    let normalized_name = normalize_email_template_name(&payload.template_name)
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    notification_templates::validate_variables(&payload.variables)
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let template = load_email_template(&state, &normalized_name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "template not found".to_string()))?;

    let rendered_subject =
        notification_templates::render_subject(&template.subject_template, &payload.variables)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let rendered_html =
        notification_templates::render_html(&template.html_template, &payload.variables)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let delivery = dispatch_notification(
        &state,
        payload.user_id,
        NotificationChannel::Email,
        payload.destination,
        rendered_subject.clone(),
        rendered_html,
    )
    .await?;

    Ok(Json(SendTemplatedEmailResponse {
        delivered: delivery.delivered,
        provider_used: delivery.provider_used,
        attempted_providers: delivery.attempted_providers,
        failure_reason: delivery.failure_reason,
        template_name: template.name,
        rendered_subject,
    }))
}

fn email_template_response(template: &StoredEmailTemplate) -> EmailTemplateResponse {
    EmailTemplateResponse {
        name: template.name.clone(),
        trigger_endpoints: template.trigger_endpoints.clone(),
        description: template.description.clone(),
        subject_template: template.subject_template.clone(),
        html_template: template.html_template.clone(),
        placeholders: template.placeholders.clone(),
        created_at: template.created_at,
        updated_at: template.updated_at,
        updated_by: template.updated_by.clone(),
    }
}

fn email_template_from_row(row: sqlx::postgres::PgRow) -> EmailTemplateResponse {
    let template = stored_email_template_from_row(row);
    email_template_response(&template)
}

fn stored_email_template_from_row(row: sqlx::postgres::PgRow) -> StoredEmailTemplate {
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let name: String = row.get("template_name");
    let trigger_endpoints = notification_templates::template_trigger_endpoints(&name)
        .unwrap_or_default()
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let description = notification_templates::template_description(&name)
        .unwrap_or("N/A")
        .to_string();

    StoredEmailTemplate {
        name,
        trigger_endpoints,
        description,
        subject_template: row.get("subject_template"),
        html_template: row.get("html_template"),
        placeholders: row.get("placeholders"),
        created_at: created_at.timestamp(),
        updated_at: updated_at.timestamp(),
        updated_by: row.get("updated_by"),
    }
}

async fn load_email_template(
    state: &AppState,
    name: &str,
) -> Result<Option<StoredEmailTemplate>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT template_name, subject_template, html_template, placeholders, created_at, updated_at, updated_by
         FROM control_app.email_templates
         WHERE template_name = $1
         LIMIT 1",
    )
    .bind(name)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("database error loading template: {err}"),
        )
    })?;

    Ok(row.map(stored_email_template_from_row))
}

#[derive(Debug, Clone)]
struct StoredEmailTemplate {
    name: String,
    trigger_endpoints: Vec<String>,
    description: String,
    subject_template: String,
    html_template: String,
    placeholders: Vec<String>,
    created_at: i64,
    updated_at: i64,
    updated_by: String,
}

async fn dispatch_notification(
    state: &AppState,
    user_id: String,
    channel: NotificationChannel,
    destination: String,
    subject: String,
    message: String,
) -> Result<SendNotificationApiResponse, (StatusCode, String)> {
    let response = {
        let mut core_client = state.core_client.lock().await;
        let mut request = GrpcRequest::new(SendNotificationRequest {
            user_id,
            channel: channel as i32,
            destination,
            subject,
            message,
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        core_client
            .send_notification(request)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("core grpc error: {err}")))?
            .into_inner()
    };

    Ok(SendNotificationApiResponse {
        delivered: response.delivered,
        provider_used: response.provider_used,
        attempted_providers: response.attempted_providers,
        failure_reason: response.failure_reason,
    })
}

// =========================================================================
// Regions
// =========================================================================

async fn list_regions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<RegionListResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }

    let rows = sqlx::query(
        "SELECT id, display_ref, name, country, country_code, flag, currency, currency_symbol,
                timezone, address, api_base_url, public_key, secret_key_hint, status, server,
                total_users, total_devices, total_organizations, services, last_rotated_at,
                created_at, updated_at
         FROM control_app.regions
         ORDER BY created_at ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let items = rows.iter().map(region_row_response).collect::<Vec<_>>();
    Ok(Json(RegionListResponse {
        total: items.len(),
        items,
    }))
}

async fn get_region(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<RegionResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }

    let region_id = parse_uuid_param(&id, "region id")?;
    let row = sqlx::query(
        "SELECT id, display_ref, name, country, country_code, flag, currency, currency_symbol,
                timezone, address, api_base_url, public_key, secret_key_hint, status, server,
                total_users, total_devices, total_organizations, services, last_rotated_at,
                created_at, updated_at
         FROM control_app.regions
         WHERE id = $1
         LIMIT 1",
    )
    .bind(region_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "region not found".to_string()))?;

    Ok(Json(region_row_response(&row)))
}

async fn create_region(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CreateRegionBody>,
) -> Result<Json<RegionResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }
    if body.name.trim().is_empty() || body.country.trim().is_empty() || body.api_base_url.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name, country, and api_base_url are required".to_string()));
    }
    if body.public_key.trim().is_empty() || body.secret_key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "public_key and secret_key are required".to_string()));
    }

    let display_ref = generate_display_ref("REG");
    let secret_key_hint = secret_key_hint(&body.secret_key);
    let services_json = serde_json::to_value(body.services.unwrap_or_default())
        .unwrap_or_else(|_| serde_json::json!([]));
    let row = sqlx::query(
        "INSERT INTO control_app.regions
            (display_ref, name, country, country_code, flag, currency, currency_symbol, timezone,
             address, api_base_url, public_key, secret_key, secret_key_hint, status, services)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         RETURNING id, display_ref, name, country, country_code, flag, currency, currency_symbol,
                   timezone, address, api_base_url, public_key, secret_key_hint, status, server,
                   total_users, total_devices, total_organizations, services, last_rotated_at,
                   created_at, updated_at",
    )
    .bind(display_ref)
    .bind(body.name.trim())
    .bind(body.country.trim())
    .bind(body.country_code.trim().to_ascii_uppercase())
    .bind(body.flag.as_deref().unwrap_or(""))
    .bind(body.currency.as_deref().unwrap_or("USD"))
    .bind(body.currency_symbol.as_deref().unwrap_or("$"))
    .bind(body.timezone.as_deref().unwrap_or("UTC"))
    .bind(body.address.as_deref().unwrap_or(""))
    .bind(body.api_base_url.trim())
    .bind(body.public_key.trim())
    .bind(body.secret_key.trim())
    .bind(secret_key_hint)
    .bind(body.status.as_deref().unwrap_or("ONLINE"))
    .bind(services_json)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    Ok(Json(region_row_response(&row)))
}

async fn update_region(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(body): Json<UpdateRegionBody>,
) -> Result<Json<RegionResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }
    let region_id = parse_uuid_param(&id, "region id")?;

    let secret_key_hint = body
        .secret_key
        .as_deref()
        .map(secret_key_hint);

    let services_json = body.services.map(|s| serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!([])));

    let row = sqlx::query(
        "UPDATE control_app.regions SET
            name = COALESCE($2, name),
            country = COALESCE($3, country),
            country_code = COALESCE($4, country_code),
            flag = COALESCE($5, flag),
            currency = COALESCE($6, currency),
            currency_symbol = COALESCE($7, currency_symbol),
            timezone = COALESCE($8, timezone),
            address = COALESCE($9, address),
            api_base_url = COALESCE($10, api_base_url),
            public_key = COALESCE($11, public_key),
            secret_key = COALESCE($12, secret_key),
            secret_key_hint = COALESCE($13, secret_key_hint),
            status = COALESCE($14, status),
            services = COALESCE($15, services),
            updated_at = NOW()
         WHERE id = $1
         RETURNING id, display_ref, name, country, country_code, flag, currency, currency_symbol,
                   timezone, address, api_base_url, public_key, secret_key_hint, status, server,
                   total_users, total_devices, total_organizations, services, last_rotated_at,
                   created_at, updated_at",
    )
    .bind(region_id)
    .bind(body.name.as_deref())
    .bind(body.country.as_deref())
    .bind(body.country_code.as_deref().map(|value| value.to_ascii_uppercase()))
    .bind(body.flag.as_deref())
    .bind(body.currency.as_deref())
    .bind(body.currency_symbol.as_deref())
    .bind(body.timezone.as_deref())
    .bind(body.address.as_deref())
    .bind(body.api_base_url.as_deref())
    .bind(body.public_key.as_deref())
    .bind(body.secret_key.as_deref())
    .bind(secret_key_hint.as_deref())
    .bind(body.status.as_deref())
    .bind(services_json)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "region not found".to_string()))?;

    Ok(Json(region_row_response(&row)))
}

async fn test_region_connection(
    Extension(claims): Extension<Claims>,
    Json(body): Json<TestRegionConnectionBody>,
) -> Result<Json<TestRegionConnectionResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }
    if body.api_base_url.trim().is_empty() || body.public_key.trim().is_empty() || body.secret_key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "api_base_url, public_key, and secret_key are required".to_string()));
    }
    let base_url = body.api_base_url.trim().trim_end_matches('/');
    base_url
        .parse::<axum::http::Uri>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "api_base_url must be a valid URI".to_string()))?;

    let info_url = format!("{base_url}/v1/system/info");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("http client: {e}")))?;

    let start = std::time::Instant::now();
    let resp = client
        .get(&info_url)
        .header("x-public-key", body.public_key.trim())
        .header("x-secret-key", body.secret_key.trim())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("could not reach region API: {e}")))?;
    let latency_ms = start.elapsed().as_millis() as i32;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err((StatusCode::UNAUTHORIZED, "invalid region credentials — check public and secret keys".to_string()));
    }
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err((StatusCode::BAD_GATEWAY, format!("region API returned {status}")));
    }

    let payload: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("invalid response from region API: {e}")))?;

    let server_val = payload.get("server").cloned().unwrap_or_default();
    let mut server = region_server_from_json(&server_val);
    server.api_latency_ms = latency_ms;

    let services: Vec<RegionServiceEntry> = payload
        .get("services")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Ok(Json(TestRegionConnectionResponse {
        connected: true,
        server,
        country: "Unknown".to_string(),
        currency: "USD".to_string(),
        services,
    }))
}

async fn rotate_region_keys(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !has_any_role(&claims, &["superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "rotating region keys requires superadmin role".to_string()));
    }
    let region_id = parse_uuid_param(&id, "region id")?;
    let public_key = format!("pk_live_{}", Uuid::new_v4().simple());
    let secret_key = format!("sk_live_{}", Uuid::new_v4().simple());
    let secret_key_hint = secret_key_hint(&secret_key);

    let updated = sqlx::query(
        "UPDATE control_app.regions SET
            public_key = $2,
            secret_key = $3,
            secret_key_hint = $4,
            last_rotated_at = NOW(),
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(region_id)
    .bind(&public_key)
    .bind(&secret_key)
    .bind(&secret_key_hint)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    if updated.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "region not found".to_string()));
    }

    Ok(Json(serde_json::json!({
        "public_key": public_key,
        "secret_key_hint": secret_key_hint,
    })))
}

async fn sync_region(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<RegionResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }
    let region_id = parse_uuid_param(&id, "region id")?;

    // Fetch stored credentials
    let cred_row = sqlx::query(
        "SELECT api_base_url, public_key, secret_key FROM control_app.regions WHERE id = $1",
    )
    .bind(region_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "region not found".to_string()))?;

    let api_base_url: String = cred_row.get("api_base_url");
    let public_key: String = cred_row.get("public_key");
    let secret_key: String = cred_row.get("secret_key");

    let base_url = api_base_url.trim_end_matches('/');
    let info_url = format!("{base_url}/v1/system/info");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("http client: {e}")))?;

    let start = std::time::Instant::now();
    let resp = client
        .get(&info_url)
        .header("x-public-key", &public_key)
        .header("x-secret-key", &secret_key)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("could not reach region API: {e}")))?;
    let latency_ms = start.elapsed().as_millis() as i64;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err((StatusCode::BAD_GATEWAY, format!("region API returned {status}")));
    }

    let payload: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("invalid response from region API: {e}")))?;

    let server_val = payload.get("server").cloned().unwrap_or_default();
    let mut server = region_server_from_json(&server_val);
    server.api_latency_ms = latency_ms as i32;
    let server_json = serde_json::to_value(&server).unwrap_or_else(|_| serde_json::json!({}));

    let services: Vec<RegionServiceEntry> = payload
        .get("services")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let services_json = serde_json::to_value(&services).unwrap_or_else(|_| serde_json::json!([]));

    // Count platform stats to refresh alongside the server/services sync
    let (total_users, total_organizations) = tokio::join!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM auth.users")
            .fetch_one(&state.db),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_app.organizations")
            .fetch_one(&state.db),
    );
    let total_users = total_users.unwrap_or(0).max(0);
    let total_devices: i64 = 0;
    let total_organizations = total_organizations.unwrap_or(0).max(0);

    let row = sqlx::query(
        "UPDATE control_app.regions SET
            server = $2,
            services = $3,
            total_users = $4,
            total_devices = $5,
            total_organizations = $6,
            updated_at = NOW()
         WHERE id = $1
         RETURNING id, display_ref, name, country, country_code, flag, currency, currency_symbol,
                   timezone, address, api_base_url, public_key, secret_key_hint, status, server,
                   total_users, total_devices, total_organizations, services, last_rotated_at,
                   created_at, updated_at",
    )
    .bind(region_id)
    .bind(server_json)
    .bind(services_json)
    .bind(total_users)
    .bind(total_devices)
    .bind(total_organizations)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "region not found".to_string()))?;

    Ok(Json(region_row_response(&row)))
}

async fn get_region_credentials(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RegionCredentialsResponse>, (StatusCode, String)> {
    if !has_any_role(&claims, &["admin", "superadmin"]) {
        return Err((StatusCode::FORBIDDEN, "region registry requires admin role".to_string()));
    }
    let expected = state.internal_web_token.trim();
    if expected.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "control internal web token is not configured".to_string()));
    }
    let provided = headers
        .get("x-control-internal-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if provided != expected {
        return Err((StatusCode::FORBIDDEN, "invalid internal control token".to_string()));
    }

    let row = if id == "default" {
        sqlx::query(
            "SELECT id, name, api_base_url, public_key, secret_key, status
             FROM control_app.regions
             WHERE services @> '[{\"name\":\"control-service\"}]'::jsonb
             LIMIT 1",
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    } else {
        let region_id = parse_uuid_param(&id, "region id")?;
        sqlx::query(
            "SELECT id, name, api_base_url, public_key, secret_key, status
             FROM control_app.regions
             WHERE id = $1
             LIMIT 1",
        )
        .bind(region_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    }
    .ok_or((StatusCode::NOT_FOUND, "region not found".to_string()))?;

    Ok(Json(RegionCredentialsResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        name: row.get("name"),
        api_base_url: row.get("api_base_url"),
        public_key: row.get("public_key"),
        secret_key: row.get("secret_key"),
        status: row.get("status"),
    }))
}

fn region_row_response(row: &sqlx::postgres::PgRow) -> RegionResponse {
    let server = row
        .get::<Option<JsonValue>, _>("server")
        .unwrap_or_else(|| serde_json::json!({}));
    let server = region_server_from_json(&server);
    let services: Vec<RegionServiceEntry> = row
        .get::<Option<JsonValue>, _>("services")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    RegionResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        display_ref: row.get("display_ref"),
        name: row.get("name"),
        country: row.get("country"),
        country_code: row.get("country_code"),
        flag: row.get("flag"),
        currency: row.get("currency"),
        currency_symbol: row.get("currency_symbol"),
        timezone: row.get("timezone"),
        address: row.get("address"),
        api_base_url: row.get("api_base_url"),
        api_keys: RegionApiKeysResponse {
            public_key: row.get("public_key"),
            secret_key_hint: row.get("secret_key_hint"),
            last_rotated: row
                .get::<chrono::DateTime<chrono::Utc>, _>("last_rotated_at")
                .to_rfc3339(),
        },
        server,
        status: row.get("status"),
        total_users: row.get("total_users"),
        total_devices: row.get("total_devices"),
        total_organizations: row.get("total_organizations"),
        created_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
        updated_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .to_rfc3339(),
        services,
    }
}

fn default_region_server() -> RegionServerResponse {
    RegionServerResponse {
        cpu_cores: 0,
        cpu_usage_percent: 0.0,
        ram_gb: 0,
        ram_usage_percent: 0.0,
        storage_gb: 0,
        storage_usage_percent: 0.0,
        uptime_days: 0,
        api_latency_ms: 0,
    }
}

fn region_server_from_json(value: &JsonValue) -> RegionServerResponse {
    let defaults = default_region_server();
    RegionServerResponse {
        cpu_cores: json_i64(value, "cpu_cores").unwrap_or(defaults.cpu_cores as i64) as i32,
        cpu_usage_percent: json_f64(value, "cpu_usage_percent").unwrap_or(defaults.cpu_usage_percent),
        ram_gb: json_i64(value, "ram_gb").unwrap_or(defaults.ram_gb as i64) as i32,
        ram_usage_percent: json_f64(value, "ram_usage_percent").unwrap_or(defaults.ram_usage_percent),
        storage_gb: json_i64(value, "storage_gb").unwrap_or(defaults.storage_gb as i64) as i32,
        storage_usage_percent: json_f64(value, "storage_usage_percent").unwrap_or(defaults.storage_usage_percent),
        uptime_days: json_i64(value, "uptime_days").unwrap_or(defaults.uptime_days as i64) as i32,
        api_latency_ms: json_i64(value, "api_latency_ms").unwrap_or(defaults.api_latency_ms as i64) as i32,
    }
}

fn json_i64(value: &JsonValue, key: &str) -> Option<i64> {
    value.get(key).and_then(JsonValue::as_i64)
}

fn json_f64(value: &JsonValue, key: &str) -> Option<f64> {
    value.get(key).and_then(JsonValue::as_f64)
}

fn generate_display_ref(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..8].to_ascii_uppercase())
}

fn secret_key_hint(secret: &str) -> String {
    let trimmed = secret.trim();
    let suffix = trimmed
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    if suffix.is_empty() {
        "****".to_string()
    } else {
        format!("****{suffix}")
    }
}

fn parse_uuid_param(raw: &str, field: &str) -> Result<Uuid, (StatusCode, String)> {
    raw.parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid {field}")))
}

// =========================================================================
// Registry Organizations & Professionals
// =========================================================================

#[derive(Debug, Serialize)]
struct OrganizationResponse {
    id: String,
    display_ref: String,
    name: String,
    r#type: String,
    phone: String,
    email: String,
    address: String,
    city: String,
    state: String,
    website: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
    verified: bool,
    verified_at: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct ProfessionalResponse {
    id: String,
    display_ref: String,
    name: String,
    r#type: String,
    specialty: Option<String>,
    phone: String,
    email: String,
    address: Option<String>,
    license_number: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
    organization_id: Option<String>,
    organization_name: Option<String>,
    verified: bool,
    verified_at: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct OrganizationProfessionalsResponse {
    items: Vec<ProfessionalResponse>,
}

#[derive(Debug, Deserialize)]
struct OrganizationListQuery {
    q: Option<String>,
    r#type: Option<String>,
    city: Option<String>,
    verified: Option<bool>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfessionalListQuery {
    q: Option<String>,
    r#type: Option<String>,
    specialty: Option<String>,
    organization_id: Option<String>,
    verified: Option<bool>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateOrganizationBody {
    name: String,
    r#type: String,
    phone: String,
    email: String,
    address: String,
    city: String,
    state: String,
    website: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateOrganizationBody {
    name: Option<String>,
    r#type: Option<String>,
    phone: Option<String>,
    email: Option<String>,
    address: Option<String>,
    city: Option<String>,
    state: Option<String>,
    website: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
    status: Option<String>,
    verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CreateProfessionalBody {
    name: String,
    r#type: String,
    organization_id: Option<String>,
    specialty: Option<String>,
    phone: String,
    email: String,
    address: Option<String>,
    license_number: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateProfessionalBody {
    name: Option<String>,
    r#type: Option<String>,
    organization_id: Option<String>,
    specialty: Option<String>,
    phone: Option<String>,
    email: Option<String>,
    address: Option<String>,
    license_number: Option<String>,
    account_number: Option<String>,
    guardian_account_id: Option<String>,
    status: Option<String>,
    verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct VerificationBody {
    verified: Option<bool>,
}

async fn list_organizations(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Query(query): Query<OrganizationListQuery>,
) -> Result<Json<CursorPage<OrganizationResponse>>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.read")?;

    let limit = normalize_admin_limit(query.limit);
    let offset = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let mut qb = QueryBuilder::<sqlx::Postgres>::new(
        "SELECT id, display_ref, name, type, phone, email, address, city, state, website,
                account_number, guardian_account_id, verified, verified_at, status, created_at, updated_at
         FROM control_app.organizations
         WHERE 1=1",
    );

    if let Some(q) = query.q.as_deref().filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", q.trim().to_lowercase());
        qb.push(" AND (LOWER(name) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(display_ref) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(email) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(city) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(COALESCE(account_number, '')) LIKE ");
        qb.push_bind(pattern);
        qb.push(")");
    }
    if let Some(kind) = query.r#type.as_deref().filter(|value| !value.trim().is_empty()) {
        qb.push(" AND type = ");
        qb.push_bind(kind.trim().to_uppercase());
    }
    if let Some(city) = query.city.as_deref().filter(|value| !value.trim().is_empty()) {
        qb.push(" AND LOWER(city) = ");
        qb.push_bind(city.trim().to_lowercase());
    }
    if let Some(verified) = query.verified {
        qb.push(" AND verified = ");
        qb.push_bind(verified);
    }

    qb.push(" ORDER BY created_at DESC, name ASC LIMIT ");
    qb.push_bind((limit + 1) as i64);
    qb.push(" OFFSET ");
    qb.push_bind(offset as i64);

    let rows = qb
        .build()
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let has_more = rows.len() as u32 > limit;
    let items = rows
        .iter()
        .take(limit as usize)
        .map(organization_from_row)
        .collect::<Vec<_>>();

    Ok(Json(CursorPage {
        data: items,
        pagination: CursorPagination {
            limit,
            next_cursor: has_more.then(|| (offset + limit as usize).to_string()),
            has_more,
        },
    }))
}

async fn get_organization(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<OrganizationResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.read")?;
    let organization_id = parse_uuid_param(&id, "organization id")?;

    let row = sqlx::query(
        "SELECT id, display_ref, name, type, phone, email, address, city, state, website,
                account_number, guardian_account_id, verified, verified_at, status, created_at, updated_at
         FROM control_app.organizations
         WHERE id = $1",
    )
    .bind(organization_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "organization not found".to_string()))?;

    Ok(Json(organization_from_row(&row)))
}

async fn create_organization(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Json(body): Json<CreateOrganizationBody>,
) -> Result<Json<OrganizationResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    validate_required_text(&body.name, "name")?;
    validate_required_text(&body.r#type, "type")?;
    validate_required_text(&body.phone, "phone")?;
    validate_required_text(&body.email, "email")?;
    validate_required_text(&body.address, "address")?;
    validate_required_text(&body.city, "city")?;
    validate_required_text(&body.state, "state")?;

    let row = sqlx::query(
        "INSERT INTO control_app.organizations
            (display_ref, name, type, phone, email, address, city, state, website, account_number, guardian_account_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''))
         RETURNING id, display_ref, name, type, phone, email, address, city, state, website,
                   account_number, guardian_account_id, verified, verified_at, status, created_at, updated_at",
    )
    .bind(generate_display_ref("ORG"))
    .bind(body.name.trim())
    .bind(body.r#type.trim().to_uppercase())
    .bind(body.phone.trim())
    .bind(body.email.trim())
    .bind(body.address.trim())
    .bind(body.city.trim())
    .bind(body.state.trim())
    .bind(body.website.as_deref().unwrap_or("").trim())
    .bind(body.account_number.as_deref().unwrap_or("").trim())
    .bind(body.guardian_account_id.as_deref().unwrap_or("").trim())
    .fetch_one(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    Ok(Json(organization_from_row(&row)))
}

async fn update_organization(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    Json(body): Json<UpdateOrganizationBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    let organization_id = parse_uuid_param(&id, "organization id")?;
    let verified_at = body.verified.map(|value| if value { Some(chrono::Utc::now()) } else { None }).flatten();

    let result = sqlx::query(
        "UPDATE control_app.organizations SET
            name = COALESCE($2, name),
            type = COALESCE($3, type),
            phone = COALESCE($4, phone),
            email = COALESCE($5, email),
            address = COALESCE($6, address),
            city = COALESCE($7, city),
            state = COALESCE($8, state),
            website = COALESCE($9, website),
            account_number = COALESCE($10, account_number),
            guardian_account_id = COALESCE($11, guardian_account_id),
            status = COALESCE($12, status),
            verified = COALESCE($13, verified),
            verified_at = CASE
                WHEN $13 IS NULL THEN verified_at
                WHEN $13 THEN COALESCE($14, verified_at, NOW())
                ELSE NULL
            END,
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(organization_id)
    .bind(body.name.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.r#type.as_deref().map(|value| value.trim().to_uppercase()))
    .bind(body.phone.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.email.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.address.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.city.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.state.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.website.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.account_number.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.guardian_account_id.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.status.as_deref().map(|value| value.trim().to_uppercase()))
    .bind(body.verified)
    .bind(verified_at)
    .execute(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "organization not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "updated": true })))
}

async fn verify_organization(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    body: Option<Json<VerificationBody>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    let organization_id = parse_uuid_param(&id, "organization id")?;
    let verified = body.and_then(|payload| payload.0.verified).unwrap_or(true);

    let result = sqlx::query(
        "UPDATE control_app.organizations
         SET verified = $2,
             verified_at = CASE WHEN $2 THEN NOW() ELSE NULL END,
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(organization_id)
    .bind(verified)
    .execute(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "organization not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "id": id, "verified": verified })))
}

async fn list_organization_professionals(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<OrganizationProfessionalsResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.read")?;
    let organization_id = parse_uuid_param(&id, "organization id")?;

    let rows = sqlx::query(
        "SELECT p.id, p.display_ref, p.name, p.type, p.specialty, p.phone, p.email, p.address,
                p.license_number, p.account_number, p.guardian_account_id, p.organization_id,
                o.name AS organization_name, p.verified, p.verified_at, p.status, p.created_at, p.updated_at
         FROM control_app.professionals p
         LEFT JOIN control_app.organizations o ON o.id = p.organization_id
         WHERE p.organization_id = $1
         ORDER BY p.created_at DESC, p.name ASC",
    )
    .bind(organization_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    Ok(Json(OrganizationProfessionalsResponse {
        items: rows.iter().map(professional_from_row).collect(),
    }))
}

async fn list_professionals(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Query(query): Query<ProfessionalListQuery>,
) -> Result<Json<CursorPage<ProfessionalResponse>>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.read")?;

    let limit = normalize_admin_limit(query.limit);
    let offset = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let mut qb = QueryBuilder::<sqlx::Postgres>::new(
        "SELECT p.id, p.display_ref, p.name, p.type, p.specialty, p.phone, p.email, p.address,
                p.license_number, p.account_number, p.guardian_account_id, p.organization_id,
                o.name AS organization_name, p.verified, p.verified_at, p.status, p.created_at, p.updated_at
         FROM control_app.professionals p
         LEFT JOIN control_app.organizations o ON o.id = p.organization_id
         WHERE 1=1",
    );

    if let Some(q) = query.q.as_deref().filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", q.trim().to_lowercase());
        qb.push(" AND (LOWER(p.name) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(p.display_ref) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(p.email) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(COALESCE(p.specialty, '')) LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR LOWER(COALESCE(o.name, '')) LIKE ");
        qb.push_bind(pattern);
        qb.push(")");
    }
    if let Some(kind) = query.r#type.as_deref().filter(|value| !value.trim().is_empty()) {
        qb.push(" AND p.type = ");
        qb.push_bind(kind.trim().to_uppercase());
    }
    if let Some(specialty) = query.specialty.as_deref().filter(|value| !value.trim().is_empty()) {
        qb.push(" AND LOWER(COALESCE(p.specialty, '')) LIKE ");
        qb.push_bind(format!("%{}%", specialty.trim().to_lowercase()));
    }
    if let Some(org_id) = query.organization_id.as_deref().filter(|value| !value.trim().is_empty()) {
        qb.push(" AND p.organization_id = ");
        qb.push_bind(parse_uuid_param(org_id, "organization id")?);
    }
    if let Some(verified) = query.verified {
        qb.push(" AND p.verified = ");
        qb.push_bind(verified);
    }

    qb.push(" ORDER BY p.created_at DESC, p.name ASC LIMIT ");
    qb.push_bind((limit + 1) as i64);
    qb.push(" OFFSET ");
    qb.push_bind(offset as i64);

    let rows = qb
        .build()
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let has_more = rows.len() as u32 > limit;
    let items = rows
        .iter()
        .take(limit as usize)
        .map(professional_from_row)
        .collect::<Vec<_>>();

    Ok(Json(CursorPage {
        data: items,
        pagination: CursorPagination {
            limit,
            next_cursor: has_more.then(|| (offset + limit as usize).to_string()),
            has_more,
        },
    }))
}

async fn get_professional(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<ProfessionalResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.read")?;
    let professional_id = parse_uuid_param(&id, "professional id")?;

    let row = sqlx::query(
        "SELECT p.id, p.display_ref, p.name, p.type, p.specialty, p.phone, p.email, p.address,
                p.license_number, p.account_number, p.guardian_account_id, p.organization_id,
                o.name AS organization_name, p.verified, p.verified_at, p.status, p.created_at, p.updated_at
         FROM control_app.professionals p
         LEFT JOIN control_app.organizations o ON o.id = p.organization_id
         WHERE p.id = $1",
    )
    .bind(professional_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "professional not found".to_string()))?;

    Ok(Json(professional_from_row(&row)))
}

async fn create_professional(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Json(body): Json<CreateProfessionalBody>,
) -> Result<Json<ProfessionalResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    validate_required_text(&body.name, "name")?;
    validate_required_text(&body.r#type, "type")?;
    validate_required_text(&body.phone, "phone")?;
    validate_required_text(&body.email, "email")?;
    let organization_id = body
        .organization_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_uuid_param(value, "organization id"))
        .transpose()?;

    let row = sqlx::query(
        "INSERT INTO control_app.professionals
            (display_ref, name, type, specialty, phone, email, address, license_number,
             account_number, guardian_account_id, organization_id)
         VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), NULLIF($8, ''),
                 NULLIF($9, ''), NULLIF($10, ''), $11)
         RETURNING id, display_ref, name, type, specialty, phone, email, address,
                   license_number, account_number, guardian_account_id, organization_id,
                   verified, verified_at, status, created_at, updated_at",
    )
    .bind(generate_display_ref("PRO"))
    .bind(body.name.trim())
    .bind(body.r#type.trim().to_uppercase())
    .bind(body.specialty.as_deref().unwrap_or("").trim())
    .bind(body.phone.trim())
    .bind(body.email.trim())
    .bind(body.address.as_deref().unwrap_or("").trim())
    .bind(body.license_number.as_deref().unwrap_or("").trim())
    .bind(body.account_number.as_deref().unwrap_or("").trim())
    .bind(body.guardian_account_id.as_deref().unwrap_or("").trim())
    .bind(organization_id)
    .fetch_one(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    let organization_name = match row.get::<Option<Uuid>, _>("organization_id") {
        Some(org_id) => fetch_organization_name(&state, org_id).await,
        None => None,
    };

    Ok(Json(professional_from_created_row(&row, organization_name)))
}

async fn update_professional(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    Json(body): Json<UpdateProfessionalBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    let professional_id = parse_uuid_param(&id, "professional id")?;
    let organization_id = body
        .organization_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_uuid_param(value, "organization id"))
        .transpose()?;
    let verified_at = body.verified.map(|value| if value { Some(chrono::Utc::now()) } else { None }).flatten();

    let result = sqlx::query(
        "UPDATE control_app.professionals SET
            name = COALESCE($2, name),
            type = COALESCE($3, type),
            organization_id = COALESCE($4, organization_id),
            specialty = COALESCE($5, specialty),
            phone = COALESCE($6, phone),
            email = COALESCE($7, email),
            address = COALESCE($8, address),
            license_number = COALESCE($9, license_number),
            account_number = COALESCE($10, account_number),
            guardian_account_id = COALESCE($11, guardian_account_id),
            status = COALESCE($12, status),
            verified = COALESCE($13, verified),
            verified_at = CASE
                WHEN $13 IS NULL THEN verified_at
                WHEN $13 THEN COALESCE($14, verified_at, NOW())
                ELSE NULL
            END,
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(professional_id)
    .bind(body.name.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.r#type.as_deref().map(|value| value.trim().to_uppercase()))
    .bind(organization_id)
    .bind(body.specialty.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.phone.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.email.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.address.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.license_number.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.account_number.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.guardian_account_id.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(body.status.as_deref().map(|value| value.trim().to_uppercase()))
    .bind(body.verified)
    .bind(verified_at)
    .execute(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "professional not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "updated": true })))
}

async fn verify_professional(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    body: Option<Json<VerificationBody>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.registry.write")?;
    let professional_id = parse_uuid_param(&id, "professional id")?;
    let verified = body.and_then(|payload| payload.0.verified).unwrap_or(true);

    let result = sqlx::query(
        "UPDATE control_app.professionals
         SET verified = $2,
             verified_at = CASE WHEN $2 THEN NOW() ELSE NULL END,
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(professional_id)
    .bind(verified)
    .execute(&state.db)
    .await
    .map_err(map_registry_write_error)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "professional not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "id": id, "verified": verified })))
}

fn organization_from_row(row: &sqlx::postgres::PgRow) -> OrganizationResponse {
    OrganizationResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        display_ref: row.get("display_ref"),
        name: row.get("name"),
        r#type: row.get("type"),
        phone: row.get("phone"),
        email: row.get("email"),
        address: row.get("address"),
        city: row.get("city"),
        state: row.get("state"),
        website: row.get("website"),
        account_number: row.get("account_number"),
        guardian_account_id: row.get("guardian_account_id"),
        verified: row.get("verified"),
        verified_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at")
            .map(|value| value.to_rfc3339()),
        status: row.get("status"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }
}

fn professional_from_row(row: &sqlx::postgres::PgRow) -> ProfessionalResponse {
    ProfessionalResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        display_ref: row.get("display_ref"),
        name: row.get("name"),
        r#type: row.get("type"),
        specialty: row.get("specialty"),
        phone: row.get("phone"),
        email: row.get("email"),
        address: row.get("address"),
        license_number: row.get("license_number"),
        account_number: row.get("account_number"),
        guardian_account_id: row.get("guardian_account_id"),
        organization_id: row
            .get::<Option<Uuid>, _>("organization_id")
            .map(|value| value.to_string()),
        organization_name: row.get("organization_name"),
        verified: row.get("verified"),
        verified_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at")
            .map(|value| value.to_rfc3339()),
        status: row.get("status"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }
}

fn professional_from_created_row(
    row: &sqlx::postgres::PgRow,
    organization_name: Option<String>,
) -> ProfessionalResponse {
    ProfessionalResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        display_ref: row.get("display_ref"),
        name: row.get("name"),
        r#type: row.get("type"),
        specialty: row.get("specialty"),
        phone: row.get("phone"),
        email: row.get("email"),
        address: row.get("address"),
        license_number: row.get("license_number"),
        account_number: row.get("account_number"),
        guardian_account_id: row.get("guardian_account_id"),
        organization_id: row
            .get::<Option<Uuid>, _>("organization_id")
            .map(|value| value.to_string()),
        organization_name,
        verified: row.get("verified"),
        verified_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at")
            .map(|value| value.to_rfc3339()),
        status: row.get("status"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }
}

async fn fetch_organization_name(state: &AppState, organization_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT name FROM control_app.organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

fn validate_required_text(value: &str, field: &str) -> Result<(), (StatusCode, String)> {
    if value.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, format!("{field} is required")));
    }
    Ok(())
}

fn map_registry_write_error(err: sqlx::Error) -> (StatusCode, String) {
    match err {
        sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
            (StatusCode::CONFLICT, db_err.message().to_string())
        }
        other => (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {other}")),
    }
}

// =========================================================================
// Device Categories
// =========================================================================

#[derive(Debug, Serialize)]
struct DeviceCategoryResponse {
    id: String,
    name: String,
    slug: String,
    description: String,
    status: String,
    models_count: i64,
    total_devices: i64,
    assigned_devices: i64,
    available_devices: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateDeviceCategoryBody {
    name: String,
    slug: Option<String>,
    description: Option<String>,
    status: Option<String>,
    sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct UpdateDeviceCategoryBody {
    name: Option<String>,
    slug: Option<String>,
    description: Option<String>,
    status: Option<String>,
    sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct DeviceCategoryQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_device_categories(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Query(query): Query<DeviceCategoryQuery>,
) -> Result<Json<CursorPage<DeviceCategoryResponse>>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_categories.read")?;

    let status_filter = query.status;
    let limit = normalize_admin_limit(query.limit);
    let offset = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let rows = sqlx::query(
        "SELECT c.id, c.name, c.description, c.status, c.sort_order, c.created_at, c.updated_at,
                COALESCE((SELECT COUNT(*) FROM control_app.device_models m WHERE m.category_id = c.id), 0) AS models_count
         FROM control_app.device_categories c
         WHERE ($1::TEXT IS NULL OR c.status = $1)
         ORDER BY c.sort_order ASC, c.id ASC
         LIMIT $2 OFFSET $3",
    )
    .bind(status_filter.as_deref())
    .bind((limit + 1) as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let has_more = rows.len() as u32 > limit;
    let categories = rows
        .iter()
        .take(limit as usize)
        .map(|r| DeviceCategoryResponse {
            id: r.get::<Uuid, _>("id").to_string(),
            name: r.get("name"),
            slug: slugify(&r.get::<String, _>("name")),
            description: r.get::<Option<String>, _>("description").unwrap_or_default(),
            status: r.get("status"),
            models_count: r.get("models_count"),
            total_devices: 0,
            assigned_devices: 0,
            available_devices: 0,
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            updated_at: r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        })
        .collect::<Vec<_>>();

    Ok(Json(CursorPage {
        data: categories,
        pagination: CursorPagination {
            limit,
            next_cursor: has_more.then(|| (offset + limit as usize).to_string()),
            has_more,
        },
    }))
}

async fn get_device_category(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<DeviceCategoryResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_categories.read")?;
    let cat_id = parse_uuid_param(&id, "category id")?;

    let row = sqlx::query(
        "SELECT c.id, c.name, c.description, c.status, c.sort_order, c.created_at, c.updated_at,
                COALESCE((SELECT COUNT(*) FROM control_app.device_models m WHERE m.category_id = c.id), 0) AS models_count
         FROM control_app.device_categories c WHERE c.id = $1",
    )
    .bind(cat_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "category not found".to_string()))?;

    Ok(Json(DeviceCategoryResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        name: row.get("name"),
        slug: slugify(&row.get::<String, _>("name")),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        status: row.get("status"),
        models_count: row.get("models_count"),
        total_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn create_device_category(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Json(body): Json<CreateDeviceCategoryBody>,
) -> Result<Json<DeviceCategoryResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_categories.write")?;
    if body.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO control_app.device_categories (name, description, status, sort_order)
         VALUES ($1, $2, $3, $4)
         RETURNING id, name, description, status, created_at, updated_at",
    )
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(body.status.as_deref().unwrap_or("active"))
    .bind(body.sort_order.unwrap_or(0))
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(Json(DeviceCategoryResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        name: row.get("name"),
        slug: body.slug.unwrap_or_else(|| slugify(body.name.trim())),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        status: row.get("status"),
        models_count: 0,
        total_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn update_device_category(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDeviceCategoryBody>,
) -> Result<Json<DeviceCategoryResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_categories.write")?;
    let cat_id = parse_uuid_param(&id, "category id")?;

    let row = sqlx::query(
        "UPDATE control_app.device_categories SET
            name = COALESCE($2, name),
            description = COALESCE($3, description),
            status = COALESCE($4, status),
            sort_order = COALESCE($5, sort_order),
            updated_at = NOW()
         WHERE id = $1
         RETURNING id, name, description, status, created_at, updated_at",
    )
    .bind(cat_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.status)
    .bind(body.sort_order)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "category not found".to_string()))?;

    Ok(Json(DeviceCategoryResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        name: row.get("name"),
        slug: body
            .slug
            .or_else(|| Some(slugify(&row.get::<String, _>("name"))))
            .unwrap_or_default(),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        status: row.get("status"),
        models_count: 0,
        total_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn delete_device_category(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_categories.write")?;
    let cat_id = parse_uuid_param(&id, "category id")?;
    let in_use: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_app.device_models WHERE category_id = $1",
    )
    .bind(cat_id)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;
    if in_use > 0 {
        sqlx::query(
            "UPDATE control_app.device_categories
             SET status = 'archived', updated_at = NOW()
             WHERE id = $1",
        )
        .bind(cat_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;
        return Ok(Json(serde_json::json!({
            "deleted": false,
            "status": "archived",
            "reason": "category is still referenced by device models"
        })));
    }

    let result = sqlx::query("DELETE FROM control_app.device_categories WHERE id = $1")
        .bind(cat_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "category not found".to_string()));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

// =========================================================================
// Device Models
// =========================================================================

#[derive(Debug, Serialize)]
struct DeviceModelResponse {
    id: String,
    slug: String,
    category_id: String,
    category_name: String,
    model_code: String,
    name: String,
    firmware_version: String,
    manufacturer: String,
    description: String,
    protocol: String,
    connectivity: String,
    features: Vec<String>,
    status: String,
    device_count: i64,
    active_devices: i64,
    assigned_devices: i64,
    available_devices: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateDeviceModelBody {
    category_id: String,
    slug: Option<String>,
    model_code: String,
    name: String,
    firmware_version: Option<String>,
    manufacturer: Option<String>,
    description: Option<String>,
    protocol: Option<String>,
    connectivity: Option<String>,
    features: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateDeviceModelBody {
    category_id: Option<String>,
    slug: Option<String>,
    name: Option<String>,
    firmware_version: Option<String>,
    manufacturer: Option<String>,
    description: Option<String>,
    protocol: Option<String>,
    connectivity: Option<String>,
    features: Option<Vec<String>>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceModelQuery {
    status: Option<String>,
    category_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_device_models(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Query(query): Query<DeviceModelQuery>,
) -> Result<Json<CursorPage<DeviceModelResponse>>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_models.read")?;

    let limit = normalize_admin_limit(query.limit);
    let offset = parse_offset_cursor(query.cursor.as_deref())
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let mut sql = String::from(
        "SELECT m.*, c.name AS category_name
         FROM control_app.device_models m
         JOIN control_app.device_categories c ON c.id = m.category_id
         WHERE 1=1",
    );
    if query.status.is_some() {
        sql.push_str(" AND m.status = $1");
    }
    if query.category_id.is_some() {
        sql.push_str(if query.status.is_some() {
            " AND m.category_id = $2"
        } else {
            " AND m.category_id = $1"
        });
    }
    sql.push_str(" ORDER BY c.sort_order, m.model_code LIMIT $");
    let limit_pos = if query.status.is_some() && query.category_id.is_some() {
        3
    } else if query.status.is_some() || query.category_id.is_some() {
        2
    } else {
        1
    };
    sql.push_str(&limit_pos.to_string());
    sql.push_str(" OFFSET $");
    sql.push_str(&(limit_pos + 1).to_string());

    let mut q = sqlx::query(&sql);
    if let Some(ref status) = query.status {
        q = q.bind(status);
    }
    if let Some(ref cat_id) = query.category_id {
        let cid: Uuid = cat_id
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, "bad category_id".to_string()))?;
        q = q.bind(cid);
    }
    q = q.bind((limit + 1) as i64).bind(offset as i64);

    let rows = q
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let has_more = rows.len() as u32 > limit;
    let models = rows
        .iter()
        .take(limit as usize)
        .map(|r| DeviceModelResponse {
            id: r.get::<Uuid, _>("id").to_string(),
            slug: slugify(&r.get::<String, _>("model_code")),
            category_id: r.get::<Uuid, _>("category_id").to_string(),
            category_name: r.get("category_name"),
            model_code: r.get("model_code"),
            name: r.get("name"),
            firmware_version: String::new(),
            manufacturer: r.get("manufacturer"),
            description: r.get::<Option<String>, _>("description").unwrap_or_default(),
            protocol: r.get("protocol"),
            connectivity: r.get("connectivity"),
            features: json_string_array(&r.get::<serde_json::Value, _>("features")),
            status: r.get("status"),
            device_count: 0,
            active_devices: 0,
            assigned_devices: 0,
            available_devices: 0,
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            updated_at: r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        })
        .collect::<Vec<_>>();

    Ok(Json(CursorPage {
        data: models,
        pagination: CursorPagination {
            limit,
            next_cursor: has_more.then(|| (offset + limit as usize).to_string()),
            has_more,
        },
    }))
}

async fn get_device_model(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<DeviceModelResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_models.read")?;
    let model_id = parse_uuid_param(&id, "model id")?;

    let row = sqlx::query(
        "SELECT m.*, c.name AS category_name
         FROM control_app.device_models m
         JOIN control_app.device_categories c ON c.id = m.category_id
         WHERE m.id = $1",
    )
    .bind(model_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "model not found".to_string()))?;

    Ok(Json(DeviceModelResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        slug: slugify(&row.get::<String, _>("model_code")),
        category_id: row.get::<Uuid, _>("category_id").to_string(),
        category_name: row.get("category_name"),
        model_code: row.get("model_code"),
        name: row.get("name"),
        firmware_version: String::new(),
        manufacturer: row.get("manufacturer"),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        protocol: row.get("protocol"),
        connectivity: row.get("connectivity"),
        features: json_string_array(&row.get::<serde_json::Value, _>("features")),
        status: row.get("status"),
        device_count: 0,
        active_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn create_device_model(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Json(body): Json<CreateDeviceModelBody>,
) -> Result<Json<DeviceModelResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_models.write")?;
    let cat_id: Uuid = body.category_id.parse().map_err(|_| (StatusCode::BAD_REQUEST, "bad category_id".to_string()))?;

    let row = sqlx::query(
        "INSERT INTO control_app.device_models
            (category_id, model_code, name, manufacturer, description, protocol, connectivity, features)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *",
    )
    .bind(cat_id)
    .bind(body.model_code.trim())
    .bind(body.name.trim())
    .bind(body.manufacturer.as_deref().unwrap_or("JiAi Medical"))
    .bind(&body.description)
    .bind(body.protocol.as_deref().unwrap_or("IW"))
    .bind(body.connectivity.as_deref().unwrap_or("4G"))
    .bind(serde_json::json!(body.features.unwrap_or_default()))
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    // Get category name
    let cat_name: String =
        sqlx::query_scalar("SELECT name FROM control_app.device_categories WHERE id = $1")
            .bind(cat_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or_default();

    Ok(Json(DeviceModelResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        slug: body
            .slug
            .unwrap_or_else(|| slugify(body.model_code.trim())),
        category_id: row.get::<Uuid, _>("category_id").to_string(),
        category_name: cat_name,
        model_code: row.get("model_code"),
        name: row.get("name"),
        firmware_version: body.firmware_version.unwrap_or_default(),
        manufacturer: row.get("manufacturer"),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        protocol: row.get("protocol"),
        connectivity: row.get("connectivity"),
        features: json_string_array(&row.get::<serde_json::Value, _>("features")),
        status: row.get("status"),
        device_count: 0,
        active_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn update_device_model(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDeviceModelBody>,
) -> Result<Json<DeviceModelResponse>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_models.write")?;
    let model_id = parse_uuid_param(&id, "model id")?;
    let cat_id: Option<Uuid> = body.category_id.as_ref().map(|c| c.parse()).transpose().map_err(|_| (StatusCode::BAD_REQUEST, "bad category_id".to_string()))?;

    let row = sqlx::query(
        "UPDATE control_app.device_models SET
            category_id = COALESCE($2, category_id),
            name = COALESCE($3, name),
            manufacturer = COALESCE($4, manufacturer),
            description = COALESCE($5, description),
            protocol = COALESCE($6, protocol),
            connectivity = COALESCE($7, connectivity),
            features = COALESCE($8, features),
            status = COALESCE($9, status),
            updated_at = NOW()
         WHERE id = $1
         RETURNING *",
    )
    .bind(model_id)
    .bind(cat_id)
    .bind(&body.name)
    .bind(&body.manufacturer)
    .bind(&body.description)
    .bind(&body.protocol)
    .bind(&body.connectivity)
    .bind(body.features.as_ref().map(|items| serde_json::json!(items)))
    .bind(&body.status)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "model not found".to_string()))?;

    let category_name: String = sqlx::query_scalar(
        "SELECT name FROM control_app.device_categories WHERE id = $1",
    )
    .bind(row.get::<Uuid, _>("category_id"))
    .fetch_one(&state.db)
    .await
    .unwrap_or_default();

    Ok(Json(DeviceModelResponse {
        id: row.get::<Uuid, _>("id").to_string(),
        slug: body
            .slug
            .unwrap_or_else(|| slugify(&row.get::<String, _>("model_code"))),
        category_id: row.get::<Uuid, _>("category_id").to_string(),
        category_name,
        model_code: row.get("model_code"),
        name: row.get("name"),
        firmware_version: body.firmware_version.unwrap_or_default(),
        manufacturer: row.get("manufacturer"),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        protocol: row.get("protocol"),
        connectivity: row.get("connectivity"),
        features: json_string_array(&row.get::<serde_json::Value, _>("features")),
        status: row.get("status"),
        device_count: 0,
        active_devices: 0,
        assigned_devices: 0,
        available_devices: 0,
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    }))
}

async fn delete_device_model(
    State(state): State<AppState>,
    Extension(client): Extension<SystemApiClientContext>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_system_scope(&client, "system.device_models.write")?;
    let model_id = parse_uuid_param(&id, "model id")?;
    let row = sqlx::query(
        "SELECT model_code FROM control_app.device_models WHERE id = $1 LIMIT 1",
    )
    .bind(model_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "model not found".to_string()))?;
    let _model_code: String = row.get("model_code");
    sqlx::query("DELETE FROM control_app.device_models WHERE id = $1")
        .bind(model_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

fn json_string_array(value: &JsonValue) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

// =========================================================================
// Apps
// =========================================================================

async fn get_apps_overview(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<AppsOverviewResponse>, (StatusCode, String)> {
    ensure_apps_read_access(&claims)?;
    let rows = sqlx::query(
        "SELECT *
         FROM control_app.system_apps
         ORDER BY platform ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let apps = rows
        .iter()
        .map(app_record_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    let total_registered_users = apps
        .iter()
        .map(|app| app.stats.registered_users)
        .sum::<i64>();
    let total_users_online = apps.iter().map(|app| app.stats.users_online).sum::<i64>();
    let total_guests = apps.iter().map(|app| app.stats.guests_count).sum::<i64>();

    Ok(Json(AppsOverviewResponse {
        total_registered_users,
        total_users_online,
        total_guests,
        apps,
    }))
}

async fn list_apps(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<AppListQuery>,
) -> Result<Json<AppsListResponse>, (StatusCode, String)> {
    ensure_apps_read_access(&claims)?;
    let q = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"));
    let status = query
        .status
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    if let Some(value) = status.as_deref() {
        if !matches!(value, "online" | "maintenance" | "degraded" | "offline") {
            return Err((StatusCode::BAD_REQUEST, "invalid status".to_string()));
        }
    }

    let rows = sqlx::query(
        "SELECT *
         FROM control_app.system_apps
         WHERE ($1::TEXT IS NULL
                OR platform ILIKE $1
                OR display_name ILIKE $1
                OR description ILIKE $1)
           AND ($2::TEXT IS NULL OR status = $2)
         ORDER BY platform ASC",
    )
    .bind(q.as_deref())
    .bind(status.as_deref())
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let apps = rows
        .iter()
        .map(app_record_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(AppsListResponse { apps }))
}

async fn get_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(platform): Path<String>,
) -> Result<Json<AppDetailResponse>, (StatusCode, String)> {
    ensure_apps_read_access(&claims)?;
    let platform = normalize_app_platform(platform.as_str())?;

    let row = sqlx::query(
        "SELECT *
         FROM control_app.system_apps
         WHERE platform = $1",
    )
    .bind(platform.as_str())
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "app not found".to_string()))?;

    let app = app_record_from_row(&row)?;
    let version_rows = sqlx::query(
        "SELECT version,
                released_at,
                release_notes,
                api_version,
                rollout_percentage,
                channel,
                status
         FROM control_app.system_app_versions
         WHERE platform = $1
         ORDER BY released_at DESC",
    )
    .bind(platform.as_str())
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let version_history = version_rows
        .into_iter()
        .map(|value| AppVersionHistoryResponse {
            version: value.get::<String, _>("version"),
            released_at: value
                .get::<chrono::DateTime<chrono::Utc>, _>("released_at")
                .to_rfc3339(),
            release_notes: value.get::<String, _>("release_notes"),
            api_version: value.get::<String, _>("api_version"),
            rollout_percentage: value.get::<i32, _>("rollout_percentage"),
            channel: value.get::<String, _>("channel"),
            status: value.get::<String, _>("status"),
        })
        .collect::<Vec<_>>();

    Ok(Json(AppDetailResponse {
        app,
        version_history,
    }))
}

async fn get_app_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(platform): Path<String>,
) -> Result<Json<AppStatsResponse>, (StatusCode, String)> {
    ensure_apps_read_access(&claims)?;
    let platform = normalize_app_platform(platform.as_str())?;

    let row = sqlx::query(
        "SELECT stats_guests_count,
                stats_registered_users,
                stats_users_online,
                stats_peak_online_today,
                stats_avg_session_minutes,
                stats_crash_rate_percent,
                stats_api_status,
                stats_api_latency_ms,
                stats_device_distribution
         FROM control_app.system_apps
         WHERE platform = $1",
    )
    .bind(platform.as_str())
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "app not found".to_string()))?;

    Ok(Json(AppStatsResponse {
        guests_count: row.get::<i64, _>("stats_guests_count"),
        registered_users: row.get::<i64, _>("stats_registered_users"),
        users_online: row.get::<i64, _>("stats_users_online"),
        peak_online_today: row.get::<i64, _>("stats_peak_online_today"),
        avg_session_minutes: row.get::<f64, _>("stats_avg_session_minutes"),
        crash_rate_percent: row.get::<f64, _>("stats_crash_rate_percent"),
        api_status: row.get::<String, _>("stats_api_status"),
        api_latency_ms: row.get::<i32, _>("stats_api_latency_ms"),
        device_distribution: row.get::<JsonValue, _>("stats_device_distribution"),
    }))
}

async fn update_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(platform): Path<String>,
    Json(payload): Json<UpdateAppPayload>,
) -> Result<Json<AppRecordResponse>, (StatusCode, String)> {
    ensure_apps_write_access(&claims)?;
    let platform = normalize_app_platform(platform.as_str())?;

    if let Some(status) = payload.status.as_deref() {
        validate_app_status(status)?;
    }
    if let Some(policy) = payload.update_policy.as_deref() {
        validate_update_policy(policy)?;
    }

    let row = sqlx::query(
        "UPDATE control_app.system_apps
         SET display_name = COALESCE($1, display_name),
             description = COALESCE($2, description),
             status = COALESCE($3, status),
             update_policy = COALESCE($4, update_policy),
             force_update_version = COALESCE($5, force_update_version),
             features = COALESCE($6, features),
             supported_devices = COALESCE($7, supported_devices),
             notes = COALESCE($8, notes),
             updated_at = NOW(),
             last_updated_at = NOW()
         WHERE platform = $9
         RETURNING *",
    )
    .bind(payload.display_name.as_deref())
    .bind(payload.description.as_deref())
    .bind(payload.status.as_deref().map(|value| value.trim().to_ascii_lowercase()))
    .bind(
        payload
            .update_policy
            .as_deref()
            .map(|value| value.trim().to_ascii_lowercase()),
    )
    .bind(
        payload
            .force_update_version
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    )
    .bind(payload.features)
    .bind(payload.supported_devices)
    .bind(payload.notes.as_deref())
    .bind(platform.as_str())
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "app not found".to_string()))?;

    Ok(Json(app_record_from_row(&row)?))
}

async fn push_app_update(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(platform): Path<String>,
    Json(payload): Json<PushAppUpdatePayload>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_apps_write_access(&claims)?;
    let platform = normalize_app_platform(platform.as_str())?;
    let target_version = payload.target_version.trim();
    if target_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "target_version is required".to_string(),
        ));
    }
    let rollout = payload.rollout_percentage.unwrap_or(100).clamp(1, 100);
    let channel = if rollout < 100 { "beta" } else { "stable" };
    let status = if payload.force.unwrap_or(false) {
        "required"
    } else {
        "recommended"
    };

    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM control_app.system_apps WHERE platform = $1",
    )
    .bind(platform.as_str())
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;
    if exists == 0 {
        return Err((StatusCode::NOT_FOUND, "app not found".to_string()));
    }

    sqlx::query(
        "INSERT INTO control_app.system_app_versions
            (platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status)
         SELECT platform, $2, NOW(), 'Pushed from control dashboard', api_version, $3, $4, 'current'
         FROM control_app.system_apps
         WHERE platform = $1",
    )
    .bind(platform.as_str())
    .bind(target_version)
    .bind(rollout)
    .bind(channel)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    sqlx::query(
        "UPDATE control_app.system_apps
         SET latest_available_version = $2,
             force_update_version = CASE WHEN $3 = true THEN $2 ELSE force_update_version END,
             update_policy = $4,
             last_updated_at = NOW(),
             updated_at = NOW()
         WHERE platform = $1",
    )
    .bind(platform.as_str())
    .bind(target_version)
    .bind(payload.force.unwrap_or(false))
    .bind(status)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    Ok(Json(MessageResponse {
        message: "Update pushed successfully".to_string(),
    }))
}

async fn bulk_update_apps(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<BulkUpdateAppsPayload>,
) -> Result<Json<BulkUpdateAppsResponse>, (StatusCode, String)> {
    ensure_apps_write_access(&claims)?;
    if let Some(status) = payload.status.as_deref() {
        validate_app_status(status)?;
    }
    if let Some(policy) = payload.update_policy.as_deref() {
        validate_update_policy(policy)?;
    }

    let platforms = payload
        .platforms
        .unwrap_or_default()
        .into_iter()
        .map(|value| normalize_app_platform(value.as_str()))
        .collect::<Result<Vec<_>, _>>()?;

    let result = if platforms.is_empty() {
        let features = payload.features.clone();
        sqlx::query(
            "UPDATE control_app.system_apps
             SET status = COALESCE($1, status),
                 update_policy = COALESCE($2, update_policy),
                 api_version = COALESCE($3, api_version),
                 features = COALESCE($4, features),
                 updated_at = NOW(),
                 last_updated_at = NOW()",
        )
        .bind(payload.status.as_deref().map(|value| value.trim().to_ascii_lowercase()))
        .bind(
            payload
                .update_policy
                .as_deref()
                .map(|value| value.trim().to_ascii_lowercase()),
        )
        .bind(payload.api_version.as_deref())
        .bind(features)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    } else {
        let features = payload.features.clone();
        let normalized_platforms = platforms
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>();
        sqlx::query(
            "UPDATE control_app.system_apps
             SET status = COALESCE($1, status),
                 update_policy = COALESCE($2, update_policy),
                 api_version = COALESCE($3, api_version),
                 features = COALESCE($4, features),
                 updated_at = NOW(),
                 last_updated_at = NOW()
             WHERE platform = ANY($5::text[])",
        )
        .bind(payload.status.as_deref().map(|value| value.trim().to_ascii_lowercase()))
        .bind(
            payload
                .update_policy
                .as_deref()
                .map(|value| value.trim().to_ascii_lowercase()),
        )
        .bind(payload.api_version.as_deref())
        .bind(features)
        .bind(&normalized_platforms)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    };

    Ok(Json(BulkUpdateAppsResponse {
        updated: result.rows_affected() as i64,
        message: "Apps updated successfully".to_string(),
    }))
}

// =========================================================================
// Billing Detail Endpoints
// =========================================================================

async fn get_billing_plan(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(plan_id): Path<String>,
) -> Result<Json<BillingPlanResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListPlansRequest {
            status: String::new(),
            limit: 200,
            cursor: String::new(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_plans(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let plan = response
        .plans
        .into_iter()
        .find(|p| p.plan_id == plan_id)
        .ok_or((StatusCode::NOT_FOUND, "plan not found".to_string()))?;

    Ok(Json(billing_plan_response(plan)))
}

async fn get_billing_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(subscription_id): Path<String>,
) -> Result<Json<BillingSubscriptionResponse>, (StatusCode, String)> {
    ensure_billing_read_access(&claims)?;

    let response = {
        let mut billing_client = state.billing_client.lock().await;
        let mut request = GrpcRequest::new(ListSubscriptionsRequest {
            user_id: String::new(),
            status: String::new(),
            plan_code: String::new(),
            limit: 200,
            cursor: String::new(),
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        billing_client
            .list_subscriptions(request)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("billing grpc error: {err}"),
                )
            })?
            .into_inner()
    };

    let sub = response
        .subscriptions
        .into_iter()
        .find(|s| s.subscription_id == subscription_id)
        .ok_or((StatusCode::NOT_FOUND, "subscription not found".to_string()))?;

    Ok(Json(billing_subscription_response(sub)))
}

// =========================================================================
// Support Tickets
// =========================================================================

async fn create_support_ticket(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CreateSupportTicketBody>,
) -> Result<Json<SupportTicketResponse>, (StatusCode, String)> {
    ensure_support_write_scope(&claims)?;

    let subject = body.subject.trim().to_string();
    let message = body.message.trim().to_string();
    let user_id = body.user_id.trim().to_string();

    if subject.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".to_string()));
    }
    if message.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message is required".to_string()));
    }
    if user_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id is required".to_string()));
    }
    if let Some(priority) = body.priority.as_deref() {
        if !matches!(priority, "low" | "normal" | "high" | "urgent") {
            return Err((StatusCode::BAD_REQUEST, "invalid priority".to_string()));
        }
    }

    // Look up user name and email
    let user_row = sqlx::query(
        "SELECT auth.email,
                COALESCE(users.full_name, '') AS full_name
         FROM auth.users auth
         LEFT JOIN users_app.users users ON users.user_id = auth.id
         WHERE auth.id::text = $1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "user not found".to_string()))?;

    let user_email: Option<String> = user_row.try_get("email").ok();
    let user_name: Option<String> = user_row
        .try_get::<String, _>("full_name")
        .ok()
        .filter(|n| !n.trim().is_empty());

    let ticket_id = format!(
        "TKT-{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_uppercase()
    );
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO control_app.support_tickets
             (ticket_id, user_id, user_name, user_email, subject, message, status, priority, category, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8, $9, $9)",
    )
    .bind(&ticket_id)
    .bind(&user_id)
    .bind(&user_name)
    .bind(&user_email)
    .bind(&subject)
    .bind(&message)
    .bind(body.priority.as_deref())
    .bind(body.category.as_deref())
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(Json(SupportTicketResponse {
        ticket_id,
        user_id,
        user_name,
        user_email,
        subject,
        message,
        status: "open".to_string(),
        priority: body.priority,
        category: body.category,
        assigned_to: None,
        assigned_name: None,
        created_at: now.timestamp(),
        updated_at: now.timestamp(),
        replies: vec![],
        attachments: vec![],
    }))
}

async fn list_support_tickets(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<SupportTicketsQuery>,
) -> Result<Json<SupportTicketsListResponse>, (StatusCode, String)> {
    ensure_support_read_scope(&claims)?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = (page.saturating_sub(1) * limit) as i64;
    let normalized_sort = support_sort_clause(query.sort.as_deref());

    let normalized_status = query
        .status
        .as_deref()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(status) = normalized_status.as_deref() {
        if !matches!(status, "open" | "responded" | "closed") {
            return Err((StatusCode::BAD_REQUEST, "invalid status filter".to_string()));
        }
    }
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"));

    let mut count_sql = String::from("SELECT COUNT(*) FROM control_app.support_tickets t WHERE 1=1");
    let mut list_sql = String::from(
        "SELECT t.ticket_id,
                t.user_id,
                t.user_name,
                t.user_email,
                t.subject,
                t.message,
                t.status,
                t.priority,
                t.category,
                t.assigned_to,
                t.assigned_name,
                EXTRACT(EPOCH FROM t.created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM t.updated_at)::BIGINT AS updated_at
         FROM control_app.support_tickets t
         WHERE 1=1",
    );
    let mut bind_index = 1;
    if normalized_status.is_some() {
        count_sql.push_str(" AND t.status = $");
        count_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" AND t.status = $");
        list_sql.push_str(&bind_index.to_string());
        bind_index += 1;
    }
    if search.is_some() {
        count_sql.push_str(" AND (t.ticket_id ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push_str(" OR t.user_id ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push_str(" OR COALESCE(t.user_name, '') ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push_str(" OR COALESCE(t.user_email, '') ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push_str(" OR t.subject ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push_str(" OR t.message ILIKE $");
        count_sql.push_str(&bind_index.to_string());
        count_sql.push(')');

        list_sql.push_str(" AND (t.ticket_id ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" OR t.user_id ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" OR COALESCE(t.user_name, '') ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" OR COALESCE(t.user_email, '') ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" OR t.subject ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push_str(" OR t.message ILIKE $");
        list_sql.push_str(&bind_index.to_string());
        list_sql.push(')');
        bind_index += 1;
    }

    list_sql.push_str(" ORDER BY ");
    list_sql.push_str(normalized_sort.as_str());
    list_sql.push_str(" LIMIT $");
    list_sql.push_str(&bind_index.to_string());
    list_sql.push_str(" OFFSET $");
    list_sql.push_str(&(bind_index + 1).to_string());

    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(status) = normalized_status.as_deref() {
        count_query = count_query.bind(status);
    }
    if let Some(search_value) = search.as_deref() {
        count_query = count_query.bind(search_value);
    }
    let total = count_query
        .fetch_one(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let mut list_query = sqlx::query(&list_sql);
    if let Some(status) = normalized_status.as_deref() {
        list_query = list_query.bind(status);
    }
    if let Some(search_value) = search.as_deref() {
        list_query = list_query.bind(search_value);
    }
    list_query = list_query.bind(limit as i64).bind(offset);

    let rows = list_query
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let ticket_ids: Vec<String> = rows
        .iter()
        .map(|row| row.get::<String, _>("ticket_id"))
        .collect();
    let reply_map = support_replies_by_ticket(&state, &ticket_ids).await?;

    let data = rows
        .into_iter()
        .map(|row| {
            let ticket_id = row.get::<String, _>("ticket_id");
            SupportTicketResponse {
                ticket_id: ticket_id.clone(),
                user_id: row.get::<String, _>("user_id"),
                user_name: row.get::<Option<String>, _>("user_name"),
                user_email: row.get::<Option<String>, _>("user_email"),
                subject: row.get::<String, _>("subject"),
                message: row.get::<String, _>("message"),
                status: row.get::<String, _>("status"),
                priority: row.get::<Option<String>, _>("priority"),
                category: row.get::<Option<String>, _>("category"),
                assigned_to: row.get::<Option<String>, _>("assigned_to"),
                assigned_name: row.get::<Option<String>, _>("assigned_name"),
                created_at: row.get::<i64, _>("created_at"),
                updated_at: row.get::<i64, _>("updated_at"),
                replies: reply_map.get(&ticket_id).cloned().unwrap_or_default(),
                attachments: Vec::new(),
            }
        })
        .collect::<Vec<_>>();

    let total_pages = if total <= 0 {
        0
    } else {
        ((total + limit as i64 - 1) / limit as i64) as u32
    };

    Ok(Json(SupportTicketsListResponse {
        data,
        page,
        limit,
        total,
        total_pages,
    }))
}

async fn get_support_ticket(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<SupportTicketResponse>, (StatusCode, String)> {
    ensure_support_read_scope(&claims)?;
    let ticket = load_support_ticket(&state, id.as_str()).await?;
    Ok(Json(ticket))
}

async fn reply_support_ticket(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<SupportTicketReplyBody>,
) -> Result<Json<SupportTicketResponse>, (StatusCode, String)> {
    ensure_support_write_scope(&claims)?;

    let message = payload.message.trim();
    if message.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message is required".to_string()));
    }

    let current_status = sqlx::query_scalar::<_, String>(
        "SELECT status
         FROM control_app.support_tickets
         WHERE ticket_id = $1",
    )
    .bind(id.as_str())
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "support ticket not found".to_string()))?;

    if current_status == "closed" {
        return Err((
            StatusCode::CONFLICT,
            "cannot reply to a closed ticket".to_string(),
        ));
    }

    sqlx::query(
        "INSERT INTO control_app.support_ticket_replies (ticket_id, author, message)
         VALUES ($1, $2, $3)",
    )
    .bind(id.as_str())
    .bind(claims.sub.as_str())
    .bind(message)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    sqlx::query(
        "UPDATE control_app.support_tickets
         SET status = 'responded',
             updated_at = NOW()
         WHERE ticket_id = $1",
    )
    .bind(id.as_str())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    load_support_ticket(&state, id.as_str()).await.map(Json)
}

async fn record_support_attachment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(body): Json<AttachmentMetaBody>,
) -> Result<Json<SupportTicketAttachmentResponse>, (StatusCode, String)> {
    ensure_support_write_scope(&claims)?;

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM control_app.support_tickets WHERE ticket_id = $1)",
    )
    .bind(id.as_str())
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if !exists {
        return Err((StatusCode::NOT_FOUND, "ticket not found".to_string()));
    }

    let att_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO control_app.support_ticket_attachments
             (id, ticket_id, filename, size, mime_type, uploaded_by, uploaded_at, url)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(att_id)
    .bind(id.as_str())
    .bind(&body.filename)
    .bind(body.size)
    .bind(&body.mime_type)
    .bind(&body.uploaded_by)
    .bind(now)
    .bind(&body.url)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(Json(SupportTicketAttachmentResponse {
        id: att_id.to_string(),
        filename: body.filename,
        size: body.size,
        mime_type: body.mime_type,
        uploaded_by: body.uploaded_by,
        uploaded_at: now.timestamp(),
        url: body.url,
    }))
}

async fn update_support_ticket_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<SupportTicketStatusBody>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    ensure_support_write_scope(&claims)?;

    let normalized_status = payload.status.trim().to_ascii_lowercase();
    if !matches!(normalized_status.as_str(), "open" | "responded" | "closed") {
        return Err((StatusCode::BAD_REQUEST, "invalid status".to_string()));
    }

    let result = sqlx::query(
        "UPDATE control_app.support_tickets
         SET status = $1,
             updated_at = NOW()
         WHERE ticket_id = $2",
    )
    .bind(normalized_status.as_str())
    .bind(id.as_str())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "support ticket not found".to_string()));
    }

    Ok(Json(MessageResponse {
        message: "Ticket status updated".to_string(),
    }))
}

async fn get_support_summary(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<SupportSummaryResponse>, (StatusCode, String)> {
    ensure_support_read_scope(&claims)?;

    let row = sqlx::query(
        "SELECT
            COUNT(*)::BIGINT AS total_tickets,
            COUNT(*) FILTER (WHERE status = 'open')::BIGINT AS open_tickets,
            COUNT(*) FILTER (WHERE status = 'closed')::BIGINT AS closed_tickets
         FROM control_app.support_tickets",
    )
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    Ok(Json(SupportSummaryResponse {
        open_tickets: row.get::<i64, _>("open_tickets"),
        closed_tickets: row.get::<i64, _>("closed_tickets"),
        total_tickets: row.get::<i64, _>("total_tickets"),
    }))
}

// =========================================================================
// Dashboard — SOS Requests & Activity
// =========================================================================

async fn dashboard_activity(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_scope(&claims, "control:dashboard:read")?;

    // Pull recent audit logs for platform activity
    let response = {
        let mut logs_client = state.logs_client.lock().await;
        let mut request = GrpcRequest::new(ListAuditLogsRequest {
            consumer: String::new(),
            action: String::new(),
            user_id: String::new(),
            from_unix: 0,
            to_unix: 0,
            limit: 50,
            cursor: String::new(),
            ..Default::default()
        });
        let _ = inject_internal_metadata(&mut request, "control-service", None, None);
        logs_client
            .list_audit_logs(request)
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("logs grpc error: {err}")))?
            .into_inner()
    };

    let activities: Vec<serde_json::Value> = response
        .items
        .iter()
        .map(|log| {
            serde_json::json!({
                "event_id": log.event_id,
                "action": log.action,
                "consumer": log.consumer,
                "user_id": log.user_id,
                "created_at": log.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "activities": activities,
        "total": activities.len(),
    })))
}

async fn load_support_ticket(
    state: &AppState,
    ticket_id: &str,
) -> Result<SupportTicketResponse, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT t.ticket_id,
                t.user_id,
                t.user_name,
                t.user_email,
                t.subject,
                t.message,
                t.status,
                t.priority,
                t.category,
                t.assigned_to,
                t.assigned_name,
                EXTRACT(EPOCH FROM t.created_at)::BIGINT AS created_at,
                EXTRACT(EPOCH FROM t.updated_at)::BIGINT AS updated_at
         FROM control_app.support_tickets t
         WHERE t.ticket_id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?
    .ok_or((StatusCode::NOT_FOUND, "support ticket not found".to_string()))?;

    let replies = support_replies_by_ticket(state, &[ticket_id.to_string()])
        .await?
        .remove(ticket_id)
        .unwrap_or_default();

    let attachment_rows = sqlx::query(
        "SELECT id,
                filename,
                size,
                mime_type,
                uploaded_by,
                EXTRACT(EPOCH FROM uploaded_at)::BIGINT AS uploaded_at,
                url
         FROM control_app.support_ticket_attachments
         WHERE ticket_id = $1
         ORDER BY uploaded_at ASC",
    )
    .bind(ticket_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    let attachments = attachment_rows
        .into_iter()
        .map(|reply_row| SupportTicketAttachmentResponse {
            id: reply_row.get::<Uuid, _>("id").to_string(),
            filename: reply_row.get::<String, _>("filename"),
            size: reply_row.get::<i64, _>("size"),
            mime_type: reply_row.get::<String, _>("mime_type"),
            uploaded_by: reply_row.get::<String, _>("uploaded_by"),
            uploaded_at: reply_row.get::<i64, _>("uploaded_at"),
            url: reply_row.get::<String, _>("url"),
        })
        .collect::<Vec<_>>();

    Ok(SupportTicketResponse {
        ticket_id: row.get::<String, _>("ticket_id"),
        user_id: row.get::<String, _>("user_id"),
        user_name: row.get::<Option<String>, _>("user_name"),
        user_email: row.get::<Option<String>, _>("user_email"),
        subject: row.get::<String, _>("subject"),
        message: row.get::<String, _>("message"),
        status: row.get::<String, _>("status"),
        priority: row.get::<Option<String>, _>("priority"),
        category: row.get::<Option<String>, _>("category"),
        assigned_to: row.get::<Option<String>, _>("assigned_to"),
        assigned_name: row.get::<Option<String>, _>("assigned_name"),
        created_at: row.get::<i64, _>("created_at"),
        updated_at: row.get::<i64, _>("updated_at"),
        replies,
        attachments,
    })
}

async fn support_replies_by_ticket(
    state: &AppState,
    ticket_ids: &[String],
) -> Result<HashMap<String, Vec<SupportTicketReplyResponse>>, (StatusCode, String)> {
    let mut map: HashMap<String, Vec<SupportTicketReplyResponse>> = HashMap::new();
    if ticket_ids.is_empty() {
        return Ok(map);
    }

    let rows = sqlx::query(
        "SELECT ticket_id,
                author,
                message,
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at
         FROM control_app.support_ticket_replies
         WHERE ticket_id = ANY($1::text[])
         ORDER BY created_at ASC",
    )
    .bind(ticket_ids)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    for row in rows {
        let ticket_id = row.get::<String, _>("ticket_id");
        map.entry(ticket_id)
            .or_default()
            .push(SupportTicketReplyResponse {
                author: row.get::<String, _>("author"),
                message: row.get::<String, _>("message"),
                created_at: row.get::<i64, _>("created_at"),
            });
    }
    Ok(map)
}

fn support_sort_clause(sort: Option<&str>) -> String {
    let (field, direction) = sort
        .and_then(|value| value.split_once(':'))
        .map(|(field, direction)| (field.trim(), direction.trim()))
        .unwrap_or(("updated_at", "desc"));
    let column = match field {
        "created_at" => "t.created_at",
        "updated_at" => "t.updated_at",
        "status" => "t.status",
        "priority" => "t.priority",
        "ticket_id" => "t.ticket_id",
        _ => "t.updated_at",
    };
    let direction = if direction.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    };
    format!("{column} {direction}, t.ticket_id DESC")
}

#[derive(Clone, Copy)]
enum AnalyticsWindowMode {
    Days,
    Months,
}

fn analytics_period_spec(period: Option<&str>) -> (AnalyticsWindowMode, i32) {
    match period.unwrap_or("12m").trim().to_ascii_lowercase().as_str() {
        "7d" => (AnalyticsWindowMode::Days, 7),
        "30d" => (AnalyticsWindowMode::Days, 30),
        "90d" => (AnalyticsWindowMode::Days, 90),
        "6m" => (AnalyticsWindowMode::Months, 6),
        "12m" => (AnalyticsWindowMode::Months, 12),
        _ => (AnalyticsWindowMode::Months, 12),
    }
}

fn analytics_window_start(mode: AnalyticsWindowMode, buckets: i32) -> chrono::DateTime<chrono::Utc> {
    match mode {
        AnalyticsWindowMode::Days => chrono::Utc::now() - chrono::Duration::days(i64::from(buckets - 1)),
        AnalyticsWindowMode::Months => chrono::Utc::now() - chrono::Duration::days(i64::from((buckets - 1) * 30)),
    }
}

fn analytics_bucket_labels(mode: AnalyticsWindowMode, buckets: i32) -> Vec<String> {
    let now = chrono::Utc::now();
    let mut labels = Vec::with_capacity(buckets.max(0) as usize);
    for offset in (0..buckets).rev() {
        let label_dt = match mode {
            AnalyticsWindowMode::Days => now - chrono::Duration::days(i64::from(offset)),
            AnalyticsWindowMode::Months => now - chrono::Duration::days(i64::from(offset * 30)),
        };
        let label = match mode {
            AnalyticsWindowMode::Days => label_dt.format("%Y-%m-%d").to_string(),
            AnalyticsWindowMode::Months => label_dt.format("%Y-%m").to_string(),
        };
        labels.push(label);
    }
    labels
}

fn analytics_bucket_label_from_unix(mode: AnalyticsWindowMode, unix: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(unix, 0).map(|dt| match mode {
        AnalyticsWindowMode::Days => dt.format("%Y-%m-%d").to_string(),
        AnalyticsWindowMode::Months => dt.format("%Y-%m").to_string(),
    })
}

async fn load_count_series(
    state: &AppState,
    period: Option<&str>,
    table_name: &str,
    timestamp_column: &str,
    where_clause: Option<&str>,
) -> Result<Vec<AnalyticsSeriesPointResponse>, (StatusCode, String)> {
    let (mode, buckets) = analytics_period_spec(period);
    let bucket_trunc = match mode {
        AnalyticsWindowMode::Days => "day",
        AnalyticsWindowMode::Months => "month",
    };
    let step_interval = match mode {
        AnalyticsWindowMode::Days => "1 day",
        AnalyticsWindowMode::Months => "1 month",
    };
    let label_format = match mode {
        AnalyticsWindowMode::Days => "YYYY-MM-DD",
        AnalyticsWindowMode::Months => "YYYY-MM",
    };
    let base = match where_clause {
        Some(filter) => format!(
            "SELECT date_trunc('{bucket_trunc}', {timestamp_column}) AS bucket,
                    COUNT(*)::bigint AS count
             FROM {table_name}
             WHERE {filter}
               AND {timestamp_column} >= date_trunc('{bucket_trunc}', NOW()) - (($1::int - 1) * interval '{step_interval}')
             GROUP BY 1"
        ),
        None => format!(
            "SELECT date_trunc('{bucket_trunc}', {timestamp_column}) AS bucket,
                    COUNT(*)::bigint AS count
             FROM {table_name}
             WHERE {timestamp_column} >= date_trunc('{bucket_trunc}', NOW()) - (($1::int - 1) * interval '{step_interval}')
             GROUP BY 1"
        ),
    };
    let sql = format!(
        "WITH series AS (
             SELECT generate_series(
                 date_trunc('{bucket_trunc}', NOW()) - (($1::int - 1) * interval '{step_interval}'),
                 date_trunc('{bucket_trunc}', NOW()),
                 interval '{step_interval}'
             ) AS bucket
         ),
         counts AS (
             {base}
         )
         SELECT TO_CHAR(series.bucket, '{label_format}') AS bucket,
                COALESCE(counts.count, 0) AS count
         FROM series
         LEFT JOIN counts ON counts.bucket = series.bucket
         ORDER BY series.bucket"
    );

    let rows = sqlx::query(sql.as_str())
        .bind(buckets)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {err}")))?;

    Ok(rows
        .into_iter()
        .map(|row| AnalyticsSeriesPointResponse {
            date: row.get::<String, _>("bucket"),
            count: row.get::<i64, _>("count"),
        })
        .collect())
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_allowlist_matches_ip_and_cidr_entries() {
        let allowed = vec!["203.0.113.10".to_string(), "10.0.0.0/24".to_string()];
        assert!(ip_matches_any_allowed("203.0.113.10", &allowed));
        assert!(ip_matches_any_allowed("10.0.0.25", &allowed));
        assert!(!ip_matches_any_allowed("198.51.100.1", &allowed));
    }

    #[test]
    fn masking_redacts_sensitive_fields_and_contacts() {
        let mut value = serde_json::json!({
            "email": "john.doe@example.com",
            "phone": "+1 415 555 1234",
            "password_hash": "secret-hash",
            "profile": {
                "work_email": "ops@example.com",
                "contact_phone": "+1 650 555 7777",
                "access_token": "top-secret-token"
            }
        });

        mask_json_value(&mut value, None);

        assert_eq!(
            value["email"],
            JsonValue::String("jo***@example.com".to_string())
        );
        assert_eq!(
            value["phone"],
            JsonValue::String("+1 *** *** 1234".to_string())
        );
        assert_eq!(
            value["password_hash"],
            JsonValue::String("[redacted]".to_string())
        );
        assert_eq!(
            value["profile"]["work_email"],
            JsonValue::String("op***@example.com".to_string())
        );
        assert_eq!(
            value["profile"]["contact_phone"],
            JsonValue::String("+1 *** *** 7777".to_string())
        );
        assert_eq!(
            value["profile"]["access_token"],
            JsonValue::String("[redacted]".to_string())
        );
    }
}

fn sha256_hex_bytes(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}
