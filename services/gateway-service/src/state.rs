use crate::routing::service_map::ServiceMap;
use config::grpc::{inject_internal_metadata, CircuitBreaker, CircuitBreakerError};
use contracts::wildon::{
    api_clients::v1::{
        api_clients_service_client::ApiClientsServiceClient, ClientEnvironment, ClientPolicy,
        ClientStatus, GetClientPolicyRequest, ValidateClientRequest,
    },
    auth::v1::auth_service_client::AuthServiceClient,
    billing::v1::billing_service_client::BillingServiceClient,
    logs::v1::logs_service_client::LogsServiceClient,
    public::v1::public_service_client::PublicServiceClient,
    users::v1::users_service_client::UsersServiceClient,
};
use rate_limit::RouteId;
use redis::AsyncCommands;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tonic::{transport::Channel, Request as GrpcRequest};

// ── Service health cache ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub status: String,         // "UP" | "DOWN" | "UNKNOWN"
    pub reason: Option<String>,
    pub checked_at: i64,
}

impl ServiceStatus {
    pub fn unknown() -> Self {
        Self {
            status: "UNKNOWN".to_string(),
            reason: None,
            checked_at: 0,
        }
    }
}

// ── API call metrics ────────────────────────────────────────────────────────

pub struct ApiMetrics {
    pub total: AtomicU64,
    pub errors_4xx: AtomicU64,
    pub errors_5xx: AtomicU64,
    pub since_ts: i64,
    pub by_method: Mutex<HashMap<String, u64>>,
    pub by_service: Mutex<HashMap<String, u64>>,
    pub latency_samples: Mutex<VecDeque<u32>>,  // microseconds, last 1000
    // For Redis flush: track deltas since last flush
    pub total_flushed: AtomicU64,
    pub errors_4xx_flushed: AtomicU64,
    pub errors_5xx_flushed: AtomicU64,
}

impl ApiMetrics {
    const MAX_SAMPLES: usize = 1000;

    pub fn new(since_ts: i64, base_total: u64, base_4xx: u64, base_5xx: u64) -> Self {
        Self {
            total: AtomicU64::new(base_total),
            errors_4xx: AtomicU64::new(base_4xx),
            errors_5xx: AtomicU64::new(base_5xx),
            since_ts,
            by_method: Mutex::new(HashMap::new()),
            by_service: Mutex::new(HashMap::new()),
            latency_samples: Mutex::new(VecDeque::with_capacity(Self::MAX_SAMPLES)),
            total_flushed: AtomicU64::new(base_total),
            errors_4xx_flushed: AtomicU64::new(base_4xx),
            errors_5xx_flushed: AtomicU64::new(base_5xx),
        }
    }

    pub fn record_sync(&self, method: &str, service: &str, status: u16, _latency_us: u32) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            self.errors_5xx.fetch_add(1, Ordering::Relaxed);
        } else if status >= 400 {
            self.errors_4xx.fetch_add(1, Ordering::Relaxed);
        }
        // by_method and by_service need an async lock; callers should use record() below
        let _ = (method, service); // suppress unused warning — incremented in async record()
    }

    pub async fn record(&self, method: &str, service: &str, status: u16, latency_us: u32) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            self.errors_5xx.fetch_add(1, Ordering::Relaxed);
        } else if status >= 400 {
            self.errors_4xx.fetch_add(1, Ordering::Relaxed);
        }

        {
            let mut by_method = self.by_method.lock().await;
            *by_method.entry(method.to_string()).or_insert(0) += 1;
        }
        {
            let mut by_service = self.by_service.lock().await;
            *by_service.entry(service.to_string()).or_insert(0) += 1;
        }
        {
            let mut samples = self.latency_samples.lock().await;
            if samples.len() >= Self::MAX_SAMPLES {
                samples.pop_front();
            }
            samples.push_back(latency_us);
        }
    }

    pub async fn snapshot(&self) -> ApiCallSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let errors_4xx = self.errors_4xx.load(Ordering::Relaxed);
        let errors_5xx = self.errors_5xx.load(Ordering::Relaxed);
        let errors_total = errors_4xx + errors_5xx;
        let error_rate = if total > 0 {
            (errors_total as f64 / total as f64 * 10000.0).round() / 10000.0
        } else {
            0.0
        };

        let mut raw: Vec<u32> = self.latency_samples.lock().await.iter().cloned().collect();
        raw.sort_unstable();
        let avg_latency_ms = if raw.is_empty() {
            0.0
        } else {
            raw.iter().map(|&v| v as f64).sum::<f64>() / raw.len() as f64 / 1000.0
        };
        let p95_latency_ms = if raw.is_empty() {
            0.0
        } else {
            let idx = ((raw.len() as f64 * 0.95) as usize).min(raw.len() - 1);
            raw[idx] as f64 / 1000.0
        };

        ApiCallSnapshot {
            total,
            errors_4xx,
            errors_5xx,
            error_rate,
            avg_latency_ms,
            p95_latency_ms,
            by_method: self.by_method.lock().await.clone(),
            by_service: self.by_service.lock().await.clone(),
            since: self.since_ts,
        }
    }

    /// Returns delta since last flush and advances the flushed baseline.
    pub fn take_flush_delta(&self) -> (u64, u64, u64) {
        let cur_total = self.total.load(Ordering::Relaxed);
        let cur_4xx = self.errors_4xx.load(Ordering::Relaxed);
        let cur_5xx = self.errors_5xx.load(Ordering::Relaxed);

        let prev_total = self.total_flushed.swap(cur_total, Ordering::Relaxed);
        let prev_4xx = self.errors_4xx_flushed.swap(cur_4xx, Ordering::Relaxed);
        let prev_5xx = self.errors_5xx_flushed.swap(cur_5xx, Ordering::Relaxed);

        (
            cur_total.saturating_sub(prev_total),
            cur_4xx.saturating_sub(prev_4xx),
            cur_5xx.saturating_sub(prev_5xx),
        )
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiCallSnapshot {
    pub total: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub error_rate: f64,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub by_method: HashMap<String, u64>,
    pub by_service: HashMap<String, u64>,
    pub since: i64,
}

pub type SharedAuthClient = Arc<Mutex<AuthServiceClient<Channel>>>;
pub type SharedPublicClient = Arc<Mutex<PublicServiceClient<Channel>>>;
pub type SharedUsersClient = Arc<Mutex<UsersServiceClient<Channel>>>;
pub type SharedApiClientsClient = Arc<Mutex<ApiClientsServiceClient<Channel>>>;
pub type SharedBillingClient = Arc<Mutex<BillingServiceClient<Channel>>>;
pub type SharedLogsClient = Arc<Mutex<LogsServiceClient<Channel>>>;

#[derive(Debug, Clone)]
pub struct ValidatedClient {
    pub client_id: String,
    pub policy: ClientPolicy,
    pub app_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RateLimitRejection {
    pub dimension: &'static str,
    pub limit: u32,
    pub retry_after_seconds: i64,
    pub route_id: String,
}

#[derive(Debug, Clone)]
pub enum RateLimitCheckError {
    Rejected(RateLimitRejection),
    Backend(String),
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedRateLimits {
    pub user_rpm: Option<u32>,
    pub unauthenticated_ip_rpm: u32,
}

#[derive(Debug, Clone)]
struct CachedClientPolicy {
    policy: ClientPolicy,
    cached_at: i64,
}

#[derive(Debug, Clone)]
struct CachedValidatedClient {
    client_id: String,
    policy: ClientPolicy,
    cached_at: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub service_map: ServiceMap,
    pub auth_client: SharedAuthClient,
    pub public_client: SharedPublicClient,
    pub users_client: SharedUsersClient,
    pub api_clients_client: SharedApiClientsClient,
    pub billing_client: SharedBillingClient,
    pub logs_client: SharedLogsClient,
    pub expected_issuer: String,
    pub deployment_environment: String,
    pub browser_allowed_origins: Arc<HashSet<String>>,
    pub rate_limit_window_seconds: i64,
    pub rate_limit_fail_open: bool,
    pub service_health: Arc<Mutex<HashMap<String, ServiceStatus>>>,
    pub api_metrics: Arc<ApiMetrics>,
    redis: Option<redis::Client>,
    client_policy_cache_ttl_seconds: i64,
    client_policy_cache: Arc<Mutex<HashMap<String, CachedClientPolicy>>>,
    validated_client_cache: Arc<Mutex<HashMap<String, CachedValidatedClient>>>,
    api_clients_breaker: CircuitBreaker,
}

impl AppState {
    pub fn new(
        service_map: ServiceMap,
        auth_client: AuthServiceClient<Channel>,
        public_client: PublicServiceClient<Channel>,
        users_client: UsersServiceClient<Channel>,
        api_clients_client: ApiClientsServiceClient<Channel>,
        billing_client: BillingServiceClient<Channel>,
        logs_client: LogsServiceClient<Channel>,
        expected_issuer: String,
    ) -> Self {
        let rate_window_seconds = read_i64("RATE_LIMIT_WINDOW_SECONDS", 60);
        let client_policy_cache_ttl_seconds =
            read_i64("CLIENT_POLICY_CACHE_TTL_SECONDS", 60).clamp(1, 60);
        let deployment_environment = env::var("APP_ENV")
            .or_else(|_| env::var("ENVIRONMENT"))
            .unwrap_or_else(|_| "prod".to_string())
            .to_lowercase();
        let deployment_environment = match deployment_environment.as_str() {
            "production" => "prod".to_string(),
            "development" => "dev".to_string(),
            value => value.to_string(),
        };
        let browser_allowed_origins = parse_origins_from_env();
        let redis = env::var("REDIS_URL")
            .ok()
            .and_then(|url| redis::Client::open(url).ok());

        let since_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            service_map,
            auth_client: Arc::new(Mutex::new(auth_client)),
            public_client: Arc::new(Mutex::new(public_client)),
            users_client: Arc::new(Mutex::new(users_client)),
            api_clients_client: Arc::new(Mutex::new(api_clients_client)),
            billing_client: Arc::new(Mutex::new(billing_client)),
            logs_client: Arc::new(Mutex::new(logs_client)),
            expected_issuer,
            deployment_environment,
            browser_allowed_origins: Arc::new(browser_allowed_origins),
            rate_limit_window_seconds: rate_window_seconds,
            rate_limit_fail_open: read_bool("RATE_LIMIT_FAIL_OPEN", true),
            service_health: Arc::new(Mutex::new(HashMap::new())),
            api_metrics: Arc::new(ApiMetrics::new(since_ts, 0, 0, 0)),
            redis,
            client_policy_cache_ttl_seconds,
            client_policy_cache: Arc::new(Mutex::new(HashMap::new())),
            validated_client_cache: Arc::new(Mutex::new(HashMap::new())),
            api_clients_breaker: CircuitBreaker::from_env("gateway-api-clients"),
        }
    }

    /// Load API counter baselines from Redis (if available) so restarts don't lose totals.
    pub async fn restore_metrics_from_redis(&self) {
        let redis = match self.redis.as_ref() {
            Some(r) => r,
            None => return,
        };
        let mut conn = match redis.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let total: u64 = conn.get("api:total").await.unwrap_or(0u64);
        let errors_4xx: u64 = conn.get("api:errors_4xx").await.unwrap_or(0u64);
        let errors_5xx: u64 = conn.get("api:errors_5xx").await.unwrap_or(0u64);

        use std::sync::atomic::Ordering;
        self.api_metrics.total.store(total, Ordering::Relaxed);
        self.api_metrics.errors_4xx.store(errors_4xx, Ordering::Relaxed);
        self.api_metrics.errors_5xx.store(errors_5xx, Ordering::Relaxed);
        self.api_metrics.total_flushed.store(total, Ordering::Relaxed);
        self.api_metrics.errors_4xx_flushed.store(errors_4xx, Ordering::Relaxed);
        self.api_metrics.errors_5xx_flushed.store(errors_5xx, Ordering::Relaxed);
    }

    /// Flush counter deltas to Redis.
    pub async fn flush_metrics_to_redis(&self) {
        let redis = match self.redis.as_ref() {
            Some(r) => r,
            None => return,
        };
        let mut conn = match redis.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let (dt, d4xx, d5xx) = self.api_metrics.take_flush_delta();
        if dt > 0 {
            let _: Result<(), _> = conn.incr("api:total", dt).await;
        }
        if d4xx > 0 {
            let _: Result<(), _> = conn.incr("api:errors_4xx", d4xx).await;
        }
        if d5xx > 0 {
            let _: Result<(), _> = conn.incr("api:errors_5xx", d5xx).await;
        }
    }

    /// Update a service's health status in the cache.
    pub async fn set_service_health(&self, name: &str, status: ServiceStatus) {
        let mut map = self.service_health.lock().await;
        map.insert(name.to_string(), status);
    }

    /// Get a snapshot of service health statuses.
    pub async fn get_service_health(&self, name: &str) -> ServiceStatus {
        let map = self.service_health.lock().await;
        map.get(name).cloned().unwrap_or_else(ServiceStatus::unknown)
    }

    pub async fn validate_client(
        &self,
        client_id: &str,
        audience: &str,
        surface: &str,
        app_version: Option<&str>,
        origin: Option<&str>,
        source_ip: Option<&str>,
        client_secret: Option<&str>,
        mtls_verified: bool,
    ) -> Result<ClientPolicy, String> {
        let now = now_unix_seconds();
        let cache_key = validated_cache_key(
            client_id,
            audience,
            surface,
            app_version,
            origin,
            source_ip,
            client_secret,
            mtls_verified,
        );

        {
            let cache = self.validated_client_cache.lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if now - entry.cached_at < self.client_policy_cache_ttl_seconds {
                    return Ok(entry.policy.clone());
                }
            }
        }

        let permit = self
            .api_clients_breaker
            .before_call()
            .map_err(map_breaker_error)?;
        let response = {
            let mut api_clients_client = self.api_clients_client.lock().await;
            let mut grpc_request = GrpcRequest::new(ValidateClientRequest {
                client_id: client_id.to_string(),
                audience: audience.to_string(),
                environment: self.deployment_environment.clone(),
                app_version: app_version.unwrap_or_default().to_string(),
                surface: surface.to_string(),
                origin: origin.unwrap_or_default().to_string(),
                source_ip: source_ip.unwrap_or_default().to_string(),
                mtls_verified,
                client_secret: client_secret.unwrap_or_default().to_string(),
            });
            let _ = inject_internal_metadata(&mut grpc_request, "gateway-service", None, None);
            match api_clients_client.validate_client(grpc_request).await {
                Ok(response) => {
                    self.api_clients_breaker.on_success(&permit);
                    response.into_inner()
                }
                Err(err) => {
                    self.api_clients_breaker.on_failure(&permit);
                    return Err(format!("api-clients grpc error: {err}"));
                }
            }
        };

        if !response.valid {
            return Err(response.reason);
        }

        let Some(policy) = response.policy else {
            return Err("missing validated client policy".to_string());
        };

        let mut policy_cache = self.client_policy_cache.lock().await;
        policy_cache.insert(
            client_id.to_string(),
            CachedClientPolicy {
                policy: policy.clone(),
                cached_at: now,
            },
        );

        let mut validated_cache = self.validated_client_cache.lock().await;
        validated_cache.insert(
            cache_key,
            CachedValidatedClient {
                client_id: client_id.to_string(),
                policy: policy.clone(),
                cached_at: now,
            },
        );

        Ok(policy)
    }

    pub async fn get_client_policy(&self, client_id: &str) -> Result<ClientPolicy, String> {
        let now = now_unix_seconds();

        {
            let cache = self.client_policy_cache.lock().await;
            if let Some(entry) = cache.get(client_id) {
                if now - entry.cached_at < self.client_policy_cache_ttl_seconds {
                    return Ok(entry.policy.clone());
                }
            }
        }

        let permit = match self.api_clients_breaker.before_call() {
            Ok(permit) => permit,
            Err(err) => {
                if let Some(stale) = self.get_cached_policy_stale(client_id).await {
                    tracing::warn!(
                        client_id,
                        error = %err,
                        "api-clients circuit breaker open; using stale cached client policy"
                    );
                    return Ok(stale);
                }
                return Err(map_breaker_error(err));
            }
        };
        let response = {
            let mut api_clients_client = self.api_clients_client.lock().await;
            let mut grpc_request = GrpcRequest::new(GetClientPolicyRequest {
                client_id: client_id.to_string(),
            });
            let _ = inject_internal_metadata(&mut grpc_request, "gateway-service", None, None);
            match api_clients_client.get_client_policy(grpc_request).await {
                Ok(response) => {
                    self.api_clients_breaker.on_success(&permit);
                    response.into_inner()
                }
                Err(err) => {
                    self.api_clients_breaker.on_failure(&permit);
                    if let Some(stale) = self.get_cached_policy_stale(client_id).await {
                        tracing::warn!(
                            client_id,
                            error = %err,
                            "api-clients upstream unavailable; using stale cached client policy"
                        );
                        return Ok(stale);
                    }
                    return Err(format!("api-clients grpc error: {err}"));
                }
            }
        };

        let Some(policy) = response.policy else {
            return Err("missing client policy response".to_string());
        };

        let mut cache = self.client_policy_cache.lock().await;
        cache.insert(
            client_id.to_string(),
            CachedClientPolicy {
                policy: policy.clone(),
                cached_at: now,
            },
        );

        Ok(policy)
    }

    pub fn is_policy_active(policy: &ClientPolicy) -> bool {
        matches!(
            ClientStatus::try_from(policy.status).unwrap_or(ClientStatus::Unspecified),
            ClientStatus::Active
        )
    }

    pub fn policy_environment(policy: &ClientPolicy) -> Option<&'static str> {
        match ClientEnvironment::try_from(policy.environment)
            .unwrap_or(ClientEnvironment::Unspecified)
        {
            ClientEnvironment::Dev => Some("dev"),
            ClientEnvironment::Staging => Some("staging"),
            ClientEnvironment::Prod => Some("prod"),
            ClientEnvironment::Unspecified => None,
        }
    }

    pub fn resolve_rate_limits(
        &self,
        policy: &ClientPolicy,
        route_id: &str,
        route_group: &str,
        authenticated: bool,
    ) -> ResolvedRateLimits {
        let (fallback_user_rpm, fallback_ip_rpm) = match policy.rate_limit_profile.as_str() {
            "platform_v1" => (30_u32, 1000_u32),
            "control_v1" => (20_u32, 500_u32),
            _ => (60_u32, 5000_u32),
        };

        let default_user_rpm = if policy.default_user_rpm > 0 {
            policy.default_user_rpm
        } else {
            fallback_user_rpm
        };
        let default_ip_rpm = if policy.default_client_rpm > 0 {
            policy.default_client_rpm
        } else {
            fallback_ip_rpm
        };

        let mut user_rpm = if authenticated {
            Some(default_user_rpm)
        } else {
            None
        };
        let mut unauthenticated_ip_rpm = default_ip_rpm;

        let route_group_key = format!("group:{route_group}");
        if let Some(override_entry) = policy.route_overrides.iter().find(|entry| {
            entry.enabled
                && (entry.route_id == route_id
                    || entry.route_id.eq_ignore_ascii_case(&route_group_key))
        }) {
            if authenticated {
                if override_entry.user_rpm > 0 {
                    user_rpm = Some(override_entry.user_rpm);
                }
            } else {
                user_rpm = None;
            }

            if override_entry.client_rpm > 0 {
                unauthenticated_ip_rpm = override_entry.client_rpm;
            }
        }

        ResolvedRateLimits {
            user_rpm,
            unauthenticated_ip_rpm,
        }
    }

    pub async fn evaluate_rate_limits(
        &self,
        user_id: Option<&str>,
        source_ip: Option<&str>,
        route: &RouteId,
        route_group: &str,
        pre_auth: bool,
        limits: ResolvedRateLimits,
    ) -> Result<(), RateLimitCheckError> {
        let route_key = route.as_key();
        let route_descriptor = format!("{route_group}|{route_key}");
        let normalized_route = normalize_rl_key(route_key.as_str());

        if pre_auth {
            let ip_key = format!(
                "rl:ip:{}:{}",
                normalize_rl_key(source_ip.unwrap_or("unknown")),
                normalized_route
            );
            self.consume_fixed_window(
                &ip_key,
                limits.unauthenticated_ip_rpm,
                "ip",
                &route_descriptor,
            )
            .await?;
            return Ok(());
        }

        if let (Some(user_id), Some(user_limit)) = (user_id, limits.user_rpm) {
            let user_key = format!(
                "rl:user:{}:{}",
                normalize_rl_key(user_id),
                normalized_route
            );
            self.consume_fixed_window(&user_key, user_limit, "user", &route_descriptor)
                .await?;
        } else if let Some(source_ip) = source_ip {
            let ip_key = format!("rl:ip:{}:{}", normalize_rl_key(source_ip), normalized_route);
            self.consume_fixed_window(
                &ip_key,
                limits.unauthenticated_ip_rpm,
                "ip",
                &route_descriptor,
            )
            .await?;
        }

        Ok(())
    }

    async fn consume_fixed_window(
        &self,
        key: &str,
        limit: u32,
        dimension: &'static str,
        route_id: &str,
    ) -> Result<(), RateLimitCheckError> {
        let redis = self
            .redis
            .as_ref()
            .ok_or_else(|| RateLimitCheckError::Backend("redis not configured".to_string()))?;

        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| {
                RateLimitCheckError::Backend(format!("redis connection error: {err}"))
            })?;

        let count = conn
            .incr::<_, _, i64>(key, 1)
            .await
            .map_err(|err| RateLimitCheckError::Backend(format!("redis INCR failed: {err}")))?;

        if count == 1 {
            let _ = conn
                .expire::<_, bool>(key, self.rate_limit_window_seconds)
                .await;
        }

        if count > i64::from(limit) {
            let retry_after_seconds = conn
                .ttl::<_, i64>(key)
                .await
                .ok()
                .filter(|ttl| *ttl > 0)
                .unwrap_or(self.rate_limit_window_seconds.max(1));
            return Err(RateLimitCheckError::Rejected(RateLimitRejection {
                dimension,
                limit,
                retry_after_seconds,
                route_id: route_id.to_string(),
            }));
        }

        Ok(())
    }

    async fn get_cached_policy_stale(&self, client_id: &str) -> Option<ClientPolicy> {
        let cache = self.client_policy_cache.lock().await;
        cache.get(client_id).map(|entry| entry.policy.clone())
    }

    pub async fn invalidate_client_cache(&self, client_id: &str) {
        let normalized = client_id.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            self.clear_client_caches().await;
            return;
        }

        {
            let mut cache = self.client_policy_cache.lock().await;
            cache.remove(normalized.as_str());
        }

        let mut validated_cache = self.validated_client_cache.lock().await;
        validated_cache.retain(|_, entry| entry.client_id != normalized);
    }

    pub async fn clear_client_caches(&self) {
        {
            let mut cache = self.client_policy_cache.lock().await;
            cache.clear();
        }
        let mut validated_cache = self.validated_client_cache.lock().await;
        validated_cache.clear();
    }

    pub async fn validate_claim_freshness(
        &self,
        user_id: &str,
        token_session_version: i32,
        token_perm_revision: i64,
    ) -> Result<(), String> {
        if user_id.trim().is_empty() {
            return Err("missing subject claim".to_string());
        }

        if let Some(current_session_version) =
            self.read_cached_i64(format!("sv:user:{user_id}")).await
        {
            if current_session_version != i64::from(token_session_version) {
                return Err(format!(
                    "session_version mismatch: token={}, current={current_session_version}",
                    token_session_version
                ));
            }
        }

        if let Some(current_perm_revision) =
            self.read_cached_i64(format!("perm:user:{user_id}")).await
        {
            if current_perm_revision != token_perm_revision {
                return Err(format!(
                    "perm_rev mismatch: token={token_perm_revision}, current={current_perm_revision}"
                ));
            }
        }

        Ok(())
    }

    async fn read_cached_i64(&self, key: String) -> Option<i64> {
        let redis = self.redis.as_ref()?;
        let mut conn = redis.get_multiplexed_async_connection().await.ok()?;
        conn.get::<_, Option<i64>>(key).await.ok().flatten()
    }

    pub async fn resolve_permissions(
        &self,
        user_id: &str,
        perm_rev: i64,
    ) -> Option<HashSet<String>> {
        if user_id.trim().is_empty() || perm_rev <= 0 {
            return None;
        }

        let redis = self.redis.as_ref()?;
        let mut conn = redis.get_multiplexed_async_connection().await.ok()?;
        let key = format!("permset:user:{user_id}:{perm_rev}");
        let raw = conn.get::<_, Option<String>>(key).await.ok().flatten()?;

        let parsed = raw
            .split(',')
            .flat_map(|segment| segment.split_whitespace())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<HashSet<_>>();

        if parsed.is_empty() {
            None
        } else {
            Some(parsed)
        }
    }
}

fn map_breaker_error(err: CircuitBreakerError) -> String {
    match err {
        CircuitBreakerError::Open {
            name,
            retry_after_ms,
        } => format!("{name} upstream circuit breaker is open; retry_after_ms={retry_after_ms}"),
    }
}

fn normalize_rl_key(raw: &str) -> String {
    raw.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn validated_cache_key(
    client_id: &str,
    audience: &str,
    surface: &str,
    app_version: Option<&str>,
    origin: Option<&str>,
    source_ip: Option<&str>,
    client_secret: Option<&str>,
    mtls_verified: bool,
) -> String {
    let app_version = app_version.unwrap_or_default().trim();
    let origin = origin.unwrap_or_default().trim().to_ascii_lowercase();
    let source_ip = source_ip.unwrap_or_default().trim();
    let secret_fingerprint = fingerprint(client_secret.unwrap_or_default().trim());

    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        client_id.trim().to_ascii_lowercase(),
        audience.trim().to_ascii_lowercase(),
        surface.trim().to_ascii_lowercase(),
        app_version,
        origin,
        source_ip,
        secret_fingerprint,
        if mtls_verified { "1" } else { "0" }
    )
}

fn fingerprint(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn parse_origins_from_env() -> HashSet<String> {
    let raw = env::var("BROWSER_ALLOWED_ORIGINS")
        .or_else(|_| env::var("CORS_ALLOWED_ORIGINS"))
        .unwrap_or_default();

    raw.split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn read_i64(key: &str, fallback: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn read_bool(key: &str, fallback: bool) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(fallback)
}

fn now_unix_seconds() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => 0,
    }
}
