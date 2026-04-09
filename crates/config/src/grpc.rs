use std::{
    env, fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use thiserror::Error;
use tonic::{
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig},
    Request, Status,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Debug, Error)]
pub enum GrpcConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Clone)]
pub struct UpstreamPolicy {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub concurrency_limit: usize,
    pub keepalive_interval: Duration,
}

impl Default for UpstreamPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(read_u64("GRPC_CONNECT_TIMEOUT_MS", 500)),
            request_timeout: Duration::from_millis(read_u64("GRPC_REQUEST_TIMEOUT_MS", 5000)),
            concurrency_limit: read_usize("GRPC_CONCURRENCY_LIMIT", 128),
            keepalive_interval: Duration::from_secs(read_u64("GRPC_KEEPALIVE_SECS", 30)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InternalAuthPolicy {
    pub service_name: String,
    pub require_mtls: bool,
    pub spiffe_prefix: String,
}

impl InternalAuthPolicy {
    pub fn from_env(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            require_mtls: read_bool("INTERNAL_AUTH_REQUIRE_MTLS", false),
            spiffe_prefix: env::var("INTERNAL_AUTH_SPIFFE_PREFIX")
                .unwrap_or_else(|_| "spiffe://wildon.internal/service/".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerPolicy {
    pub failure_threshold: u32,
    pub open_window: Duration,
    pub half_open_max_calls: u32,
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: read_u32("GRPC_BREAKER_FAILURE_THRESHOLD", 5),
            open_window: Duration::from_secs(read_u64("GRPC_BREAKER_OPEN_SECS", 15)),
            half_open_max_calls: read_u32("GRPC_BREAKER_HALF_OPEN_MAX_CALLS", 1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("circuit breaker '{name}' is open; retry after {retry_after_ms}ms")]
    Open { name: String, retry_after_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerPermit {
    mode: PermitMode,
}

#[derive(Debug, Clone)]
enum PermitMode {
    Closed,
    HalfOpenProbe,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerSnapshot {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub half_open_in_flight: u32,
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    name: String,
    policy: CircuitBreakerPolicy,
    inner: Arc<Mutex<CircuitBreakerInner>>,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    state: CircuitState,
    consecutive_failures: u32,
    open_until: Option<Instant>,
    half_open_in_flight: u32,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>, policy: CircuitBreakerPolicy) -> Self {
        Self {
            name: name.into(),
            policy,
            inner: Arc::new(Mutex::new(CircuitBreakerInner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                open_until: None,
                half_open_in_flight: 0,
            })),
        }
    }

    pub fn from_env(name: impl Into<String>) -> Self {
        Self::new(name, CircuitBreakerPolicy::default())
    }

    pub fn before_call(&self) -> Result<CircuitBreakerPermit, CircuitBreakerError> {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        let now = Instant::now();

        if matches!(inner.state, CircuitState::Open) {
            if let Some(open_until) = inner.open_until {
                if now < open_until {
                    let retry_after_ms =
                        open_until.saturating_duration_since(now).as_millis() as u64;
                    return Err(CircuitBreakerError::Open {
                        name: self.name.clone(),
                        retry_after_ms,
                    });
                }
            }

            inner.state = CircuitState::HalfOpen;
            inner.half_open_in_flight = 0;
            inner.open_until = None;
        }

        match inner.state {
            CircuitState::Closed => Ok(CircuitBreakerPermit {
                mode: PermitMode::Closed,
            }),
            CircuitState::HalfOpen => {
                if inner.half_open_in_flight >= self.policy.half_open_max_calls {
                    return Err(CircuitBreakerError::Open {
                        name: self.name.clone(),
                        retry_after_ms: self.policy.open_window.as_millis() as u64,
                    });
                }
                inner.half_open_in_flight += 1;
                Ok(CircuitBreakerPermit {
                    mode: PermitMode::HalfOpenProbe,
                })
            }
            CircuitState::Open => Err(CircuitBreakerError::Open {
                name: self.name.clone(),
                retry_after_ms: self.policy.open_window.as_millis() as u64,
            }),
        }
    }

    pub fn on_success(&self, permit: &CircuitBreakerPermit) {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        match permit.mode {
            PermitMode::Closed => {
                inner.consecutive_failures = 0;
            }
            PermitMode::HalfOpenProbe => {
                inner.half_open_in_flight = inner.half_open_in_flight.saturating_sub(1);
                inner.state = CircuitState::Closed;
                inner.consecutive_failures = 0;
                inner.open_until = None;
            }
        }
    }

    pub fn on_failure(&self, permit: &CircuitBreakerPermit) {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        match permit.mode {
            PermitMode::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                if inner.consecutive_failures >= self.policy.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.open_until = Some(Instant::now() + self.policy.open_window);
                }
            }
            PermitMode::HalfOpenProbe => {
                inner.half_open_in_flight = inner.half_open_in_flight.saturating_sub(1);
                inner.state = CircuitState::Open;
                inner.open_until = Some(Instant::now() + self.policy.open_window);
            }
        }
    }

    pub fn snapshot(&self) -> CircuitBreakerSnapshot {
        let inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        CircuitBreakerSnapshot {
            state: inner.state,
            consecutive_failures: inner.consecutive_failures,
            half_open_in_flight: inner.half_open_in_flight,
        }
    }
}

pub async fn connect_channel(
    endpoint: &str,
    server_name: &str,
) -> Result<Channel, GrpcConfigError> {
    connect_channel_with_policy(endpoint, server_name, UpstreamPolicy::default()).await
}

pub async fn connect_channel_with_policy(
    endpoint: &str,
    server_name: &str,
    policy: UpstreamPolicy,
) -> Result<Channel, GrpcConfigError> {
    let mut endpoint_builder = Endpoint::from_shared(endpoint.to_string())?
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .concurrency_limit(policy.concurrency_limit)
        .http2_keep_alive_interval(policy.keepalive_interval)
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(policy.keepalive_interval));

    if client_tls_enabled(endpoint) {
        let mut tls = ClientTlsConfig::new().domain_name(server_name.to_string());

        if let Some(ca_path) = env_var_non_empty("INTERNAL_TLS_CA_CERT_PATH") {
            let ca_pem = fs::read(ca_path)?;
            tls = tls.ca_certificate(Certificate::from_pem(ca_pem));
        }

        let cert_path = env_var_non_empty("INTERNAL_TLS_CLIENT_CERT_PATH");
        let key_path = env_var_non_empty("INTERNAL_TLS_CLIENT_KEY_PATH");
        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            let cert_pem = fs::read(cert_path)?;
            let key_pem = fs::read(key_path)?;
            tls = tls.identity(Identity::from_pem(cert_pem, key_pem));
        }

        endpoint_builder = endpoint_builder.tls_config(tls)?;
    }

    if read_bool("INTERNAL_GRPC_CONNECT_EAGER", false) {
        Ok(endpoint_builder.connect().await?)
    } else {
        Ok(endpoint_builder.connect_lazy())
    }
}

pub fn load_server_tls_config() -> Result<Option<ServerTlsConfig>, GrpcConfigError> {
    let cert_path = env_var_non_empty("INTERNAL_TLS_SERVER_CERT_PATH");
    let key_path = env_var_non_empty("INTERNAL_TLS_SERVER_KEY_PATH");
    let ca_path = env_var_non_empty("INTERNAL_TLS_CA_CERT_PATH");
    let require_server_tls = read_bool("INTERNAL_TLS_REQUIRE_SERVER_TLS", false);

    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        _ if require_server_tls => {
            return Err(GrpcConfigError::Config(
                "INTERNAL_TLS_REQUIRE_SERVER_TLS is set but server cert/key paths are missing"
                    .to_string(),
            ));
        }
        _ => return Ok(None),
    };

    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;
    let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(cert_pem, key_pem));

    let require_client_auth = read_bool("INTERNAL_TLS_REQUIRE_CLIENT_AUTH", false);
    match (ca_path, require_client_auth) {
        (Some(ca_path), true) => {
            let ca_pem = fs::read(ca_path)?;
            tls = tls
                .client_ca_root(Certificate::from_pem(ca_pem))
                .client_auth_optional(false);
        }
        (Some(ca_path), false) => {
            let ca_pem = fs::read(ca_path)?;
            tls = tls
                .client_ca_root(Certificate::from_pem(ca_pem))
                .client_auth_optional(true);
        }
        (None, true) => {
            return Err(GrpcConfigError::Config(
                "INTERNAL_TLS_REQUIRE_CLIENT_AUTH is set but INTERNAL_TLS_CA_CERT_PATH is missing"
                    .to_string(),
            ));
        }
        (None, false) => {}
    }

    Ok(Some(tls))
}

#[allow(clippy::result_large_err)]
pub fn authorize_internal_request<T>(
    policy: &InternalAuthPolicy,
    request: &Request<T>,
    allowed_callers: &[&str],
) -> Result<String, Status> {
    let caller = request
        .metadata()
        .get("x-internal-service")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Status::unauthenticated("missing x-internal-service metadata"))?;

    let caller_allowed = allowed_callers
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(caller));
    if !caller_allowed {
        return Err(Status::permission_denied(format!(
            "caller '{caller}' is not permitted to access {}",
            policy.service_name
        )));
    }

    if policy.require_mtls {
        let peer_certs = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("missing mTLS peer certificates"))?;
        if peer_certs.is_empty() {
            return Err(Status::unauthenticated("empty mTLS peer certificate chain"));
        }

        if !policy.spiffe_prefix.trim().is_empty() {
            let expected_uri = format!("{}{}", policy.spiffe_prefix.trim(), caller);
            let matched = peer_certs
                .iter()
                .any(|cert| certificate_has_uri(cert.as_ref(), expected_uri.as_str()));
            if !matched {
                return Err(Status::permission_denied(format!(
                    "caller '{caller}' certificate SAN URI did not match expected identity '{expected_uri}'"
                )));
            }
        }
    }

    Ok(caller.to_string())
}

#[allow(clippy::result_large_err)]
pub fn inject_internal_metadata<T>(
    request: &mut Request<T>,
    caller_service: &str,
    request_id: Option<&str>,
    traceparent: Option<&str>,
) -> Result<(), Status> {
    insert_metadata(request, "x-internal-service", caller_service)?;

    if let Some(request_id) = request_id.map(str::trim).filter(|value| !value.is_empty()) {
        insert_metadata(request, "x-request-id", request_id)?;
    }
    if let Some(traceparent) = traceparent.map(str::trim).filter(|value| !value.is_empty()) {
        insert_metadata(request, "traceparent", traceparent)?;
    }

    Ok(())
}

pub fn metadata_value<T>(request: &Request<T>, key: &str) -> Option<String> {
    request
        .metadata()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

#[allow(clippy::result_large_err)]
fn insert_metadata<T>(
    request: &mut Request<T>,
    key: &'static str,
    value: &str,
) -> Result<(), Status> {
    let metadata_value = MetadataValue::try_from(value)
        .map_err(|err| Status::invalid_argument(format!("invalid {key} metadata: {err}")))?;
    request.metadata_mut().insert(key, metadata_value);
    Ok(())
}

fn client_tls_enabled(endpoint: &str) -> bool {
    endpoint.starts_with("https://")
        || read_bool("INTERNAL_TLS_ENABLE_CLIENT", false)
        || env_var_non_empty("INTERNAL_TLS_CA_CERT_PATH").is_some()
}

fn certificate_has_uri(cert_der: &[u8], expected_uri: &str) -> bool {
    let Ok((_, cert)) = parse_x509_certificate(cert_der) else {
        return false;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };

    san.value.general_names.iter().any(|name| match name {
        GeneralName::URI(uri) => uri.eq_ignore_ascii_case(expected_uri),
        _ => false,
    })
}

fn read_u64(key: &str, fallback: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn read_usize(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn read_u32(key: &str, fallback: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
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

fn env_var_non_empty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
