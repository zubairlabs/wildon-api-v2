use config::grpc::{
    connect_channel, inject_internal_metadata, CircuitBreaker, CircuitBreakerError,
    CircuitBreakerPermit, GrpcConfigError,
};
use contracts::wildon::export::v1::{
    export_service_client::ExportServiceClient, CreateExportJobRequest, CreateExportJobResponse,
    DownloadExportRequest, DownloadExportResponse, GetExportJobRequest, GetExportJobResponse,
    HealthRequest, HealthResponse, RetryExportJobRequest, RetryExportJobResponse,
};
use tokio::time::{sleep, timeout, Duration};
use tonic::{transport::Channel, Code, Request, Status};

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub timeout: Duration,
    pub max_retries: usize,
    pub retry_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(900),
            max_retries: 2,
            retry_backoff: Duration::from_millis(150),
        }
    }
}

#[derive(Clone)]
pub struct ExportSdkClient {
    inner: ExportServiceClient<Channel>,
    policy: RetryPolicy,
    caller_service: String,
    breaker: CircuitBreaker,
}

impl ExportSdkClient {
    pub async fn connect(endpoint: String) -> Result<Self, GrpcConfigError> {
        let caller_service = std::env::var("INTERNAL_CALLER_SERVICE")
            .unwrap_or_else(|_| "unknown-service".to_string());
        Self::connect_as(endpoint, caller_service).await
    }

    pub async fn connect_as(
        endpoint: String,
        caller_service: impl Into<String>,
    ) -> Result<Self, GrpcConfigError> {
        Self::connect_with_policy(endpoint, caller_service, RetryPolicy::default()).await
    }

    pub async fn connect_with_policy(
        endpoint: String,
        caller_service: impl Into<String>,
        policy: RetryPolicy,
    ) -> Result<Self, GrpcConfigError> {
        let channel = connect_channel(&endpoint, "export-service").await?;
        let inner = ExportServiceClient::new(channel);
        Ok(Self {
            inner,
            policy,
            caller_service: caller_service.into(),
            breaker: CircuitBreaker::from_env("export-sdk"),
        })
    }

    pub async fn health(&mut self, request_id: Option<&str>) -> Result<HealthResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(HealthRequest {});
                let _ =
                    inject_internal_metadata(&mut request, &self.caller_service, request_id, None);
                if let Some(id) = request_id {
                    let value = tonic::metadata::MetadataValue::try_from(id).map_err(|err| {
                        Status::invalid_argument(format!("invalid request id metadata: {err}"))
                    })?;
                    request.metadata_mut().insert("x-request-id", value);
                }

                let call = timeout(self.policy.timeout, client.health(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "export health retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(attempt = attempt + 1, "export health timeout, retrying");
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => return Err(Status::deadline_exceeded("export health timeout")),
                }
            }

            Err(Status::unavailable("export health retries exhausted"))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn create_export_job(
        &mut self,
        payload: CreateExportJobRequest,
    ) -> Result<CreateExportJobResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.create_export_job(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "export create_export_job retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "export create_export_job timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "export create_export_job timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "export create_export_job retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn get_export_job(
        &mut self,
        payload: GetExportJobRequest,
    ) -> Result<GetExportJobResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.get_export_job(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "export get_export_job retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "export get_export_job timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded("export get_export_job timeout"))
                    }
                }
            }

            Err(Status::unavailable(
                "export get_export_job retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn download_export(
        &mut self,
        payload: DownloadExportRequest,
    ) -> Result<DownloadExportResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.download_export(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "export download_export retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "export download_export timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded("export download_export timeout"))
                    }
                }
            }

            Err(Status::unavailable(
                "export download_export retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn retry_export_job(
        &mut self,
        payload: RetryExportJobRequest,
    ) -> Result<RetryExportJobResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.retry_export_job(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "export retry_export_job retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "export retry_export_job timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded("export retry_export_job timeout"))
                    }
                }
            }

            Err(Status::unavailable(
                "export retry_export_job retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    fn before_call(&self) -> Result<CircuitBreakerPermit, Status> {
        self.breaker.before_call().map_err(map_breaker_error)
    }

    fn record_breaker<T>(&self, permit: &CircuitBreakerPermit, result: &Result<T, Status>) {
        match result {
            Ok(_) => self.breaker.on_success(permit),
            Err(status) if should_trip_breaker(status) => self.breaker.on_failure(permit),
            Err(_) => self.breaker.on_success(permit),
        }
    }
}

fn should_retry(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unavailable | Code::DeadlineExceeded | Code::Unknown
    )
}

fn should_trip_breaker(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unavailable | Code::DeadlineExceeded | Code::Unknown | Code::Internal
    )
}

fn map_breaker_error(err: CircuitBreakerError) -> Status {
    match err {
        CircuitBreakerError::Open {
            name,
            retry_after_ms,
        } => Status::unavailable(format!(
            "{name} upstream circuit breaker open; retry_after_ms={retry_after_ms}"
        )),
    }
}

fn backoff_for(policy: &RetryPolicy, attempt: usize) -> Duration {
    policy.retry_backoff * (attempt as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_filter_accepts_transient_grpc_codes() {
        assert!(should_retry(&Status::new(Code::Unavailable, "down")));
        assert!(should_retry(&Status::new(Code::DeadlineExceeded, "slow")));
        assert!(!should_retry(&Status::new(
            Code::PermissionDenied,
            "forbidden"
        )));
    }

    #[test]
    fn backoff_scales_per_attempt() {
        let policy = RetryPolicy::default();
        assert_eq!(backoff_for(&policy, 0), policy.retry_backoff);
        assert_eq!(backoff_for(&policy, 2), policy.retry_backoff * 3);
    }
}
