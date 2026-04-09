use config::grpc::{
    connect_channel, inject_internal_metadata, CircuitBreaker, CircuitBreakerError,
    CircuitBreakerPermit, GrpcConfigError,
};
use contracts::wildon::storage::v1::{
    storage_service_client::StorageServiceClient, CompleteUploadRequest, CompleteUploadResponse,
    CreateDownloadUrlRequest, CreateDownloadUrlResponse, CreateProfilePhotoDownloadUrlRequest,
    CreateProfilePhotoDownloadUrlResponse, CreateProfilePhotoUploadTicketRequest,
    CreateProfilePhotoUploadTicketResponse, CreateUploadUrlRequest, CreateUploadUrlResponse,
    GetObjectMetadataRequest, GetObjectMetadataResponse, HealthRequest, HealthResponse,
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
            timeout: Duration::from_millis(800),
            max_retries: 2,
            retry_backoff: Duration::from_millis(120),
        }
    }
}

#[derive(Clone)]
pub struct StorageSdkClient {
    inner: StorageServiceClient<Channel>,
    policy: RetryPolicy,
    caller_service: String,
    breaker: CircuitBreaker,
}

impl StorageSdkClient {
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
        let channel = connect_channel(&endpoint, "storage-service").await?;
        let inner = StorageServiceClient::new(channel);
        Ok(Self {
            inner,
            policy,
            caller_service: caller_service.into(),
            breaker: CircuitBreaker::from_env("storage-sdk"),
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
                            "storage health call retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(attempt = attempt + 1, "storage health timeout, retrying");
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => return Err(Status::deadline_exceeded("storage health timeout")),
                }
            }

            Err(Status::unavailable("storage health retries exhausted"))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn create_upload_url(
        &mut self,
        payload: CreateUploadUrlRequest,
    ) -> Result<CreateUploadUrlResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.create_upload_url(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage create_upload_url retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage create_upload_url timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "storage create_upload_url timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "storage create_upload_url retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn complete_upload(
        &mut self,
        payload: CompleteUploadRequest,
    ) -> Result<CompleteUploadResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.complete_upload(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage complete_upload retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage complete_upload timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded("storage complete_upload timeout"))
                    }
                }
            }

            Err(Status::unavailable(
                "storage complete_upload retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn create_download_url(
        &mut self,
        payload: CreateDownloadUrlRequest,
    ) -> Result<CreateDownloadUrlResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.create_download_url(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage create_download_url retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage create_download_url timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "storage create_download_url timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "storage create_download_url retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn create_profile_photo_upload_ticket(
        &mut self,
        payload: CreateProfilePhotoUploadTicketRequest,
    ) -> Result<CreateProfilePhotoUploadTicketResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(
                    self.policy.timeout,
                    client.create_profile_photo_upload_ticket(request),
                );
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage create_profile_photo_upload_ticket retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage create_profile_photo_upload_ticket timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "storage create_profile_photo_upload_ticket timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "storage create_profile_photo_upload_ticket retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn create_profile_photo_download_url(
        &mut self,
        payload: CreateProfilePhotoDownloadUrlRequest,
    ) -> Result<CreateProfilePhotoDownloadUrlResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(
                    self.policy.timeout,
                    client.create_profile_photo_download_url(request),
                );
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage create_profile_photo_download_url retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage create_profile_photo_download_url timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "storage create_profile_photo_download_url timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "storage create_profile_photo_download_url retries exhausted",
            ))
        }
        .await;
        self.record_breaker(&permit, &result);
        result
    }

    pub async fn get_object_metadata(
        &mut self,
        payload: GetObjectMetadataRequest,
    ) -> Result<GetObjectMetadataResponse, Status> {
        let permit = self.before_call()?;
        let result = async {
            for attempt in 0..=self.policy.max_retries {
                let mut client = self.inner.clone();
                let mut request = Request::new(payload.clone());
                let _ = inject_internal_metadata(&mut request, &self.caller_service, None, None);
                let call = timeout(self.policy.timeout, client.get_object_metadata(request));
                match call.await {
                    Ok(Ok(response)) => return Ok(response.into_inner()),
                    Ok(Err(status))
                        if should_retry(&status) && attempt < self.policy.max_retries =>
                    {
                        tracing::warn!(
                            attempt = attempt + 1,
                            code = ?status.code(),
                            "storage get_object_metadata retry"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Ok(Err(status)) => return Err(status),
                    Err(_) if attempt < self.policy.max_retries => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            "storage get_object_metadata timeout, retrying"
                        );
                        sleep(backoff_for(&self.policy, attempt)).await;
                    }
                    Err(_) => {
                        return Err(Status::deadline_exceeded(
                            "storage get_object_metadata timeout",
                        ))
                    }
                }
            }

            Err(Status::unavailable(
                "storage get_object_metadata retries exhausted",
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
        assert!(!should_retry(&Status::new(Code::InvalidArgument, "bad")));
    }

    #[test]
    fn backoff_scales_per_attempt() {
        let policy = RetryPolicy::default();
        assert_eq!(backoff_for(&policy, 0), policy.retry_backoff);
        assert_eq!(backoff_for(&policy, 1), policy.retry_backoff * 2);
    }
}
