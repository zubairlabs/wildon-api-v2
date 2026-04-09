use config::grpc::inject_internal_metadata;
use contracts::wildon::core::v1::{
    core_service_client::CoreServiceClient, EnqueueJobRequest, NotificationChannel,
    SendNotificationRequest,
};
use contracts::wildon::logs::v1::{
    logs_service_client::LogsServiceClient, AuditAccessPurpose, AuditActorType,
    AuditAuthMechanism, AuditDataSensitivityLevel, AuditResult, ListAuditLogsRequest,
    ListAuditLogsResponse,
};
use logs_sdk::AuditEventBuilder;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{transport::Channel, Request as GrpcRequest, Status};
use uuid::Uuid;

#[derive(Clone)]
pub struct SharedClients {
    core_client: Arc<Mutex<CoreServiceClient<Channel>>>,
    logs_client: Arc<Mutex<LogsServiceClient<Channel>>>,
}

impl SharedClients {
    pub fn new(
        core_client: CoreServiceClient<Channel>,
        logs_client: LogsServiceClient<Channel>,
    ) -> Self {
        Self {
            core_client: Arc::new(Mutex::new(core_client)),
            logs_client: Arc::new(Mutex::new(logs_client)),
        }
    }

    pub async fn dispatch_ticket_follow_up(
        &self,
        caller_service: &str,
        workflow_prefix: &str,
        user_id: &str,
        contact_email: &str,
        ticket_subject: &str,
        ticket_id: &str,
    ) {
        let mut core_client = self.core_client.lock().await;

        let mut notification_request = GrpcRequest::new(SendNotificationRequest {
            user_id: user_id.to_string(),
            channel: NotificationChannel::Email as i32,
            destination: contact_email.to_string(),
            subject: format!("Ticket received: {ticket_subject}"),
            message: format!("Ticket {ticket_id} is now open."),
        });
        let _ = inject_internal_metadata(&mut notification_request, caller_service, None, None);
        let _ = core_client.send_notification(notification_request).await;

        let mut enqueue_request = GrpcRequest::new(EnqueueJobRequest {
            job_type: format!("{workflow_prefix}_follow_up"),
            payload_json: format!("{{\"ticket_id\":\"{ticket_id}\",\"user_id\":\"{user_id}\"}}"),
            idempotency_key: format!("{workflow_prefix}-{ticket_id}"),
        });
        let _ = inject_internal_metadata(&mut enqueue_request, caller_service, None, None);
        let _ = core_client.enqueue_job(enqueue_request).await;
    }

    pub async fn audit_log(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        before_json: Option<&str>,
        after_json: Option<&str>,
    ) {
        let request = GrpcRequest::new(
            AuditEventBuilder::new("platform-service", action, resource_type, resource_id)
                .event_id(Uuid::new_v4().to_string())
                .actor(
                    AuditActorType::User,
                    user_id,
                    "support",
                    AuditAuthMechanism::Jwt,
                )
                .resource_owner_id(user_id)
                .context(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    AuditAccessPurpose::Support,
                )
                .result(AuditResult::Success)
                .sensitivity(infer_sensitivity(resource_type, action))
                .before_json(before_json)
                .after_json(after_json)
                .metadata_value(serde_json::json!({
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                }))
                .into_ingest_request(),
        );

        let mut logs_client = self.logs_client.lock().await;
        match logs_client.ingest_audit(request).await {
            Ok(_) => {
                tracing::debug!(
                    user_id = user_id,
                    action = action,
                    resource_type = resource_type,
                    resource_id = resource_id,
                    "audit event published"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    user_id = user_id,
                    action = action,
                    "failed to publish audit event"
                );
            }
        }
    }

    pub async fn ingest_audit_event(
        &self,
        caller_service: &str,
        request_id: Option<&str>,
        traceparent: Option<&str>,
        user_id: &str,
        action: &str,
        payload_json: &str,
    ) {
        let mut request = GrpcRequest::new(
            AuditEventBuilder::new(caller_service, action, "semantic_event", action)
                .event_id(Uuid::new_v4().to_string())
                .actor(
                    AuditActorType::User,
                    user_id,
                    "support",
                    AuditAuthMechanism::Jwt,
                )
                .resource_owner_id(user_id)
                .context(
                    request_id,
                    traceparent,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    AuditAccessPurpose::Support,
                )
                .result(AuditResult::Success)
                .sensitivity(AuditDataSensitivityLevel::Sensitive)
                .metadata_json(payload_json.to_string())
                .into_ingest_request(),
        );
        if let Err(err) =
            inject_internal_metadata(&mut request, caller_service, request_id, traceparent)
        {
            tracing::warn!(error = %err, action = action, "failed to build audit metadata");
            return;
        }

        let mut logs_client = self.logs_client.lock().await;
        if let Err(err) = logs_client.ingest_audit(request).await {
            tracing::warn!(error = %err, action = action, "failed to publish audit event");
        }
    }

    pub async fn list_audit_logs(
        &self,
        caller_service: &str,
        request_id: Option<&str>,
        limit: u32,
        cursor: String,
        action: String,
        consumer: String,
        user_id: String,
        from_unix: i64,
        to_unix: i64,
    ) -> Result<ListAuditLogsResponse, Status> {
        let mut request = GrpcRequest::new(ListAuditLogsRequest {
            limit,
            cursor,
            action,
            consumer,
            user_id,
            from_unix,
            to_unix,
            ..Default::default()
        });
        let _ = inject_internal_metadata(&mut request, caller_service, request_id, None);

        let mut logs_client = self.logs_client.lock().await;
        logs_client
            .list_audit_logs(request)
            .await
            .map(|response| response.into_inner())
    }
}

fn infer_sensitivity(resource_type: &str, action: &str) -> AuditDataSensitivityLevel {
    let label = format!("{resource_type}.{action}").to_ascii_lowercase();
    if label.contains("incident") || label.contains("ticket") {
        AuditDataSensitivityLevel::Sensitive
    } else if label.contains("audit") {
        AuditDataSensitivityLevel::Critical
    } else {
        AuditDataSensitivityLevel::Normal
    }
}
