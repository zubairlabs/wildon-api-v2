use chrono::Utc;
use contracts::wildon::logs::v1::{
    ActorContext, AuditAccessPurpose, AuditAuthMechanism, AuditContext, AuditDataSensitivityLevel,
    AuditEvent, AuditResult, AuditSeverity, IngestAuditRequest,
};
use serde_json::{json, Value};
use uuid::Uuid;

pub use contracts::wildon::logs::v1::AuditActorType;

#[derive(Debug, Clone)]
pub struct LogsClient;

#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    pub fn new(
        service_name: impl Into<String>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        let action = action.into();
        let mut event = AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp(),
            service_name: service_name.into(),
            environment: deployment_environment(),
            action,
            severity: AuditSeverity::Unspecified as i32,
            actor: Some(ActorContext {
                actor_type: AuditActorType::Unspecified as i32,
                actor_id: String::new(),
                actor_role: String::new(),
                auth_mechanism: AuditAuthMechanism::Unspecified as i32,
            }),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            resource_owner_id: String::new(),
            member_id: String::new(),
            context: Some(AuditContext {
                request_id: String::new(),
                trace_id: String::new(),
                session_id: String::new(),
                ip_address: String::new(),
                user_agent: String::new(),
                method: String::new(),
                path: String::new(),
                status_code: 0,
                access_purpose: AuditAccessPurpose::Unspecified as i32,
            }),
            result: AuditResult::Unspecified as i32,
            reason: String::new(),
            data_sensitivity_level: AuditDataSensitivityLevel::Unspecified
                as i32,
            before_json: String::new(),
            after_json: String::new(),
            metadata_json: "{}".to_string(),
            previous_hash: String::new(),
            event_hash: String::new(),
            taxonomy_version: "v1".to_string(),
        };
        if !validate_action_name(&event.action) {
            event.action = sanitize_action_name(&event.action);
        }
        Self { event }
    }

    pub fn event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event.event_id = event_id.into();
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.event.timestamp = timestamp;
        self
    }

    pub fn actor(
        mut self,
        actor_type: AuditActorType,
        actor_id: impl Into<String>,
        actor_role: impl Into<String>,
        auth_mechanism: AuditAuthMechanism,
    ) -> Self {
        self.event.actor = Some(ActorContext {
            actor_type: actor_type as i32,
            actor_id: actor_id.into(),
            actor_role: actor_role.into(),
            auth_mechanism: auth_mechanism as i32,
        });
        self
    }

    pub fn resource_owner_id(mut self, resource_owner_id: impl Into<String>) -> Self {
        self.event.resource_owner_id = resource_owner_id.into();
        self
    }

    pub fn member_id(mut self, member_id: impl Into<String>) -> Self {
        self.event.member_id = member_id.into();
        self
    }

    pub fn context(
        mut self,
        request_id: Option<&str>,
        trace_id: Option<&str>,
        session_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        status_code: Option<i32>,
        access_purpose: AuditAccessPurpose,
    ) -> Self {
        self.event.context = Some(AuditContext {
            request_id: clean(request_id),
            trace_id: clean(trace_id),
            session_id: clean(session_id),
            ip_address: clean(ip_address),
            user_agent: clean(user_agent),
            method: clean(method),
            path: clean(path),
            status_code: status_code.unwrap_or_default(),
            access_purpose: access_purpose as i32,
        });
        self
    }

    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.event.severity = severity as i32;
        self
    }

    pub fn result(mut self, result: AuditResult) -> Self {
        self.event.result = result as i32;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.event.reason = reason.into();
        self
    }

    pub fn sensitivity(mut self, sensitivity: AuditDataSensitivityLevel) -> Self {
        self.event.data_sensitivity_level = sensitivity as i32;
        self
    }

    pub fn before_json(mut self, before_json: Option<&str>) -> Self {
        self.event.before_json = clean(before_json);
        self
    }

    pub fn after_json(mut self, after_json: Option<&str>) -> Self {
        self.event.after_json = clean(after_json);
        self
    }

    pub fn metadata_json(mut self, metadata_json: impl Into<String>) -> Self {
        self.event.metadata_json = metadata_json.into();
        self
    }

    pub fn metadata_value(mut self, value: Value) -> Self {
        self.event.metadata_json = value.to_string();
        self
    }

    pub fn build(mut self) -> AuditEvent {
        if self.event.severity == AuditSeverity::Unspecified as i32 {
            let result =
                AuditResult::try_from(self.event.result).unwrap_or(AuditResult::Success);
            let sensitivity = AuditDataSensitivityLevel::try_from(self.event.data_sensitivity_level)
                .unwrap_or(AuditDataSensitivityLevel::Normal);
            self.event.severity = default_severity(&self.event.action, result, sensitivity) as i32;
        }
        self.event
    }

    pub fn into_ingest_request(self) -> IngestAuditRequest {
        let event = self.build();
        IngestAuditRequest {
            event_id: event.event_id.clone(),
            user_id: event
                .actor
                .as_ref()
                .map(|actor| actor.actor_id.clone())
                .unwrap_or_default(),
            action: event.action.clone(),
            payload_json: legacy_payload_json(&event).to_string(),
            consumer: event.service_name.clone(),
            canonical_event: Some(event),
        }
    }
}

pub fn validate_action_name(action: &str) -> bool {
    let trimmed = action.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.contains("..")
    {
        return false;
    }

    trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.')
}

pub fn sanitize_action_name(action: &str) -> String {
    let mut output = String::new();
    let mut last_dot = false;
    for ch in action.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '.'
        };
        if next == '.' {
            if last_dot || output.is_empty() {
                continue;
            }
            last_dot = true;
        } else {
            last_dot = false;
        }
        output.push(next);
    }
    output.trim_matches('.').to_string()
}

pub fn default_severity(
    action: &str,
    result: AuditResult,
    sensitivity: AuditDataSensitivityLevel,
) -> AuditSeverity {
    if matches!(result, AuditResult::Denied | AuditResult::Failure) {
        return AuditSeverity::Medium;
    }
    if matches!(
        sensitivity,
        AuditDataSensitivityLevel::Critical
    ) {
        return AuditSeverity::Critical;
    }
    if matches!(sensitivity, AuditDataSensitivityLevel::Phi) {
        return AuditSeverity::High;
    }
    if action.contains("access.granted")
        || action.contains("access.revoked")
        || action.contains("audit.export")
        || action.contains("auditor.")
        || action.contains("billing.")
        || action.contains("subscription.")
    {
        return AuditSeverity::Critical;
    }
    if action.contains(".view") && action.contains("care.") {
        return AuditSeverity::High;
    }
    AuditSeverity::Low
}

pub fn deployment_environment() -> String {
    std::env::var("APP_ENV")
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "prod".to_string())
}

pub fn legacy_payload_json(event: &AuditEvent) -> Value {
    let actor = event.actor.as_ref();
    let context = event.context.as_ref();
    json!({
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "resource_owner_id": event.resource_owner_id,
        "member_id": event.member_id,
        "before": empty_string_to_null(&event.before_json),
        "after": empty_string_to_null(&event.after_json),
        "metadata": parse_json_string(&event.metadata_json),
        "severity": event.severity,
        "result": event.result,
        "reason": empty_string_to_null(&event.reason),
        "actor": {
            "actor_type": actor.map(|value| value.actor_type).unwrap_or_default(),
            "actor_id": actor.map(|value| value.actor_id.clone()).unwrap_or_default(),
            "actor_role": actor.map(|value| value.actor_role.clone()).unwrap_or_default(),
            "auth_mechanism": actor.map(|value| value.auth_mechanism).unwrap_or_default(),
        },
        "context": {
            "request_id": context.map(|value| value.request_id.clone()).unwrap_or_default(),
            "trace_id": context.map(|value| value.trace_id.clone()).unwrap_or_default(),
            "session_id": context.map(|value| value.session_id.clone()).unwrap_or_default(),
            "ip_address": context.map(|value| value.ip_address.clone()).unwrap_or_default(),
            "user_agent": context.map(|value| value.user_agent.clone()).unwrap_or_default(),
            "method": context.map(|value| value.method.clone()).unwrap_or_default(),
            "path": context.map(|value| value.path.clone()).unwrap_or_default(),
            "status_code": context.map(|value| value.status_code).unwrap_or_default(),
            "access_purpose": context.map(|value| value.access_purpose).unwrap_or_default(),
        },
    })
}

fn clean(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn empty_string_to_null(value: &str) -> Value {
    if value.trim().is_empty() {
        Value::Null
    } else {
        parse_json_string(value)
    }
}

fn parse_json_string(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| json!({ "raw": value }))
}
