use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub event_type: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub payload_json: String,
    #[serde(default = "default_producer")]
    pub producer: String,
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub traceparent: Option<String>,
}

impl EventEnvelope {
    pub fn new(
        event_type: impl Into<String>,
        aggregate_id: impl Into<String>,
        payload_json: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type: event_type.into(),
            aggregate_id: aggregate_id.into(),
            occurred_at: Utc::now(),
            payload_json: payload_json.into(),
            producer: "unknown-producer".to_string(),
            schema_version: 1,
            request_id: None,
            traceparent: None,
        }
    }

    pub fn with_event_id(
        event_id: impl Into<String>,
        event_type: impl Into<String>,
        aggregate_id: impl Into<String>,
        payload_json: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            event_type: event_type.into(),
            aggregate_id: aggregate_id.into(),
            occurred_at: Utc::now(),
            payload_json: payload_json.into(),
            producer: "unknown-producer".to_string(),
            schema_version: 1,
            request_id: None,
            traceparent: None,
        }
    }

    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = producer.into();
        self
    }

    pub fn with_schema_version(mut self, schema_version: u32) -> Self {
        self.schema_version = schema_version.max(1);
        self
    }

    pub fn with_trace_context(
        mut self,
        request_id: Option<impl Into<String>>,
        traceparent: Option<impl Into<String>>,
    ) -> Self {
        self.request_id = request_id.map(Into::into);
        self.traceparent = traceparent.map(Into::into);
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutboxRecord {
    pub stream: String,
    pub envelope: EventEnvelope,
    pub delivered: bool,
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryOutbox {
    records: Vec<OutboxRecord>,
}

impl InMemoryOutbox {
    pub fn enqueue(&mut self, stream: impl Into<String>, envelope: EventEnvelope) {
        self.records.push(OutboxRecord {
            stream: stream.into(),
            envelope,
            delivered: false,
        });
    }

    pub fn mark_delivered(&mut self, event_id: &str) {
        for record in self
            .records
            .iter_mut()
            .filter(|r| r.envelope.event_id == event_id)
        {
            record.delivered = true;
        }
    }

    pub fn pending(&self) -> Vec<OutboxRecord> {
        self.records
            .iter()
            .filter(|r| !r.delivered)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Default, Clone)]
pub struct IdempotencyTracker {
    consumed: HashSet<(String, String)>,
}

impl IdempotencyTracker {
    pub fn check_and_mark(&mut self, event_id: &str, consumer: &str) -> bool {
        self.consumed
            .insert((event_id.to_string(), consumer.to_string()))
    }
}

fn default_producer() -> String {
    "unknown-producer".to_string()
}

fn default_schema_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_envelope_supports_trace_context() {
        let envelope = EventEnvelope::new(
            "billing.subscription.updated.v1",
            "sub_123",
            "{\"status\":\"active\"}",
        )
        .with_producer("billing-service")
        .with_schema_version(2)
        .with_trace_context(Some("req_123"), Some("00-abc-def-01"));

        assert_eq!(envelope.producer, "billing-service");
        assert_eq!(envelope.schema_version, 2);
        assert_eq!(envelope.request_id.as_deref(), Some("req_123"));
        assert_eq!(envelope.traceparent.as_deref(), Some("00-abc-def-01"));
    }

    #[test]
    fn idempotency_tracker_is_consumer_scoped() {
        let mut tracker = IdempotencyTracker::default();
        assert!(tracker.check_and_mark("evt_1", "consumer-a"));
        assert!(!tracker.check_and_mark("evt_1", "consumer-a"));
        assert!(tracker.check_and_mark("evt_1", "consumer-b"));
    }
}
