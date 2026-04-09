use crate::state::{AppState, CachedEntitlement};
use event_bus::EventEnvelope;
use serde_json::Value;
use tokio::sync::broadcast;

const CONSUMER_NAME: &str = "core-cache-invalidator";

pub fn spawn_consumer(
    state: AppState,
    mut rx: broadcast::Receiver<EventEnvelope>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let envelope = match rx.recv().await {
                Ok(envelope) => envelope,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "cache invalidator lagged on event bus");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::warn!("cache invalidator bus closed");
                    break;
                }
            };

            let should_process = {
                let mut tracker = state.cache_invalidation_idempotency.lock().await;
                tracker.check_and_mark(&envelope.event_id, CONSUMER_NAME)
            };

            if !should_process {
                continue;
            }

            tracing::debug!(
                event_id = %envelope.event_id,
                event_type = %envelope.event_type,
                producer = %envelope.producer,
                request_id = envelope.request_id.as_deref().unwrap_or("none"),
                traceparent = envelope.traceparent.as_deref().unwrap_or("none"),
                "cache invalidator received envelope"
            );

            match envelope.event_type.as_str() {
                "feature_flag.updated" => {
                    invalidate_feature_entries(&state, &envelope).await;
                }
                "plan.override.updated" => {
                    invalidate_user_entries(&state, &envelope.aggregate_id).await;
                }
                "entitlement.cache.flush" => {
                    flush_all(&state).await;
                }
                _ => {}
            }
        }
    })
}

pub async fn get_cached_entitlement(
    state: &AppState,
    user_id: &str,
    feature_key: &str,
) -> Option<CachedEntitlement> {
    let mut cache = state.entitlement_cache.lock().await;
    let key = cache_key(user_id, feature_key);
    let record = cache.get(&key).cloned()?;
    let now = chrono::Utc::now().timestamp();
    if record.is_expired(state.entitlement_cache_ttl_seconds, now) {
        cache.remove(&key);
        return None;
    }

    Some(record)
}

pub async fn put_cached_entitlement(
    state: &AppState,
    user_id: &str,
    feature_key: &str,
    entry: CachedEntitlement,
) {
    let mut cache = state.entitlement_cache.lock().await;
    cache.insert(cache_key(user_id, feature_key), entry);
}

pub fn publish_feature_flag_invalidation(
    state: &AppState,
    feature_key: &str,
    request_id: Option<&str>,
    traceparent: Option<&str>,
) {
    let payload_json = serde_json::json!({
        "feature_key": feature_key,
    })
    .to_string();
    let envelope = EventEnvelope::new("feature_flag.updated", feature_key, payload_json)
        .with_producer("core-service")
        .with_schema_version(1)
        .with_trace_context(
            request_id.map(ToString::to_string),
            traceparent.map(ToString::to_string),
        );
    let _ = state.cache_invalidation_bus.send(envelope);
}

fn cache_key(user_id: &str, feature_key: &str) -> (String, String) {
    (user_id.to_string(), feature_key.to_string())
}

async fn invalidate_feature_entries(state: &AppState, envelope: &EventEnvelope) {
    let feature_key = serde_json::from_str::<Value>(&envelope.payload_json)
        .ok()
        .and_then(|value| {
            value
                .get("feature_key")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| envelope.aggregate_id.clone());

    let mut cache = state.entitlement_cache.lock().await;
    let before = cache.len();
    cache.retain(|(_, key), _| key != &feature_key);
    let removed = before.saturating_sub(cache.len());
    tracing::info!(
        feature_key,
        removed,
        "applied entitlement cache invalidation by feature"
    );
}

async fn invalidate_user_entries(state: &AppState, user_id: &str) {
    let mut cache = state.entitlement_cache.lock().await;
    let before = cache.len();
    cache.retain(|(cache_user_id, _), _| cache_user_id != user_id);
    let removed = before.saturating_sub(cache.len());
    tracing::info!(
        user_id,
        removed,
        "applied entitlement cache invalidation by user"
    );
}

async fn flush_all(state: &AppState) {
    let mut cache = state.entitlement_cache.lock().await;
    let removed = cache.len();
    cache.clear();
    tracing::info!(removed, "flushed entitlement cache");
}
