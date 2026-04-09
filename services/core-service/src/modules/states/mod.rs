use std::{collections::HashMap, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct DependencyHealth {
    pub name: String,
    pub status: String,       // "UP" | "DOWN"
    pub latency_ms: i64,
    pub last_ok_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct StatesHandle {
    inner: Arc<Mutex<HashMap<String, DependencyHealth>>>,
}

impl StatesHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn set(&self, name: &str, health: DependencyHealth) {
        let mut map = self.inner.lock().await;
        map.insert(name.to_string(), health);
    }

    pub async fn snapshot(&self) -> HashMap<String, DependencyHealth> {
        self.inner.lock().await.clone()
    }

    pub async fn overall_status(&self) -> &'static str {
        let map = self.inner.lock().await;
        if map.values().any(|h| h.status == "DOWN") {
            "degraded"
        } else {
            "ok"
        }
    }
}

pub fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
