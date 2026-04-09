use contracts::wildon::export::v1::{ExportJob, ExportJobStatus};
use std::{collections::HashMap, sync::Arc};
use storage_sdk::StorageSdkClient;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone)]
pub struct ExportJobRecord {
    pub job_id: String,
    pub user_id: String,
    pub export_kind: String,
    pub format: String,
    pub status: ExportJobStatus,
    pub artifact_key: String,
    pub idempotency_key: String,
    pub error_message: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: i64,
}

impl ExportJobRecord {
    pub fn to_proto(&self) -> ExportJob {
        ExportJob {
            job_id: self.job_id.clone(),
            user_id: self.user_id.clone(),
            export_kind: self.export_kind.clone(),
            format: self.format.clone(),
            status: self.status as i32,
            artifact_key: self.artifact_key.clone(),
            idempotency_key: self.idempotency_key.clone(),
            error_message: self.error_message.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: self.completed_at,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub jobs: Arc<Mutex<HashMap<String, ExportJobRecord>>>,
    pub idempotency: Arc<Mutex<HashMap<String, String>>>,
    pub queue_tx: mpsc::Sender<String>,
    pub storage_client: Arc<Mutex<StorageSdkClient>>,
}

impl AppState {
    pub fn new(queue_tx: mpsc::Sender<String>, storage_client: StorageSdkClient) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            idempotency: Arc::new(Mutex::new(HashMap::new())),
            queue_tx,
            storage_client: Arc::new(Mutex::new(storage_client)),
        }
    }
}
