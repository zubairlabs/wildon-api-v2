use chrono::Utc;
use contracts::wildon::core::v1::JobStatus;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct JobRecordData {
    pub job_id: String,
    pub job_type: String,
    pub payload_json: String,
    pub status: JobStatus,
    pub idempotency_key: String,
    pub error_message: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl JobRecordData {
    pub fn new(job_type: &str, payload_json: &str, idempotency_key: &str) -> Self {
        let now = Utc::now().timestamp();
        Self {
            job_id: Uuid::new_v4().to_string(),
            job_type: job_type.to_string(),
            payload_json: payload_json.to_string(),
            status: JobStatus::Queued,
            idempotency_key: idempotency_key.to_string(),
            error_message: String::new(),
            created_at: now,
            updated_at: now,
        }
    }
}
