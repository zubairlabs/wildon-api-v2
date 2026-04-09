use chrono::Utc;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct BillingEventRecord {
    pub provider: String,
    pub event_id: String,
    pub user_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub invoice_id: String,
    pub transaction_id: String,
    pub payload_hash: String,
    pub received_at: i64,
}

impl BillingEventRecord {
    pub fn new(
        provider: &str,
        event_id: &str,
        user_id: &str,
        amount_cents: i64,
        currency: &str,
        payload_json: &str,
    ) -> Self {
        Self {
            provider: normalize_provider(provider),
            event_id: event_id.to_string(),
            user_id: user_id.to_string(),
            amount_cents,
            currency: currency.to_uppercase(),
            invoice_id: invoice_id_for(event_id),
            transaction_id: transaction_id_for(event_id),
            payload_hash: payload_hash(payload_json),
            received_at: Utc::now().timestamp(),
        }
    }
}

pub fn normalize_provider(provider: &str) -> String {
    let normalized = provider.trim().to_lowercase();
    if normalized.is_empty() {
        "stripe".to_string()
    } else {
        normalized
    }
}

pub fn invoice_id_for(event_id: &str) -> String {
    format!("INV-{}", short_token(event_id))
}

pub fn transaction_id_for(event_id: &str) -> String {
    format!("TRX-{}", short_token(&format!("txn:{event_id}")))
}

pub fn payload_hash(payload_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload_json.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn short_token(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase()
}
