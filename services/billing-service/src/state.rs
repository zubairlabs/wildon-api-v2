use crate::modules::{
    entitlements,
    stripe_webhooks::BillingEventRecord,
    subscriptions::{ManagedSubscriptionRecord, PlanRecord, SubscriptionRecord},
};
use chrono::Utc;
use provider_clients::stripe::StripeWebhookVerifier;
use std::{
    collections::{HashMap, HashSet},
    env,
    sync::Arc,
};
use tokio::sync::Mutex;

pub type UsageKey = (String, String);

#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    pub request_hash: String,
    pub response: SubscriptionRecord,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct InvoiceRecord {
    pub invoice_id: String,
    pub user_id: String,
    pub status: String,
    pub amount_cents: i64,
    pub refunded_amount_cents: i64,
    pub currency: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct TransactionRecord {
    pub transaction_id: String,
    pub user_id: String,
    pub invoice_id: String,
    pub status: String,
    pub amount_cents: i64,
    pub refunded_amount_cents: i64,
    pub currency: String,
    pub provider: String,
    pub external_txn_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct LedgerEntryRecord {
    pub ledger_id: String,
    pub user_id: String,
    pub transaction_id: String,
    pub invoice_id: String,
    pub entry_type: String,
    pub amount_cents: i64,
    pub currency: String,
    pub note: String,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub plan_overrides: Arc<Mutex<HashMap<String, String>>>,
    pub plan_entitlements: Arc<HashMap<String, HashSet<String>>>,
    pub usage_totals: Arc<Mutex<HashMap<UsageKey, u64>>>,
    pub billing_events: Arc<Mutex<HashMap<String, BillingEventRecord>>>,
    pub subscriptions: Arc<Mutex<HashMap<String, SubscriptionRecord>>>,
    pub plans_catalog: Arc<Mutex<HashMap<String, PlanRecord>>>,
    pub plan_code_index: Arc<Mutex<HashMap<String, String>>>,
    pub managed_subscriptions: Arc<Mutex<HashMap<String, ManagedSubscriptionRecord>>>,
    pub user_subscription_index: Arc<Mutex<HashMap<String, String>>>,
    pub next_plan_sequence: Arc<Mutex<u64>>,
    pub next_subscription_sequence: Arc<Mutex<u64>>,
    pub invoices: Arc<Mutex<HashMap<String, InvoiceRecord>>>,
    pub transactions: Arc<Mutex<HashMap<String, TransactionRecord>>>,
    pub ledger_entries: Arc<Mutex<Vec<LedgerEntryRecord>>>,
    pub idempotency_records: Arc<Mutex<HashMap<String, IdempotencyRecord>>>,
    pub idempotency_ttl_seconds: i64,
    pub stripe: Arc<StripeWebhookVerifier>,
}

impl AppState {
    pub fn new() -> Self {
        let idempotency_ttl_seconds = env::var("BILLING_IDEMPOTENCY_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(86_400);

        let now = Utc::now().timestamp();
        let free_plan = PlanRecord {
            plan_id: "plan-free".to_string(),
            plan_code: "free".to_string(),
            name: "Free".to_string(),
            description: "Default free plan".to_string(),
            priority: 0,
            interval: "lifetime".to_string(),
            price_cents: 0,
            currency: "USD".to_string(),
            device_limit: 1,
            storage_limit_bytes: 5_i64 * 1024 * 1024 * 1024,
            retention_days: 30,
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
        };
        let pro_plan = PlanRecord {
            plan_id: "plan-pro-monthly".to_string(),
            plan_code: "pro".to_string(),
            name: "Pro".to_string(),
            description: "Default pro plan".to_string(),
            priority: 10,
            interval: "monthly".to_string(),
            price_cents: 999,
            currency: "USD".to_string(),
            device_limit: 5,
            storage_limit_bytes: 50_i64 * 1024 * 1024 * 1024,
            retention_days: 90,
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
        };
        let mut plans_catalog = HashMap::new();
        plans_catalog.insert(free_plan.plan_id.clone(), free_plan.clone());
        plans_catalog.insert(pro_plan.plan_id.clone(), pro_plan.clone());
        let mut plan_code_index = HashMap::new();
        plan_code_index.insert(free_plan.plan_code.clone(), free_plan.plan_id.clone());
        plan_code_index.insert(pro_plan.plan_code.clone(), pro_plan.plan_id.clone());

        Self {
            plan_overrides: Arc::new(Mutex::new(HashMap::new())),
            plan_entitlements: Arc::new(entitlements::default_plan_entitlements()),
            usage_totals: Arc::new(Mutex::new(HashMap::new())),
            billing_events: Arc::new(Mutex::new(HashMap::new())),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            plans_catalog: Arc::new(Mutex::new(plans_catalog)),
            plan_code_index: Arc::new(Mutex::new(plan_code_index)),
            managed_subscriptions: Arc::new(Mutex::new(HashMap::new())),
            user_subscription_index: Arc::new(Mutex::new(HashMap::new())),
            next_plan_sequence: Arc::new(Mutex::new(100)),
            next_subscription_sequence: Arc::new(Mutex::new(10_000)),
            invoices: Arc::new(Mutex::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(HashMap::new())),
            ledger_entries: Arc::new(Mutex::new(Vec::new())),
            idempotency_records: Arc::new(Mutex::new(HashMap::new())),
            idempotency_ttl_seconds,
            stripe: Arc::new(StripeWebhookVerifier::from_env()),
        }
    }

    pub fn idempotency_expiry_timestamp(&self) -> i64 {
        Utc::now().timestamp() + self.idempotency_ttl_seconds
    }
}
