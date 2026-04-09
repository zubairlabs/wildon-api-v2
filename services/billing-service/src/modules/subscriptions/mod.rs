#[derive(Debug, Clone)]
pub struct SubscriptionRecord {
    pub plan: String,
    pub status: String,
    pub current_period_end: i64,
}

impl SubscriptionRecord {
    pub fn active(plan: impl Into<String>, current_period_end: i64) -> Self {
        Self {
            plan: plan.into(),
            status: "active".to_string(),
            current_period_end,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlanRecord {
    pub plan_id: String,
    pub plan_code: String,
    pub name: String,
    pub description: String,
    pub priority: i32,
    pub interval: String,
    pub price_cents: i64,
    pub currency: String,
    pub device_limit: i32,
    pub storage_limit_bytes: i64,
    pub retention_days: i32,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct ManagedSubscriptionRecord {
    pub subscription_id: String,
    pub subscription_code: String,
    pub user_id: String,
    pub plan_id: String,
    pub plan_code: String,
    pub status: String,
    pub start_date: i64,
    pub end_date: i64,
    pub auto_renew: bool,
    pub device_count: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

const PLAN_INTERVAL_MONTHLY: &str = "monthly";
const PLAN_INTERVAL_YEARLY: &str = "yearly";
const PLAN_INTERVAL_LIFETIME: &str = "lifetime";

const PLAN_STATUS_ACTIVE: &str = "active";
const PLAN_STATUS_ARCHIVED: &str = "archived";

const SUB_STATUS_TRIAL: &str = "trial";
const SUB_STATUS_ACTIVE: &str = "active";
const SUB_STATUS_PAST_DUE: &str = "past_due";
const SUB_STATUS_CANCELLED: &str = "cancelled";
const SUB_STATUS_EXPIRED: &str = "expired";

pub fn normalize_plan_interval(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        PLAN_INTERVAL_MONTHLY | PLAN_INTERVAL_YEARLY | PLAN_INTERVAL_LIFETIME => Some(normalized),
        _ => None,
    }
}

pub fn normalize_plan_status(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        PLAN_STATUS_ACTIVE | PLAN_STATUS_ARCHIVED => Some(normalized),
        _ => None,
    }
}

pub fn normalize_subscription_status(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        SUB_STATUS_TRIAL | SUB_STATUS_ACTIVE | SUB_STATUS_PAST_DUE | SUB_STATUS_CANCELLED
        | SUB_STATUS_EXPIRED => Some(normalized),
        _ => None,
    }
}

pub fn can_transition_subscription_status(current: &str, next: &str) -> bool {
    if current == next {
        return true;
    }

    matches!(
        (current, next),
        (SUB_STATUS_TRIAL, SUB_STATUS_ACTIVE)
            | (SUB_STATUS_TRIAL, SUB_STATUS_EXPIRED)
            | (SUB_STATUS_ACTIVE, SUB_STATUS_PAST_DUE)
            | (SUB_STATUS_ACTIVE, SUB_STATUS_CANCELLED)
            | (SUB_STATUS_PAST_DUE, SUB_STATUS_ACTIVE)
            | (SUB_STATUS_CANCELLED, SUB_STATUS_EXPIRED)
    )
}
