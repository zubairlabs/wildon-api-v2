//! Subscription plan queries.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubscriptionPlanRow {
    pub id: Uuid,
    pub display_ref: String,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub billing_interval: String,
    pub price_cents: i32,
    pub currency: String,
    pub trial_days: i32,
    pub stripe_price_id: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn list_active(db: &PgPool) -> Result<Vec<SubscriptionPlanRow>, Status> {
    sqlx::query_as::<_, SubscriptionPlanRow>(
        "SELECT id, display_ref, code, name, description, billing_interval,
                price_cents, currency, trial_days, stripe_price_id, is_active, created_at
         FROM billing_app.subscription_plans
         WHERE is_active = true
         ORDER BY price_cents ASC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| Status::internal(format!("list plans: {e}")))
}

pub async fn get_by_id(db: &PgPool, plan_id: Uuid) -> Result<Option<SubscriptionPlanRow>, Status> {
    sqlx::query_as::<_, SubscriptionPlanRow>(
        "SELECT id, display_ref, code, name, description, billing_interval,
                price_cents, currency, trial_days, stripe_price_id, is_active, created_at
         FROM billing_app.subscription_plans WHERE id = $1",
    )
    .bind(plan_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("get plan: {e}")))
}
