//! Device subscription CRUD — one active subscription per device.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use super::display_ref;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceSubscriptionRow {
    pub id: Uuid,
    pub display_ref: String,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub plan_id: Uuid,
    pub plan_code: String,
    pub plan_name: String,
    pub price_cents: i32,
    pub currency: String,
    pub billing_interval: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub payment_method_id: Option<Uuid>,
    pub status: String,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const SELECT_JOINED: &str = r#"
    SELECT ds.id, ds.display_ref, ds.user_id, ds.device_id, ds.plan_id,
           sp.code as plan_code, sp.name as plan_name,
           sp.price_cents, sp.currency, sp.billing_interval,
           ds.stripe_customer_id, ds.stripe_subscription_id,
           ds.payment_method_id, ds.status,
           ds.current_period_start, ds.current_period_end,
           ds.cancel_at_period_end, ds.canceled_at, ds.grace_period_ends_at,
           ds.created_at, ds.updated_at
    FROM billing_app.device_subscriptions ds
    JOIN billing_app.subscription_plans sp ON sp.id = ds.plan_id
"#;

pub async fn list_by_user(
    db: &PgPool,
    user_id: Uuid,
) -> Result<Vec<DeviceSubscriptionRow>, Status> {
    let q = format!("{SELECT_JOINED} WHERE ds.user_id = $1 ORDER BY ds.created_at DESC");
    sqlx::query_as::<_, DeviceSubscriptionRow>(&q)
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(|e| Status::internal(format!("list device subs: {e}")))
}

pub async fn get_by_device(
    db: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<Option<DeviceSubscriptionRow>, Status> {
    let q = format!("{SELECT_JOINED} WHERE ds.user_id = $1 AND ds.device_id = $2");
    sqlx::query_as::<_, DeviceSubscriptionRow>(&q)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(db)
        .await
        .map_err(|e| Status::internal(format!("get device sub: {e}")))
}

pub async fn get_by_id(db: &PgPool, sub_id: Uuid) -> Result<Option<DeviceSubscriptionRow>, Status> {
    let q = format!("{SELECT_JOINED} WHERE ds.id = $1");
    sqlx::query_as::<_, DeviceSubscriptionRow>(&q)
        .bind(sub_id)
        .fetch_optional(db)
        .await
        .map_err(|e| Status::internal(format!("get sub by id: {e}")))
}

pub async fn has_active(db: &PgPool, device_id: Uuid) -> Result<bool, Status> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM billing_app.device_subscriptions WHERE device_id = $1 AND status IN ('active', 'trialing', 'past_due')",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("check active sub: {e}")))?;
    Ok(row.is_some())
}

pub async fn insert(
    db: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    plan_id: Uuid,
    stripe_customer_id: Option<&str>,
    stripe_subscription_id: Option<&str>,
    stripe_price_id: Option<&str>,
    payment_method_id: Option<Uuid>,
    status: &str,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
) -> Result<Uuid, Status> {
    let ref_code =
        display_ref::generate_unique_ref(db, "SUB", "billing_app.device_subscriptions").await?;

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO billing_app.device_subscriptions
            (display_ref, user_id, device_id, plan_id, stripe_customer_id,
             stripe_subscription_id, stripe_price_id, payment_method_id,
             status, current_period_start, current_period_end)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id",
    )
    .bind(&ref_code)
    .bind(user_id)
    .bind(device_id)
    .bind(plan_id)
    .bind(stripe_customer_id)
    .bind(stripe_subscription_id)
    .bind(stripe_price_id)
    .bind(payment_method_id)
    .bind(status)
    .bind(current_period_start)
    .bind(current_period_end)
    .fetch_one(db)
    .await
    .map_err(|e| Status::internal(format!("insert device sub: {e}")))?;

    Ok(row.0)
}

pub async fn update_status(
    db: &PgPool,
    sub_id: Uuid,
    status: &str,
    cancel_at_period_end: Option<bool>,
    canceled_at: Option<DateTime<Utc>>,
    grace_period_ends_at: Option<DateTime<Utc>>,
) -> Result<(), Status> {
    sqlx::query(
        "UPDATE billing_app.device_subscriptions
         SET status = $2, cancel_at_period_end = COALESCE($3, cancel_at_period_end),
             canceled_at = COALESCE($4, canceled_at),
             grace_period_ends_at = COALESCE($5, grace_period_ends_at),
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(sub_id)
    .bind(status)
    .bind(cancel_at_period_end)
    .bind(canceled_at)
    .bind(grace_period_ends_at)
    .execute(db)
    .await
    .map_err(|e| Status::internal(format!("update sub status: {e}")))?;
    Ok(())
}

pub async fn update_period(
    db: &PgPool,
    stripe_subscription_id: &str,
    status: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<(), Status> {
    sqlx::query(
        "UPDATE billing_app.device_subscriptions
         SET status = $2, current_period_start = $3, current_period_end = $4, updated_at = NOW()
         WHERE stripe_subscription_id = $1",
    )
    .bind(stripe_subscription_id)
    .bind(status)
    .bind(period_start)
    .bind(period_end)
    .execute(db)
    .await
    .map_err(|e| Status::internal(format!("update sub period: {e}")))?;
    Ok(())
}
