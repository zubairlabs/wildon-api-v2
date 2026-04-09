//! Payment method CRUD — all queries filter `WHERE deleted_at IS NULL`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PaymentMethodRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub stripe_customer_id: String,
    pub stripe_payment_method_id: String,
    pub brand: Option<String>,
    pub last4: Option<String>,
    pub exp_month: Option<i32>,
    pub exp_year: Option<i32>,
    pub is_default: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub async fn list(db: &PgPool, user_id: Uuid) -> Result<Vec<PaymentMethodRow>, Status> {
    sqlx::query_as::<_, PaymentMethodRow>(
        "SELECT id, user_id, stripe_customer_id, stripe_payment_method_id,
                brand, last4, exp_month, exp_year, is_default, status, created_at
         FROM billing_app.payment_methods
         WHERE user_id = $1 AND deleted_at IS NULL
         ORDER BY is_default DESC, created_at DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(|e| Status::internal(format!("list payment methods: {e}")))
}

pub async fn insert(
    db: &PgPool,
    user_id: Uuid,
    stripe_customer_id: &str,
    stripe_pm_id: &str,
    brand: Option<&str>,
    last4: Option<&str>,
    exp_month: Option<i32>,
    exp_year: Option<i32>,
    set_default: bool,
) -> Result<PaymentMethodRow, Status> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| Status::internal(format!("begin txn: {e}")))?;

    if set_default {
        sqlx::query(
            "UPDATE billing_app.payment_methods SET is_default = false WHERE user_id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(format!("unset defaults: {e}")))?;
    }

    let row = sqlx::query_as::<_, PaymentMethodRow>(
        "INSERT INTO billing_app.payment_methods
            (user_id, stripe_customer_id, stripe_payment_method_id, brand, last4,
             exp_month, exp_year, is_default, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
         RETURNING id, user_id, stripe_customer_id, stripe_payment_method_id,
                   brand, last4, exp_month, exp_year, is_default, status, created_at",
    )
    .bind(user_id)
    .bind(stripe_customer_id)
    .bind(stripe_pm_id)
    .bind(brand)
    .bind(last4)
    .bind(exp_month)
    .bind(exp_year)
    .bind(set_default)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| Status::internal(format!("insert payment method: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| Status::internal(format!("commit: {e}")))?;
    Ok(row)
}

pub async fn set_default(db: &PgPool, user_id: Uuid, pm_id: Uuid) -> Result<(), Status> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| Status::internal(format!("begin txn: {e}")))?;

    sqlx::query(
        "UPDATE billing_app.payment_methods SET is_default = false WHERE user_id = $1 AND deleted_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| Status::internal(format!("unset defaults: {e}")))?;

    let updated = sqlx::query(
        "UPDATE billing_app.payment_methods SET is_default = true WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
    )
    .bind(pm_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| Status::internal(format!("set default: {e}")))?;

    if updated.rows_affected() == 0 {
        return Err(Status::not_found("payment method not found"));
    }

    tx.commit()
        .await
        .map_err(|e| Status::internal(format!("commit: {e}")))?;
    Ok(())
}

pub async fn soft_delete(db: &PgPool, user_id: Uuid, pm_id: Uuid) -> Result<(), Status> {
    let updated = sqlx::query(
        "UPDATE billing_app.payment_methods SET deleted_at = NOW(), status = 'removed' WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
    )
    .bind(pm_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| Status::internal(format!("soft delete pm: {e}")))?;

    if updated.rows_affected() == 0 {
        return Err(Status::not_found("payment method not found"));
    }
    Ok(())
}

/// Get the Stripe customer ID for a user (from any existing payment method).
pub async fn get_stripe_customer_id(db: &PgPool, user_id: Uuid) -> Result<Option<String>, Status> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT stripe_customer_id FROM billing_app.payment_methods WHERE user_id = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("get stripe customer: {e}")))?;
    Ok(row.map(|r| r.0))
}

/// Get the default payment method for a user.
pub async fn get_default(db: &PgPool, user_id: Uuid) -> Result<Option<PaymentMethodRow>, Status> {
    sqlx::query_as::<_, PaymentMethodRow>(
        "SELECT id, user_id, stripe_customer_id, stripe_payment_method_id,
                brand, last4, exp_month, exp_year, is_default, status, created_at
         FROM billing_app.payment_methods
         WHERE user_id = $1 AND is_default = true AND deleted_at IS NULL
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("get default pm: {e}")))
}
