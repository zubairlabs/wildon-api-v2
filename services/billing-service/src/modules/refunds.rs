//! Refund operations — admin-only, called via control-service.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use super::display_ref;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefundRow {
    pub id: Uuid,
    pub display_ref: String,
    pub invoice_id: Uuid,
    pub user_id: Uuid,
    pub admin_user_id: Uuid,
    pub stripe_refund_id: Option<String>,
    pub amount_cents: i32,
    pub currency: String,
    pub reason: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    db: &PgPool,
    invoice_id: Uuid,
    user_id: Uuid,
    admin_user_id: Uuid,
    stripe_refund_id: Option<&str>,
    stripe_payment_intent_id: Option<&str>,
    amount_cents: i32,
    currency: &str,
    reason: &str,
    status: &str,
) -> Result<RefundRow, Status> {
    let ref_code = display_ref::generate_unique_ref(db, "REF", "billing_app.refunds").await?;

    sqlx::query_as::<_, RefundRow>(
        "INSERT INTO billing_app.refunds
            (display_ref, invoice_id, user_id, admin_user_id, stripe_refund_id,
             stripe_payment_intent_id, amount_cents, currency, reason, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id, display_ref, invoice_id, user_id, admin_user_id,
                   stripe_refund_id, amount_cents, currency, reason, status, created_at",
    )
    .bind(ref_code)
    .bind(invoice_id)
    .bind(user_id)
    .bind(admin_user_id)
    .bind(stripe_refund_id)
    .bind(stripe_payment_intent_id)
    .bind(amount_cents)
    .bind(currency)
    .bind(reason)
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(|e| Status::internal(format!("insert refund: {e}")))
}

pub async fn list_by_invoice(
    db: &PgPool,
    invoice_id: Uuid,
) -> Result<(Vec<RefundRow>, i32), Status> {
    let rows = sqlx::query_as::<_, RefundRow>(
        "SELECT id, display_ref, invoice_id, user_id, admin_user_id,
                stripe_refund_id, amount_cents, currency, reason, status, created_at
         FROM billing_app.refunds WHERE invoice_id = $1 ORDER BY created_at DESC",
    )
    .bind(invoice_id)
    .fetch_all(db)
    .await
    .map_err(|e| Status::internal(format!("list refunds: {e}")))?;

    let total: i32 = rows
        .iter()
        .filter(|r| r.status == "succeeded")
        .map(|r| r.amount_cents)
        .sum();

    Ok((rows, total))
}
