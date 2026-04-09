//! Invoice v2 CRUD (device-aware invoices).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use super::display_ref;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvoiceV2Row {
    pub id: Uuid,
    pub display_ref: String,
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub subscription_id: Option<Uuid>,
    pub stripe_invoice_id: Option<String>,
    pub status: String,
    pub currency: String,
    pub subtotal_cents: i32,
    pub tax_cents: i32,
    pub tax_rate: rust_decimal::Decimal,
    pub tax_region: String,
    pub total_cents: i32,
    pub payment_method_brand: Option<String>,
    pub payment_method_last4: Option<String>,
    pub invoice_date: DateTime<Utc>,
    pub due_date: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvoiceItemRow {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub description: String,
    pub quantity: i32,
    pub unit_price_cents: i32,
    pub total_price_cents: i32,
}

const SELECT_INV: &str = r#"
    SELECT id, display_ref, user_id, device_id, subscription_id,
           stripe_invoice_id, status, currency,
           subtotal_cents, tax_cents, tax_rate, tax_region, total_cents,
           payment_method_brand, payment_method_last4,
           invoice_date, due_date, paid_at, created_at
    FROM billing_app.invoices_v2
"#;

pub async fn list_by_user(
    db: &PgPool,
    user_id: Uuid,
    limit: u32,
    cursor_offset: i64,
) -> Result<(Vec<InvoiceV2Row>, bool), Status> {
    let fetch_limit = (limit + 1) as i64;
    let q =
        format!("{SELECT_INV} WHERE user_id = $1 ORDER BY invoice_date DESC LIMIT $2 OFFSET $3");
    let rows = sqlx::query_as::<_, InvoiceV2Row>(&q)
        .bind(user_id)
        .bind(fetch_limit)
        .bind(cursor_offset)
        .fetch_all(db)
        .await
        .map_err(|e| Status::internal(format!("list invoices v2: {e}")))?;

    let has_more = rows.len() as u32 > limit;
    let items: Vec<_> = rows.into_iter().take(limit as usize).collect();
    Ok((items, has_more))
}

pub async fn get_by_id(
    db: &PgPool,
    user_id: Uuid,
    invoice_id: Uuid,
) -> Result<Option<InvoiceV2Row>, Status> {
    let q = format!("{SELECT_INV} WHERE id = $1 AND user_id = $2");
    sqlx::query_as::<_, InvoiceV2Row>(&q)
        .bind(invoice_id)
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(|e| Status::internal(format!("get invoice v2: {e}")))
}

/// Get an invoice by ID without user check (for admin refund flow).
pub async fn get_by_id_admin(
    db: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<InvoiceV2Row>, Status> {
    let q = format!("{SELECT_INV} WHERE id = $1");
    sqlx::query_as::<_, InvoiceV2Row>(&q)
        .bind(invoice_id)
        .fetch_optional(db)
        .await
        .map_err(|e| Status::internal(format!("get invoice v2 admin: {e}")))
}

pub async fn get_items(db: &PgPool, invoice_id: Uuid) -> Result<Vec<InvoiceItemRow>, Status> {
    sqlx::query_as::<_, InvoiceItemRow>(
        "SELECT id, invoice_id, description, quantity, unit_price_cents, total_price_cents
         FROM billing_app.invoice_items WHERE invoice_id = $1 ORDER BY id",
    )
    .bind(invoice_id)
    .fetch_all(db)
    .await
    .map_err(|e| Status::internal(format!("get invoice items: {e}")))
}

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    db: &PgPool,
    user_id: Uuid,
    device_id: Option<Uuid>,
    subscription_id: Option<Uuid>,
    stripe_invoice_id: Option<&str>,
    status: &str,
    currency: &str,
    subtotal_cents: i32,
    tax_cents: i32,
    tax_rate: f64,
    tax_region: &str,
    total_cents: i32,
    pm_brand: Option<&str>,
    pm_last4: Option<&str>,
) -> Result<(Uuid, String), Status> {
    let ref_code = display_ref::generate_unique_ref(db, "INV", "billing_app.invoices_v2").await?;

    let tax_decimal = rust_decimal::Decimal::try_from(tax_rate)
        .unwrap_or_else(|_| rust_decimal::Decimal::new(1300, 2));

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO billing_app.invoices_v2
            (display_ref, user_id, device_id, subscription_id, stripe_invoice_id,
             status, currency, subtotal_cents, tax_cents, tax_rate, tax_region,
             total_cents, payment_method_brand, payment_method_last4)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING id",
    )
    .bind(&ref_code)
    .bind(user_id)
    .bind(device_id)
    .bind(subscription_id)
    .bind(stripe_invoice_id)
    .bind(status)
    .bind(currency)
    .bind(subtotal_cents)
    .bind(tax_cents)
    .bind(tax_decimal)
    .bind(tax_region)
    .bind(total_cents)
    .bind(pm_brand)
    .bind(pm_last4)
    .fetch_one(db)
    .await
    .map_err(|e| Status::internal(format!("insert invoice v2: {e}")))?;

    Ok((row.0, ref_code))
}

pub async fn insert_item(
    db: &PgPool,
    invoice_id: Uuid,
    description: &str,
    quantity: i32,
    unit_price_cents: i32,
    total_price_cents: i32,
) -> Result<(), Status> {
    sqlx::query(
        "INSERT INTO billing_app.invoice_items
            (invoice_id, description, quantity, unit_price_cents, total_price_cents)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(invoice_id)
    .bind(description)
    .bind(quantity)
    .bind(unit_price_cents)
    .bind(total_price_cents)
    .execute(db)
    .await
    .map_err(|e| Status::internal(format!("insert invoice item: {e}")))?;
    Ok(())
}

pub async fn update_status(db: &PgPool, invoice_id: Uuid, status: &str) -> Result<(), Status> {
    sqlx::query("UPDATE billing_app.invoices_v2 SET status = $2 WHERE id = $1")
        .bind(invoice_id)
        .bind(status)
        .execute(db)
        .await
        .map_err(|e| Status::internal(format!("update invoice status: {e}")))?;
    Ok(())
}

pub async fn mark_paid(db: &PgPool, invoice_id: Uuid) -> Result<(), Status> {
    sqlx::query(
        "UPDATE billing_app.invoices_v2 SET status = 'paid', paid_at = NOW() WHERE id = $1",
    )
    .bind(invoice_id)
    .execute(db)
    .await
    .map_err(|e| Status::internal(format!("mark invoice paid: {e}")))?;
    Ok(())
}

pub async fn total_refunded(db: &PgPool, invoice_id: Uuid) -> Result<i32, Status> {
    let row: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT SUM(amount_cents) FROM billing_app.refunds WHERE invoice_id = $1 AND status = 'succeeded'",
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("total refunded: {e}")))?;
    Ok(row.and_then(|r| r.0).unwrap_or(0) as i32)
}
