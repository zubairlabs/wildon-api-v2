#![allow(dead_code)]

mod invoice_template;
mod modules;
mod state;

use crate::{
    modules::{
        device_subscriptions, entitlements, invoices_v2, payment_methods, plans, refunds,
        stripe_client::StripeClient, subscription_plans, subscriptions, usage,
    },
    state::{AppState, InvoiceRecord, LedgerEntryRecord, TransactionRecord},
};
use chrono::{Duration, Utc};
use config::grpc::{authorize_internal_request, load_server_tls_config, InternalAuthPolicy};
use contracts::wildon::billing::v1::{
    billing_service_server::{BillingService, BillingServiceServer},
    // v2 (device-first billing)
    AddPaymentMethodRequest,
    AddPaymentMethodResponse,
    // v1 (existing)
    BillingInvoice,
    BillingLedgerEntry,
    BillingPlan,
    BillingSubscription,
    BillingTransaction,
    CancelDeviceSubscriptionRequest,
    CancelDeviceSubscriptionResponse,
    CreateDeviceSubscriptionRequest,
    CreateDeviceSubscriptionResponse,
    CreatePlanRequest,
    CreatePlanResponse,
    CreateRefundRequest,
    CreateRefundResponse,
    CreateSetupIntentRequest,
    CreateSetupIntentResponse,
    CreateSubscriptionRequest,
    CreateSubscriptionResponse,
    DeletePlanRequest,
    DeletePlanResponse,
    DeviceBillingStatus,
    DeviceSubscriptionInfo,
    GetBillingSummaryRequest,
    GetBillingSummaryResponse,
    GetDeviceSubscriptionRequest,
    GetDeviceSubscriptionResponse,
    GetInvoiceHtmlRequest,
    GetInvoiceHtmlResponse,
    GetInvoiceV2Request,
    GetInvoiceV2Response,
    GetSubscriptionPlanRequest,
    GetSubscriptionPlanResponse,
    GetSubscriptionRequest,
    GetSubscriptionResponse,
    HealthRequest,
    HealthResponse,
    IngestBillingWebhookRequest,
    IngestBillingWebhookResponse,
    InvoiceItemInfo,
    InvoiceV2Info,
    ListDeviceSubscriptionsRequest,
    ListDeviceSubscriptionsResponse,
    ListInvoicesRequest,
    ListInvoicesResponse,
    ListInvoicesV2Request,
    ListInvoicesV2Response,
    ListLedgerEntriesRequest,
    ListLedgerEntriesResponse,
    ListPaymentMethodsRequest,
    ListPaymentMethodsResponse,
    ListPlansRequest,
    ListPlansResponse,
    ListRefundsByInvoiceRequest,
    ListRefundsByInvoiceResponse,
    ListSubscriptionPlansRequest,
    ListSubscriptionPlansResponse,
    ListSubscriptionsRequest,
    ListSubscriptionsResponse,
    ListTransactionsRequest,
    ListTransactionsResponse,
    PaymentMethodInfo,
    RecordUsageRequest,
    RecordUsageResponse,
    RefundInfo,
    RefundTransactionRequest,
    RefundTransactionResponse,
    RemovePaymentMethodRequest,
    RemovePaymentMethodResponse,
    ResolveEntitlementRequest,
    ResolveEntitlementResponse,
    ResumeDeviceSubscriptionRequest,
    ResumeDeviceSubscriptionResponse,
    RetryInvoicePaymentRequest,
    RetryInvoicePaymentResponse,
    SetDefaultPaymentMethodRequest,
    SetDefaultPaymentMethodResponse,
    SubscriptionPlanInfo,
    UpdatePlanRequest,
    UpdatePlanResponse,
    UpdateSubscriptionRequest,
    UpdateSubscriptionResponse,
    UpsertSubscriptionRequest,
    UpsertSubscriptionResponse,
    ValidateUserEntitlementRequest,
    ValidateUserEntitlementResponse,
};
use observability::init_tracing;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{env, net::SocketAddr};
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
struct BillingGrpc {
    state: AppState,
    internal_auth: InternalAuthPolicy,
    db: PgPool,
    stripe: Option<StripeClient>,
}

#[tonic::async_trait]
impl BillingService for BillingGrpc {
    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("missing")
            .to_string();

        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            request_id,
        }))
    }

    async fn resolve_entitlement(
        &self,
        request: Request<ResolveEntitlementRequest>,
    ) -> Result<Response<ResolveEntitlementResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["core-service", "public-service", "gateway-service"],
        )?;

        let payload = request.into_inner();
        let feature_key = if payload.feature_key.is_empty() {
            "profile_write".to_string()
        } else {
            payload.feature_key
        };

        let plan = {
            let subscriptions = self.state.subscriptions.lock().await;
            subscriptions
                .get(payload.user_id.as_str())
                .map(|record| record.plan.clone())
        };
        let plan = if let Some(plan) = plan {
            plan
        } else {
            let plan_overrides = self.state.plan_overrides.lock().await;
            plans::resolve_plan(&payload.user_id, &plan_overrides)
        };

        let allowed = entitlements::is_feature_allowed(
            &plan,
            &feature_key,
            self.state.plan_entitlements.as_ref(),
        );
        let reason = if allowed {
            "allowed".to_string()
        } else {
            format!("feature '{feature_key}' not available for plan '{plan}'")
        };

        Ok(Response::new(ResolveEntitlementResponse {
            allowed,
            plan,
            reason,
        }))
    }

    async fn validate_user_entitlement(
        &self,
        request: Request<ValidateUserEntitlementRequest>,
    ) -> Result<Response<ValidateUserEntitlementResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let payload = request.into_inner();
        let user_id = payload.user_id.trim();
        if user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let mut plan_code = "free".to_string();
        let mut subscription_status = "inactive".to_string();
        let mut current_devices = 0_i32;

        let linked_subscription_id = {
            let index = self.state.user_subscription_index.lock().await;
            index.get(user_id).cloned()
        };

        if let Some(subscription_id) = linked_subscription_id {
            let managed = self.state.managed_subscriptions.lock().await;
            if let Some(record) = managed.get(subscription_id.as_str()) {
                plan_code = record.plan_code.clone();
                subscription_status = record.status.clone();
                current_devices = record.device_count.max(0);
            }
        } else {
            let legacy = self.state.subscriptions.lock().await;
            if let Some(record) = legacy.get(user_id) {
                plan_code = record.plan.clone();
                subscription_status = record.status.clone();
            }
        }

        let mut device_limit = 1_i32;
        let plan_id = {
            let index = self.state.plan_code_index.lock().await;
            index.get(plan_code.as_str()).cloned()
        };
        if let Some(plan_id) = plan_id {
            let plans_catalog = self.state.plans_catalog.lock().await;
            if let Some(plan) = plans_catalog.get(plan_id.as_str()) {
                device_limit = plan.device_limit.max(0);
            }
        }

        let normalized_key = payload.entitlement_key.trim().to_ascii_lowercase();
        let is_device_check = normalized_key.is_empty()
            || normalized_key == "device_limit"
            || normalized_key == "device_manage";

        let allowed = if is_device_check {
            matches!(
                subscription_status.as_str(),
                "trial" | "active" | "past_due" | "inactive"
            ) && current_devices < device_limit
        } else {
            entitlements::is_feature_allowed(
                &plan_code,
                payload.entitlement_key.trim(),
                self.state.plan_entitlements.as_ref(),
            )
        };

        let reason = if allowed {
            "allowed".to_string()
        } else if is_device_check {
            "DEVICE_LIMIT_REACHED".to_string()
        } else {
            "feature_not_allowed_for_plan".to_string()
        };

        Ok(Response::new(ValidateUserEntitlementResponse {
            allowed,
            reason,
            plan: plan_code,
            subscription_status,
            device_limit,
            current_devices,
        }))
    }

    async fn record_usage(
        &self,
        request: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["core-service", "public-service", "gateway-service"],
        )?;

        let payload = request.into_inner();
        if payload.user_id.is_empty() || payload.metric.is_empty() {
            return Err(Status::invalid_argument("user_id and metric are required"));
        }

        let mut totals = self.state.usage_totals.lock().await;
        let total = usage::record_usage(
            &mut totals,
            &payload.user_id,
            &payload.metric,
            payload.amount,
        );

        Ok(Response::new(RecordUsageResponse { total }))
    }

    async fn ingest_billing_webhook(
        &self,
        request: Request<IngestBillingWebhookRequest>,
    ) -> Result<Response<IngestBillingWebhookResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["core-service", "gateway-service"],
        )?;

        let payload = request.into_inner();
        if payload.event_id.trim().is_empty() || payload.user_id.trim().is_empty() {
            return Err(Status::invalid_argument(
                "event_id and user_id are required",
            ));
        }

        let provider = crate::modules::stripe_webhooks::normalize_provider(&payload.provider);
        if provider == "stripe" {
            self.state
                .stripe
                .verify(&payload.signature, &payload.payload_json, &payload.event_id)
                .map_err(|err| {
                    Status::permission_denied(format!("stripe verification failed: {err}"))
                })?;
        }

        let dedupe_key = format!("{provider}:{}", payload.event_id);
        let mut billing_events = self.state.billing_events.lock().await;
        let payload_hash = crate::modules::stripe_webhooks::payload_hash(&payload.payload_json);
        if let Some(existing) = billing_events.get(&dedupe_key) {
            if existing.payload_hash != payload_hash {
                return Err(Status::failed_precondition(
                    "webhook event replay payload mismatch",
                ));
            }
            return Ok(Response::new(IngestBillingWebhookResponse {
                accepted: false,
                duplicate: true,
                invoice_id: existing.invoice_id.clone(),
                reason: "duplicate billing event".to_string(),
                transaction_id: existing.transaction_id.clone(),
            }));
        }

        let record = crate::modules::stripe_webhooks::BillingEventRecord::new(
            &provider,
            &payload.event_id,
            &payload.user_id,
            payload.amount_cents,
            &payload.currency,
            &payload.payload_json,
        );
        let invoice_id = record.invoice_id.clone();
        let transaction_id = record.transaction_id.clone();
        let now = Utc::now().timestamp();
        let currency = payload.currency.trim().to_uppercase();
        let amount_cents = payload.amount_cents;
        let user_id = payload.user_id.trim().to_string();

        {
            let mut invoices = self.state.invoices.lock().await;
            invoices.insert(
                invoice_id.clone(),
                InvoiceRecord {
                    invoice_id: invoice_id.clone(),
                    user_id: user_id.clone(),
                    status: "issued".to_string(),
                    amount_cents,
                    refunded_amount_cents: 0,
                    currency: currency.clone(),
                    created_at: now,
                    updated_at: now,
                },
            );
        }
        {
            let mut transactions = self.state.transactions.lock().await;
            transactions.insert(
                transaction_id.clone(),
                TransactionRecord {
                    transaction_id: transaction_id.clone(),
                    user_id: user_id.clone(),
                    invoice_id: invoice_id.clone(),
                    status: "settled".to_string(),
                    amount_cents,
                    refunded_amount_cents: 0,
                    currency: currency.clone(),
                    provider: provider.clone(),
                    external_txn_id: payload.event_id.clone(),
                    created_at: now,
                    updated_at: now,
                },
            );
        }
        {
            let mut ledger_entries = self.state.ledger_entries.lock().await;
            ledger_entries.push(LedgerEntryRecord {
                ledger_id: next_ledger_id(),
                user_id: user_id.clone(),
                transaction_id: transaction_id.clone(),
                invoice_id: invoice_id.clone(),
                entry_type: "payment_settled".to_string(),
                amount_cents,
                currency: currency.clone(),
                note: format!("provider={provider};event_id={}", payload.event_id),
                created_at: now,
            });
        }
        billing_events.insert(dedupe_key, record);

        Ok(Response::new(IngestBillingWebhookResponse {
            accepted: true,
            duplicate: false,
            invoice_id,
            reason: "accepted".to_string(),
            transaction_id,
        }))
    }

    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<GetSubscriptionResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "core-service",
                "public-service",
                "gateway-service",
                "control-service",
            ],
        )?;

        let user_id = request.into_inner().user_id;
        if user_id.trim().is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let subscriptions = self.state.subscriptions.lock().await;
        if let Some(subscription) = subscriptions.get(user_id.trim()) {
            return Ok(Response::new(GetSubscriptionResponse {
                user_id,
                plan: subscription.plan.clone(),
                status: subscription.status.clone(),
                current_period_end: subscription.current_period_end,
            }));
        }
        drop(subscriptions);

        let linked_subscription_id = {
            let index = self.state.user_subscription_index.lock().await;
            index.get(user_id.trim()).cloned()
        };
        if let Some(subscription_id) = linked_subscription_id {
            let managed = self.state.managed_subscriptions.lock().await;
            if let Some(subscription) = managed.get(subscription_id.as_str()) {
                return Ok(Response::new(GetSubscriptionResponse {
                    user_id,
                    plan: subscription.plan_code.clone(),
                    status: subscription.status.clone(),
                    current_period_end: subscription.end_date,
                }));
            }
        }

        let plan_overrides = self.state.plan_overrides.lock().await;
        let plan = plans::resolve_plan(user_id.trim(), &plan_overrides);
        let current_period_end = (Utc::now() + Duration::days(30)).timestamp();

        Ok(Response::new(GetSubscriptionResponse {
            user_id,
            plan,
            status: "active".to_string(),
            current_period_end,
        }))
    }

    async fn upsert_subscription(
        &self,
        request: Request<UpsertSubscriptionRequest>,
    ) -> Result<Response<UpsertSubscriptionResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["control-service", "core-service", "gateway-service"],
        )?;

        let idempotency_key = request
            .metadata()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Status::invalid_argument("missing idempotency-key metadata"))?
            .to_string();

        let payload = request.into_inner();
        if payload.user_id.trim().is_empty() || payload.plan.trim().is_empty() {
            return Err(Status::invalid_argument("user_id and plan are required"));
        }

        let status = if payload.status.trim().is_empty() {
            "active".to_string()
        } else {
            payload.status.trim().to_string()
        };
        let current_period_end = if payload.current_period_end > 0 {
            payload.current_period_end
        } else {
            (Utc::now() + Duration::days(30)).timestamp()
        };

        let request_hash = subscription_request_hash(
            payload.user_id.trim(),
            payload.plan.trim(),
            &status,
            current_period_end,
        );
        let operation_key = format!("upsert_subscription:{idempotency_key}");
        let now = Utc::now().timestamp();

        let mut idempotency_records = self.state.idempotency_records.lock().await;
        idempotency_records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = idempotency_records.get(&operation_key) {
            if existing.request_hash != request_hash {
                return Err(Status::already_exists(
                    "idempotency key reuse with a different request payload",
                ));
            }

            return Ok(Response::new(UpsertSubscriptionResponse {
                duplicate: true,
                user_id: payload.user_id,
                plan: existing.response.plan.clone(),
                status: existing.response.status.clone(),
                current_period_end: existing.response.current_period_end,
            }));
        }

        let subscription = crate::modules::subscriptions::SubscriptionRecord {
            plan: payload.plan.trim().to_string(),
            status: status.clone(),
            current_period_end,
        };
        let user_id = payload.user_id.trim().to_string();

        let mut subscriptions = self.state.subscriptions.lock().await;
        subscriptions.insert(user_id.clone(), subscription.clone());
        drop(subscriptions);

        idempotency_records.insert(
            operation_key,
            crate::state::IdempotencyRecord {
                request_hash,
                response: subscription.clone(),
                expires_at: self.state.idempotency_expiry_timestamp(),
            },
        );

        Ok(Response::new(UpsertSubscriptionResponse {
            duplicate: false,
            user_id,
            plan: subscription.plan,
            status,
            current_period_end,
        }))
    }

    async fn list_plans(
        &self,
        request: Request<ListPlansRequest>,
    ) -> Result<Response<ListPlansResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "control-service",
                "public-service",
                "core-service",
                "gateway-service",
            ],
        )?;

        let payload = request.into_inner();
        let filter_status = payload.status.trim().to_ascii_lowercase();
        let limit = normalize_limit(payload.limit);
        let cursor = parse_offset_cursor(payload.cursor.as_str())?;

        let plans_catalog = self.state.plans_catalog.lock().await;
        let mut plans = plans_catalog.values().cloned().collect::<Vec<_>>();
        drop(plans_catalog);

        if !filter_status.is_empty() {
            plans.retain(|plan| plan.status == filter_status);
        }
        plans.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| right.created_at.cmp(&left.created_at))
                .then_with(|| right.plan_id.cmp(&left.plan_id))
        });
        let (plans, next_cursor, has_more) = paginate_items(plans, limit, cursor);

        Ok(Response::new(ListPlansResponse {
            plans: plans.iter().map(to_proto_plan).collect(),
            next_cursor,
            has_more,
        }))
    }

    async fn create_plan(
        &self,
        request: Request<CreatePlanRequest>,
    ) -> Result<Response<CreatePlanResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;
        let payload = request.into_inner();

        let plan_code = payload.plan_code.trim().to_ascii_lowercase();
        if plan_code.is_empty() {
            return Err(Status::invalid_argument("plan_code is required"));
        }
        let interval = subscriptions::normalize_plan_interval(payload.interval.as_str())
            .ok_or_else(|| Status::invalid_argument("interval must be monthly|yearly|lifetime"))?;
        let status = if payload.status.trim().is_empty() {
            "active".to_string()
        } else {
            subscriptions::normalize_plan_status(payload.status.as_str())
                .ok_or_else(|| Status::invalid_argument("status must be active|archived"))?
        };
        if payload.price_cents < 0 {
            return Err(Status::invalid_argument("price_cents cannot be negative"));
        }
        if payload.device_limit < 0 {
            return Err(Status::invalid_argument("device_limit cannot be negative"));
        }
        if payload.retention_days < 0 {
            return Err(Status::invalid_argument(
                "retention_days cannot be negative",
            ));
        }
        if payload.storage_limit_bytes < 0 {
            return Err(Status::invalid_argument(
                "storage_limit_bytes cannot be negative",
            ));
        }

        {
            let index = self.state.plan_code_index.lock().await;
            if index.contains_key(plan_code.as_str()) {
                return Err(Status::already_exists("plan_code already exists"));
            }
        }

        let now = Utc::now().timestamp();
        let plan_id = format!("plan-{}", Uuid::new_v4().simple());
        let currency = if payload.currency.trim().is_empty() {
            "USD".to_string()
        } else {
            payload.currency.trim().to_ascii_uppercase()
        };
        let plan = subscriptions::PlanRecord {
            plan_id: plan_id.clone(),
            plan_code: plan_code.clone(),
            name: payload.name.trim().to_string(),
            description: payload.description.trim().to_string(),
            priority: payload.priority,
            interval,
            price_cents: payload.price_cents,
            currency,
            device_limit: payload.device_limit,
            storage_limit_bytes: payload.storage_limit_bytes,
            retention_days: payload.retention_days,
            status,
            created_at: now,
            updated_at: now,
        };

        {
            let mut plans_catalog = self.state.plans_catalog.lock().await;
            plans_catalog.insert(plan_id.clone(), plan.clone());
        }
        {
            let mut index = self.state.plan_code_index.lock().await;
            index.insert(plan_code, plan_id);
        }

        Ok(Response::new(CreatePlanResponse {
            plan: Some(to_proto_plan(&plan)),
        }))
    }

    async fn update_plan(
        &self,
        request: Request<UpdatePlanRequest>,
    ) -> Result<Response<UpdatePlanResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;
        let payload = request.into_inner();
        if payload.plan_id.trim().is_empty() {
            return Err(Status::invalid_argument("plan_id is required"));
        }

        let now = Utc::now().timestamp();
        let existing_plan = {
            let plans_catalog = self.state.plans_catalog.lock().await;
            plans_catalog
                .get(payload.plan_id.trim())
                .cloned()
                .ok_or_else(|| Status::not_found("plan not found"))?
        };

        let mut plan = existing_plan.clone();
        if let Some(value) = payload.plan_code {
            let normalized = value.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(Status::invalid_argument("plan_code cannot be empty"));
            }
            if normalized != plan.plan_code {
                let index = self.state.plan_code_index.lock().await;
                if index.contains_key(normalized.as_str()) {
                    return Err(Status::already_exists("plan_code already exists"));
                }
                drop(index);
                plan.plan_code = normalized;
            }
        }
        if let Some(value) = payload.name {
            let normalized = value.trim();
            if normalized.is_empty() {
                return Err(Status::invalid_argument("name cannot be empty"));
            }
            plan.name = normalized.to_string();
        }
        if let Some(value) = payload.description {
            plan.description = value.trim().to_string();
        }
        if let Some(value) = payload.priority {
            plan.priority = value;
        }
        if let Some(value) = payload.interval {
            plan.interval =
                subscriptions::normalize_plan_interval(value.as_str()).ok_or_else(|| {
                    Status::invalid_argument("interval must be monthly|yearly|lifetime")
                })?;
        }
        if let Some(value) = payload.price_cents {
            if value < 0 {
                return Err(Status::invalid_argument("price_cents cannot be negative"));
            }
            plan.price_cents = value;
        }
        if let Some(value) = payload.currency {
            let normalized = value.trim().to_ascii_uppercase();
            if normalized.is_empty() {
                return Err(Status::invalid_argument("currency cannot be empty"));
            }
            plan.currency = normalized;
        }
        if let Some(value) = payload.device_limit {
            if value < 0 {
                return Err(Status::invalid_argument("device_limit cannot be negative"));
            }
            plan.device_limit = value;
        }
        if let Some(value) = payload.storage_limit_bytes {
            if value < 0 {
                return Err(Status::invalid_argument(
                    "storage_limit_bytes cannot be negative",
                ));
            }
            plan.storage_limit_bytes = value;
        }
        if let Some(value) = payload.retention_days {
            if value < 0 {
                return Err(Status::invalid_argument(
                    "retention_days cannot be negative",
                ));
            }
            plan.retention_days = value;
        }
        if let Some(value) = payload.status {
            plan.status = subscriptions::normalize_plan_status(value.as_str())
                .ok_or_else(|| Status::invalid_argument("status must be active|archived"))?;
        }
        plan.updated_at = now;

        {
            let mut plans_catalog = self.state.plans_catalog.lock().await;
            plans_catalog.insert(plan.plan_id.clone(), plan.clone());
        }
        if plan.plan_code != existing_plan.plan_code {
            let mut index = self.state.plan_code_index.lock().await;
            index.remove(existing_plan.plan_code.as_str());
            index.insert(plan.plan_code.clone(), plan.plan_id.clone());
        }

        Ok(Response::new(UpdatePlanResponse {
            plan: Some(to_proto_plan(&plan)),
        }))
    }

    async fn delete_plan(
        &self,
        request: Request<DeletePlanRequest>,
    ) -> Result<Response<DeletePlanResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;
        let payload = request.into_inner();
        if payload.plan_id.trim().is_empty() {
            return Err(Status::invalid_argument("plan_id is required"));
        }

        let mut plans_catalog = self.state.plans_catalog.lock().await;
        let plan = plans_catalog
            .get_mut(payload.plan_id.trim())
            .ok_or_else(|| Status::not_found("plan not found"))?;
        plan.status = "archived".to_string();
        plan.updated_at = Utc::now().timestamp();

        Ok(Response::new(DeletePlanResponse {
            deleted: true,
            plan: Some(to_proto_plan(plan)),
        }))
    }

    async fn list_subscriptions(
        &self,
        request: Request<ListSubscriptionsRequest>,
    ) -> Result<Response<ListSubscriptionsResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "control-service",
                "public-service",
                "core-service",
                "gateway-service",
            ],
        )?;

        let payload = request.into_inner();
        let filter_user = payload.user_id.trim().to_string();
        let filter_status = payload.status.trim().to_ascii_lowercase();
        let filter_plan_code = payload.plan_code.trim().to_ascii_lowercase();
        let limit = normalize_limit(payload.limit);
        let cursor = parse_offset_cursor(payload.cursor.as_str())?;

        let managed = self.state.managed_subscriptions.lock().await;
        let mut subscriptions = managed.values().cloned().collect::<Vec<_>>();
        drop(managed);

        if !filter_user.is_empty() {
            subscriptions.retain(|record| record.user_id == filter_user);
        }
        if !filter_status.is_empty() {
            subscriptions.retain(|record| record.status == filter_status);
        }
        if !filter_plan_code.is_empty() {
            subscriptions.retain(|record| record.plan_code == filter_plan_code);
        }

        subscriptions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.subscription_id.cmp(&left.subscription_id))
        });
        let (subscriptions, next_cursor, has_more) = paginate_items(subscriptions, limit, cursor);

        Ok(Response::new(ListSubscriptionsResponse {
            subscriptions: subscriptions.iter().map(to_proto_subscription).collect(),
            next_cursor,
            has_more,
        }))
    }

    async fn create_subscription(
        &self,
        request: Request<CreateSubscriptionRequest>,
    ) -> Result<Response<CreateSubscriptionResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;
        let payload = request.into_inner();

        let user_id = payload.user_id.trim();
        if user_id.is_empty() {
            return Err(Status::invalid_argument("user_id is required"));
        }

        let plan = resolve_plan_for_request(
            &self.state,
            payload.plan_id.trim(),
            payload.plan_code.trim(),
        )
        .await?;
        if plan.status != "active" {
            return Err(Status::failed_precondition(
                "cannot subscribe to an archived plan",
            ));
        }

        let status = if payload.status.trim().is_empty() {
            "active".to_string()
        } else {
            subscriptions::normalize_subscription_status(payload.status.as_str()).ok_or_else(
                || {
                    Status::invalid_argument(
                        "status must be trial|active|past_due|cancelled|expired",
                    )
                },
            )?
        };

        let now = Utc::now().timestamp();
        let start_date = if payload.start_date > 0 {
            payload.start_date
        } else {
            now
        };
        let end_date = if payload.end_date > 0 {
            payload.end_date
        } else {
            default_subscription_end_date(start_date, &plan.interval)
        };
        let auto_renew = payload.auto_renew.unwrap_or(plan.interval != "lifetime")
            && plan.interval != "lifetime";
        let device_count = payload.device_count.unwrap_or(0).max(0);

        let subscription_id = format!("sub-{}", Uuid::new_v4().simple());
        let subscription_code = {
            let mut sequence = self.state.next_subscription_sequence.lock().await;
            *sequence += 1;
            format!("SUB-{}", *sequence)
        };
        let record = subscriptions::ManagedSubscriptionRecord {
            subscription_id: subscription_id.clone(),
            subscription_code: subscription_code.clone(),
            user_id: user_id.to_string(),
            plan_id: plan.plan_id.clone(),
            plan_code: plan.plan_code.clone(),
            status: status.clone(),
            start_date,
            end_date,
            auto_renew,
            device_count,
            created_at: now,
            updated_at: now,
        };

        {
            let mut managed = self.state.managed_subscriptions.lock().await;
            managed.insert(subscription_id.clone(), record.clone());
        }
        {
            let mut by_user = self.state.user_subscription_index.lock().await;
            by_user.insert(user_id.to_string(), subscription_id);
        }
        {
            let mut legacy = self.state.subscriptions.lock().await;
            legacy.insert(
                user_id.to_string(),
                crate::modules::subscriptions::SubscriptionRecord {
                    plan: plan.plan_code.clone(),
                    status,
                    current_period_end: end_date,
                },
            );
        }

        Ok(Response::new(CreateSubscriptionResponse {
            subscription: Some(to_proto_subscription(&record)),
        }))
    }

    async fn update_subscription(
        &self,
        request: Request<UpdateSubscriptionRequest>,
    ) -> Result<Response<UpdateSubscriptionResponse>, Status> {
        let _caller =
            authorize_internal_request(&self.internal_auth, &request, &["control-service"])?;
        let payload = request.into_inner();
        if payload.subscription_id.trim().is_empty() {
            return Err(Status::invalid_argument("subscription_id is required"));
        }

        let existing = {
            let managed = self.state.managed_subscriptions.lock().await;
            managed
                .get(payload.subscription_id.trim())
                .cloned()
                .ok_or_else(|| Status::not_found("subscription not found"))?
        };

        let mut record = existing.clone();
        if payload.plan_id.is_some() || payload.plan_code.is_some() {
            let plan = resolve_plan_for_request(
                &self.state,
                payload.plan_id.as_deref().unwrap_or_default(),
                payload.plan_code.as_deref().unwrap_or_default(),
            )
            .await?;
            record.plan_id = plan.plan_id.clone();
            record.plan_code = plan.plan_code.clone();
            if plan.interval == "lifetime" {
                record.auto_renew = false;
            }
        }

        if let Some(next_status) = payload.status {
            let normalized = subscriptions::normalize_subscription_status(next_status.as_str())
                .ok_or_else(|| {
                    Status::invalid_argument(
                        "status must be trial|active|past_due|cancelled|expired",
                    )
                })?;
            if !subscriptions::can_transition_subscription_status(
                record.status.as_str(),
                normalized.as_str(),
            ) {
                return Err(Status::failed_precondition(format!(
                    "illegal subscription status transition: {} -> {}",
                    record.status, normalized
                )));
            }
            record.status = normalized;
        }

        if let Some(end_date) = payload.end_date {
            if end_date <= 0 {
                return Err(Status::invalid_argument("end_date must be positive"));
            }
            record.end_date = end_date;
        }

        if let Some(auto_renew) = payload.auto_renew {
            let plan = resolve_plan_for_request(&self.state, record.plan_id.as_str(), "").await?;
            record.auto_renew = auto_renew && plan.interval != "lifetime";
        }
        if let Some(device_count) = payload.device_count {
            if device_count < 0 {
                return Err(Status::invalid_argument("device_count cannot be negative"));
            }
            record.device_count = device_count;
        }

        record.updated_at = Utc::now().timestamp();

        {
            let mut managed = self.state.managed_subscriptions.lock().await;
            managed.insert(record.subscription_id.clone(), record.clone());
        }
        {
            let mut by_user = self.state.user_subscription_index.lock().await;
            by_user.insert(record.user_id.clone(), record.subscription_id.clone());
        }
        {
            let mut legacy = self.state.subscriptions.lock().await;
            legacy.insert(
                record.user_id.clone(),
                crate::modules::subscriptions::SubscriptionRecord {
                    plan: record.plan_code.clone(),
                    status: record.status.clone(),
                    current_period_end: record.end_date,
                },
            );
        }

        Ok(Response::new(UpdateSubscriptionResponse {
            subscription: Some(to_proto_subscription(&record)),
        }))
    }

    async fn list_transactions(
        &self,
        request: Request<ListTransactionsRequest>,
    ) -> Result<Response<ListTransactionsResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "control-service",
                "public-service",
                "core-service",
                "gateway-service",
            ],
        )?;

        let payload = request.into_inner();
        let filter_user = payload.user_id.trim().to_string();
        let limit = normalize_limit(payload.limit);
        let cursor = parse_offset_cursor(payload.cursor.as_str())?;

        let transactions = self.state.transactions.lock().await;
        let mut items = transactions.values().cloned().collect::<Vec<_>>();
        drop(transactions);

        if !filter_user.is_empty() {
            items.retain(|record| record.user_id == filter_user);
        }
        items.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.transaction_id.cmp(&left.transaction_id))
        });
        let (items, next_cursor, has_more) = paginate_items(items, limit, cursor);

        Ok(Response::new(ListTransactionsResponse {
            transactions: items.iter().map(to_proto_transaction).collect(),
            next_cursor,
            has_more,
        }))
    }

    async fn list_invoices(
        &self,
        request: Request<ListInvoicesRequest>,
    ) -> Result<Response<ListInvoicesResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "control-service",
                "public-service",
                "core-service",
                "gateway-service",
            ],
        )?;

        let payload = request.into_inner();
        let filter_user = payload.user_id.trim().to_string();
        let limit = normalize_limit(payload.limit);
        let cursor = parse_offset_cursor(payload.cursor.as_str())?;

        let invoices = self.state.invoices.lock().await;
        let mut items = invoices.values().cloned().collect::<Vec<_>>();
        drop(invoices);

        if !filter_user.is_empty() {
            items.retain(|record| record.user_id == filter_user);
        }
        items.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.invoice_id.cmp(&left.invoice_id))
        });
        let (items, next_cursor, has_more) = paginate_items(items, limit, cursor);

        Ok(Response::new(ListInvoicesResponse {
            invoices: items.iter().map(to_proto_invoice).collect(),
            next_cursor,
            has_more,
        }))
    }

    async fn list_ledger_entries(
        &self,
        request: Request<ListLedgerEntriesRequest>,
    ) -> Result<Response<ListLedgerEntriesResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &[
                "control-service",
                "public-service",
                "core-service",
                "gateway-service",
            ],
        )?;

        let payload = request.into_inner();
        let filter_user = payload.user_id.trim().to_string();
        let filter_transaction = payload.transaction_id.trim().to_string();
        let limit = normalize_limit(payload.limit);
        let cursor = parse_offset_cursor(payload.cursor.as_str())?;

        let ledger = self.state.ledger_entries.lock().await;
        let mut items = ledger.clone();
        drop(ledger);

        if !filter_user.is_empty() {
            items.retain(|record| record.user_id == filter_user);
        }
        if !filter_transaction.is_empty() {
            items.retain(|record| record.transaction_id == filter_transaction);
        }
        items.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.ledger_id.cmp(&left.ledger_id))
        });
        let (items, next_cursor, has_more) = paginate_items(items, limit, cursor);

        Ok(Response::new(ListLedgerEntriesResponse {
            entries: items.iter().map(to_proto_ledger_entry).collect(),
            next_cursor,
            has_more,
        }))
    }

    async fn refund_transaction(
        &self,
        request: Request<RefundTransactionRequest>,
    ) -> Result<Response<RefundTransactionResponse>, Status> {
        let _caller = authorize_internal_request(
            &self.internal_auth,
            &request,
            &["control-service", "core-service", "gateway-service"],
        )?;

        let payload = request.into_inner();
        let transaction_id = payload.transaction_id.trim();
        if transaction_id.is_empty() {
            return Err(Status::invalid_argument("transaction_id is required"));
        }

        let reason = if payload.reason.trim().is_empty() {
            "manual_refund".to_string()
        } else {
            payload.reason.trim().to_string()
        };
        let now = Utc::now().timestamp();

        let (transaction, refund_amount_cents) = {
            let mut transactions = self.state.transactions.lock().await;
            let transaction = transactions
                .get_mut(transaction_id)
                .ok_or_else(|| Status::not_found("transaction not found"))?;
            if transaction.amount_cents <= 0 {
                return Err(Status::failed_precondition(
                    "refund is only supported for positive settled transactions",
                ));
            }

            let refundable = transaction
                .amount_cents
                .saturating_sub(transaction.refunded_amount_cents);
            if refundable <= 0 {
                return Err(Status::failed_precondition(
                    "transaction is already fully refunded",
                ));
            }

            let requested = if payload.amount_cents > 0 {
                payload.amount_cents
            } else {
                refundable
            };
            if requested <= 0 {
                return Err(Status::invalid_argument("amount_cents must be positive"));
            }
            if requested > refundable {
                return Err(Status::failed_precondition(
                    "refund amount exceeds refundable balance",
                ));
            }

            transaction.refunded_amount_cents += requested;
            transaction.updated_at = now;
            if transaction.refunded_amount_cents >= transaction.amount_cents {
                transaction.status = "refunded".to_string();
            }
            (transaction.clone(), requested)
        };

        let invoice = {
            let mut invoices = self.state.invoices.lock().await;
            let invoice = invoices
                .get_mut(transaction.invoice_id.as_str())
                .ok_or_else(|| Status::not_found("invoice not found"))?;
            invoice.refunded_amount_cents += refund_amount_cents;
            invoice.updated_at = now;
            if invoice.refunded_amount_cents >= invoice.amount_cents {
                invoice.status = "refunded".to_string();
            } else if invoice.refunded_amount_cents > 0 {
                invoice.status = "partially_refunded".to_string();
            }
            invoice.clone()
        };

        let ledger_entry = LedgerEntryRecord {
            ledger_id: next_ledger_id(),
            user_id: transaction.user_id.clone(),
            transaction_id: transaction.transaction_id.clone(),
            invoice_id: transaction.invoice_id.clone(),
            entry_type: "refund".to_string(),
            amount_cents: -refund_amount_cents,
            currency: transaction.currency.clone(),
            note: reason,
            created_at: now,
        };
        {
            let mut ledger_entries = self.state.ledger_entries.lock().await;
            ledger_entries.push(ledger_entry.clone());
        }

        Ok(Response::new(RefundTransactionResponse {
            refunded: true,
            reason: "refund applied".to_string(),
            transaction: Some(to_proto_transaction(&transaction)),
            invoice: Some(to_proto_invoice(&invoice)),
            ledger_entry: Some(to_proto_ledger_entry(&ledger_entry)),
        }))
    }

    // =========================================================================
    // v2: Device-first billing RPCs
    // =========================================================================

    async fn list_payment_methods(
        &self,
        request: Request<ListPaymentMethodsRequest>,
    ) -> Result<Response<ListPaymentMethodsResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let rows = payment_methods::list(&self.db, user_id).await?;
        Ok(Response::new(ListPaymentMethodsResponse {
            payment_methods: rows
                .into_iter()
                .map(|r| PaymentMethodInfo {
                    id: r.id.to_string(),
                    stripe_payment_method_id: r.stripe_payment_method_id,
                    brand: r.brand.unwrap_or_default(),
                    last4: r.last4.unwrap_or_default(),
                    exp_month: r.exp_month.unwrap_or(0),
                    exp_year: r.exp_year.unwrap_or(0),
                    is_default: r.is_default,
                    status: r.status,
                    created_at: r.created_at.timestamp(),
                })
                .collect(),
        }))
    }

    async fn create_setup_intent(
        &self,
        request: Request<CreateSetupIntentRequest>,
    ) -> Result<Response<CreateSetupIntentResponse>, Status> {
        let stripe = self
            .stripe
            .as_ref()
            .ok_or_else(|| Status::unavailable("stripe not configured"))?;
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;

        // Get or create Stripe customer
        let cust_id = match payment_methods::get_stripe_customer_id(&self.db, user_id).await? {
            Some(id) => id,
            None => {
                let cust = stripe
                    .get_or_create_customer(&user_id.to_string(), "")
                    .await
                    .map_err(|e| Status::internal(format!("stripe customer: {e}")))?;
                cust.id
            }
        };

        let si = stripe
            .create_setup_intent(&cust_id)
            .await
            .map_err(|e| Status::internal(format!("stripe setup intent: {e}")))?;

        Ok(Response::new(CreateSetupIntentResponse {
            client_secret: si.client_secret,
            stripe_customer_id: cust_id,
        }))
    }

    async fn add_payment_method(
        &self,
        request: Request<AddPaymentMethodRequest>,
    ) -> Result<Response<AddPaymentMethodResponse>, Status> {
        let stripe = self
            .stripe
            .as_ref()
            .ok_or_else(|| Status::unavailable("stripe not configured"))?;
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;

        let pm = stripe
            .get_payment_method(&req.stripe_payment_method_id)
            .await
            .map_err(|e| Status::internal(format!("get pm: {e}")))?;

        let card = pm.card.as_ref();
        let cust_id = payment_methods::get_stripe_customer_id(&self.db, user_id)
            .await?
            .ok_or_else(|| {
                Status::failed_precondition("no stripe customer — create setup intent first")
            })?;

        let row = payment_methods::insert(
            &self.db,
            user_id,
            &cust_id,
            &req.stripe_payment_method_id,
            card.map(|c| c.brand.as_str()),
            card.map(|c| c.last4.as_str()),
            card.map(|c| c.exp_month),
            card.map(|c| c.exp_year),
            req.set_as_default,
        )
        .await?;

        Ok(Response::new(AddPaymentMethodResponse {
            payment_method: Some(PaymentMethodInfo {
                id: row.id.to_string(),
                stripe_payment_method_id: row.stripe_payment_method_id,
                brand: row.brand.unwrap_or_default(),
                last4: row.last4.unwrap_or_default(),
                exp_month: row.exp_month.unwrap_or(0),
                exp_year: row.exp_year.unwrap_or(0),
                is_default: row.is_default,
                status: row.status,
                created_at: row.created_at.timestamp(),
            }),
        }))
    }

    async fn set_default_payment_method(
        &self,
        request: Request<SetDefaultPaymentMethodRequest>,
    ) -> Result<Response<SetDefaultPaymentMethodResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let pm_id: Uuid = req
            .payment_method_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad pm_id"))?;
        payment_methods::set_default(&self.db, user_id, pm_id).await?;
        Ok(Response::new(SetDefaultPaymentMethodResponse {
            success: true,
        }))
    }

    async fn remove_payment_method(
        &self,
        request: Request<RemovePaymentMethodRequest>,
    ) -> Result<Response<RemovePaymentMethodResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let pm_id: Uuid = req
            .payment_method_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad pm_id"))?;
        payment_methods::soft_delete(&self.db, user_id, pm_id).await?;

        // Detach from Stripe if configured
        if let Some(stripe) = &self.stripe {
            // Best-effort detach — don't fail if Stripe is unreachable
            let _ = stripe.detach_payment_method(&req.payment_method_id).await;
        }

        Ok(Response::new(RemovePaymentMethodResponse { success: true }))
    }

    async fn list_subscription_plans(
        &self,
        _request: Request<ListSubscriptionPlansRequest>,
    ) -> Result<Response<ListSubscriptionPlansResponse>, Status> {
        let rows = subscription_plans::list_active(&self.db).await?;
        Ok(Response::new(ListSubscriptionPlansResponse {
            plans: rows.into_iter().map(to_plan_info).collect(),
        }))
    }

    async fn get_subscription_plan(
        &self,
        request: Request<GetSubscriptionPlanRequest>,
    ) -> Result<Response<GetSubscriptionPlanResponse>, Status> {
        let req = request.into_inner();
        let plan_id: Uuid = req
            .plan_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad plan_id"))?;
        let row = subscription_plans::get_by_id(&self.db, plan_id)
            .await?
            .ok_or_else(|| Status::not_found("plan not found"))?;
        Ok(Response::new(GetSubscriptionPlanResponse {
            plan: Some(to_plan_info(row)),
        }))
    }

    async fn list_device_subscriptions(
        &self,
        request: Request<ListDeviceSubscriptionsRequest>,
    ) -> Result<Response<ListDeviceSubscriptionsResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let rows = device_subscriptions::list_by_user(&self.db, user_id).await?;
        Ok(Response::new(ListDeviceSubscriptionsResponse {
            subscriptions: rows.into_iter().map(to_device_sub_info).collect(),
        }))
    }

    async fn get_device_subscription(
        &self,
        request: Request<GetDeviceSubscriptionRequest>,
    ) -> Result<Response<GetDeviceSubscriptionResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let device_id: Uuid = req
            .device_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad device_id"))?;
        let row = device_subscriptions::get_by_device(&self.db, user_id, device_id)
            .await?
            .ok_or_else(|| Status::not_found("no subscription for device"))?;
        Ok(Response::new(GetDeviceSubscriptionResponse {
            subscription: Some(to_device_sub_info(row)),
        }))
    }

    async fn create_device_subscription(
        &self,
        request: Request<CreateDeviceSubscriptionRequest>,
    ) -> Result<Response<CreateDeviceSubscriptionResponse>, Status> {
        let stripe = self
            .stripe
            .as_ref()
            .ok_or_else(|| Status::unavailable("stripe not configured"))?;
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let device_id: Uuid = req
            .device_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad device_id"))?;
        let plan_id: Uuid = req
            .plan_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad plan_id"))?;
        let pm_id: Uuid = req
            .payment_method_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad pm_id"))?;

        // Check double subscription
        if device_subscriptions::has_active(&self.db, device_id).await? {
            return Err(Status::already_exists(
                "device already has an active subscription",
            ));
        }

        // Load plan
        let plan = subscription_plans::get_by_id(&self.db, plan_id)
            .await?
            .ok_or_else(|| Status::not_found("plan not found"))?;

        let stripe_price_id = plan
            .stripe_price_id
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("plan has no stripe_price_id configured"))?;

        // Get Stripe customer + PM
        let cust_id = payment_methods::get_stripe_customer_id(&self.db, user_id)
            .await?
            .ok_or_else(|| {
                Status::failed_precondition("no stripe customer — add payment method first")
            })?;

        let pm_rows = payment_methods::list(&self.db, user_id).await?;
        let pm = pm_rows
            .iter()
            .find(|r| r.id == pm_id)
            .ok_or_else(|| Status::not_found("payment method not found"))?;

        // Create Stripe subscription
        let stripe_sub = stripe
            .create_subscription(
                &cust_id,
                stripe_price_id,
                &pm.stripe_payment_method_id,
                plan.trial_days,
            )
            .await
            .map_err(|e| Status::internal(format!("stripe create sub: {e}")))?;

        let period_start = chrono::DateTime::from_timestamp(stripe_sub.current_period_start, 0);
        let period_end = chrono::DateTime::from_timestamp(stripe_sub.current_period_end, 0);

        // Insert DB record
        let sub_id = device_subscriptions::insert(
            &self.db,
            user_id,
            device_id,
            plan_id,
            Some(&cust_id),
            Some(&stripe_sub.id),
            Some(stripe_price_id),
            Some(pm_id),
            &stripe_sub.status,
            period_start,
            period_end,
        )
        .await?;

        let row = device_subscriptions::get_by_id(&self.db, sub_id)
            .await?
            .ok_or_else(|| Status::internal("subscription just created but not found"))?;

        Ok(Response::new(CreateDeviceSubscriptionResponse {
            subscription: Some(to_device_sub_info(row)),
            stripe_subscription_id: stripe_sub.id,
        }))
    }

    async fn cancel_device_subscription(
        &self,
        request: Request<CancelDeviceSubscriptionRequest>,
    ) -> Result<Response<CancelDeviceSubscriptionResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let sub_id: Uuid = req
            .subscription_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad sub_id"))?;

        let sub = device_subscriptions::get_by_id(&self.db, sub_id)
            .await?
            .ok_or_else(|| Status::not_found("subscription not found"))?;

        if sub.user_id != user_id {
            return Err(Status::permission_denied("not subscription owner"));
        }

        if let (Some(stripe), Some(stripe_sub_id)) = (&self.stripe, &sub.stripe_subscription_id) {
            stripe
                .cancel_subscription(stripe_sub_id, !req.cancel_immediately)
                .await
                .map_err(|e| Status::internal(format!("stripe cancel: {e}")))?;
        }

        let (new_status, cancel_at_end) = if req.cancel_immediately {
            ("canceled", false)
        } else {
            (sub.status.as_str(), true)
        };

        device_subscriptions::update_status(
            &self.db,
            sub_id,
            new_status,
            Some(cancel_at_end),
            Some(Utc::now()),
            None,
        )
        .await?;

        let row = device_subscriptions::get_by_id(&self.db, sub_id)
            .await?
            .ok_or_else(|| Status::internal("sub not found after update"))?;

        Ok(Response::new(CancelDeviceSubscriptionResponse {
            subscription: Some(to_device_sub_info(row)),
        }))
    }

    async fn resume_device_subscription(
        &self,
        request: Request<ResumeDeviceSubscriptionRequest>,
    ) -> Result<Response<ResumeDeviceSubscriptionResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let sub_id: Uuid = req
            .subscription_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad sub_id"))?;

        let sub = device_subscriptions::get_by_id(&self.db, sub_id)
            .await?
            .ok_or_else(|| Status::not_found("subscription not found"))?;

        if sub.user_id != user_id {
            return Err(Status::permission_denied("not subscription owner"));
        }
        if !sub.cancel_at_period_end {
            return Err(Status::failed_precondition(
                "subscription not pending cancellation",
            ));
        }

        if let (Some(stripe), Some(stripe_sub_id)) = (&self.stripe, &sub.stripe_subscription_id) {
            stripe
                .resume_subscription(stripe_sub_id)
                .await
                .map_err(|e| Status::internal(format!("stripe resume: {e}")))?;
        }

        device_subscriptions::update_status(&self.db, sub_id, &sub.status, Some(false), None, None)
            .await?;

        let row = device_subscriptions::get_by_id(&self.db, sub_id)
            .await?
            .ok_or_else(|| Status::internal("sub not found after update"))?;

        Ok(Response::new(ResumeDeviceSubscriptionResponse {
            subscription: Some(to_device_sub_info(row)),
        }))
    }

    async fn list_invoices_v2(
        &self,
        request: Request<ListInvoicesV2Request>,
    ) -> Result<Response<ListInvoicesV2Response>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let limit = if req.limit == 0 {
            50
        } else {
            req.limit.min(200)
        };
        let offset: i64 = req.cursor.parse().unwrap_or(0);

        let (rows, has_more) = invoices_v2::list_by_user(&self.db, user_id, limit, offset).await?;
        let next_cursor = if has_more {
            (offset + limit as i64).to_string()
        } else {
            String::new()
        };

        let mut invoices = Vec::with_capacity(rows.len());
        for row in rows {
            let items = invoices_v2::get_items(&self.db, row.id).await?;
            invoices.push(to_invoice_v2_info(row, items));
        }

        Ok(Response::new(ListInvoicesV2Response {
            invoices,
            next_cursor,
            has_more,
        }))
    }

    async fn get_invoice_v2(
        &self,
        request: Request<GetInvoiceV2Request>,
    ) -> Result<Response<GetInvoiceV2Response>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let invoice_id: Uuid = req
            .invoice_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad invoice_id"))?;

        let row = invoices_v2::get_by_id(&self.db, user_id, invoice_id)
            .await?
            .ok_or_else(|| Status::not_found("invoice not found"))?;
        let items = invoices_v2::get_items(&self.db, row.id).await?;

        Ok(Response::new(GetInvoiceV2Response {
            invoice: Some(to_invoice_v2_info(row, items)),
        }))
    }

    async fn get_invoice_html(
        &self,
        request: Request<GetInvoiceHtmlRequest>,
    ) -> Result<Response<GetInvoiceHtmlResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let invoice_id: Uuid = req
            .invoice_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad invoice_id"))?;

        let row = invoices_v2::get_by_id(&self.db, user_id, invoice_id)
            .await?
            .ok_or_else(|| Status::not_found("invoice not found"))?;
        let items = invoices_v2::get_items(&self.db, row.id).await?;

        let template_items: Vec<(String, u32, String, String)> = items
            .iter()
            .map(|i| {
                (
                    i.description.clone(),
                    i.quantity as u32,
                    format!("${:.2}", i.unit_price_cents as f64 / 100.0),
                    format!("${:.2}", i.total_price_cents as f64 / 100.0),
                )
            })
            .collect();

        let tax_label = format!("Tax ({}%)", row.tax_rate);
        let html = invoice_template::render_invoice_html(
            &row.display_ref,
            &row.invoice_date.format("%b %d, %Y").to_string(),
            &row.due_date
                .map(|d| d.format("%b %d, %Y").to_string())
                .unwrap_or_else(|| "—".to_string()),
            "", // customer name — not stored on invoice, would need user lookup
            "", // account number
            "", // email
            &template_items,
            &format!("${:.2}", row.subtotal_cents as f64 / 100.0),
            &tax_label,
            &format!("${:.2}", row.tax_cents as f64 / 100.0),
            &format!("${:.2}", row.total_cents as f64 / 100.0),
            &format!(
                "{} ending {}",
                row.payment_method_brand.as_deref().unwrap_or("Card"),
                row.payment_method_last4.as_deref().unwrap_or("****")
            ),
            &row.status,
        );

        Ok(Response::new(GetInvoiceHtmlResponse { html }))
    }

    async fn retry_invoice_payment(
        &self,
        request: Request<RetryInvoicePaymentRequest>,
    ) -> Result<Response<RetryInvoicePaymentResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;
        let invoice_id: Uuid = req
            .invoice_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad invoice_id"))?;

        let inv = invoices_v2::get_by_id(&self.db, user_id, invoice_id)
            .await?
            .ok_or_else(|| Status::not_found("invoice not found"))?;

        if inv.status != "open" && inv.status != "failed" {
            return Err(Status::failed_precondition(format!(
                "cannot retry invoice with status: {}",
                inv.status
            )));
        }

        // Retry via Stripe — pay the open invoice
        if let (Some(stripe), Some(ref stripe_inv_id)) = (&self.stripe, &inv.stripe_invoice_id) {
            match stripe.pay_invoice(stripe_inv_id).await {
                Ok(status) => {
                    if status == "paid" {
                        invoices_v2::mark_paid(&self.db, invoice_id).await?;
                    }
                    Ok(Response::new(RetryInvoicePaymentResponse {
                        success: status == "paid",
                        status,
                    }))
                }
                Err(e) => {
                    tracing::warn!(error = %e, invoice_id = %invoice_id, "stripe invoice pay retry failed");
                    Ok(Response::new(RetryInvoicePaymentResponse {
                        success: false,
                        status: format!("failed: {e}"),
                    }))
                }
            }
        } else {
            // No Stripe — just mark as paid locally for testing
            invoices_v2::mark_paid(&self.db, invoice_id).await?;
            Ok(Response::new(RetryInvoicePaymentResponse {
                success: true,
                status: "paid".to_string(),
            }))
        }
    }

    async fn get_billing_summary(
        &self,
        request: Request<GetBillingSummaryRequest>,
    ) -> Result<Response<GetBillingSummaryResponse>, Status> {
        let req = request.into_inner();
        let user_id: Uuid = req
            .user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad user_id"))?;

        let subs = device_subscriptions::list_by_user(&self.db, user_id).await?;
        let default_pm = payment_methods::get_default(&self.db, user_id).await?;

        let active = subs
            .iter()
            .filter(|s| s.status == "active" || s.status == "trialing")
            .count() as i32;
        let past_due = subs.iter().filter(|s| s.status == "past_due").count() as i32;

        let devices: Vec<DeviceBillingStatus> = subs
            .iter()
            .map(|s| DeviceBillingStatus {
                device_id: s.device_id.to_string(),
                device_name: String::new(), // would need device lookup
                subscription_status: s.status.clone(),
                plan_name: s.plan_name.clone(),
                price_cents: s.price_cents,
                billing_interval: s.billing_interval.clone(),
                next_billing_date: s.current_period_end.map(|d| d.timestamp()).unwrap_or(0),
            })
            .collect();

        Ok(Response::new(GetBillingSummaryResponse {
            total_devices: subs.len() as i32,
            active_subscriptions: active,
            past_due_subscriptions: past_due,
            default_payment_brand: default_pm
                .as_ref()
                .and_then(|p| p.brand.clone())
                .unwrap_or_default(),
            default_payment_last4: default_pm
                .as_ref()
                .and_then(|p| p.last4.clone())
                .unwrap_or_default(),
            devices,
        }))
    }

    async fn create_refund(
        &self,
        request: Request<CreateRefundRequest>,
    ) -> Result<Response<CreateRefundResponse>, Status> {
        let req = request.into_inner();
        let admin_id: Uuid = req
            .admin_user_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad admin_id"))?;
        let invoice_id: Uuid = req
            .invoice_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad invoice_id"))?;

        // Load invoice (admin can see any user's invoice)
        let inv = invoices_v2::get_by_id_admin(&self.db, invoice_id)
            .await?
            .ok_or_else(|| Status::not_found("invoice not found"))?;

        // Validation 1: only refund paid/partially_refunded
        if inv.status != "paid" && inv.status != "partially_refunded" {
            return Err(Status::failed_precondition(format!(
                "cannot refund invoice with status: {}",
                inv.status
            )));
        }

        // Validation 2: prevent over-refunding
        let already_refunded = invoices_v2::total_refunded(&self.db, invoice_id).await?;
        if already_refunded + req.amount_cents > inv.total_cents {
            return Err(Status::failed_precondition(format!(
                "refund would exceed invoice total: {} + {} > {}",
                already_refunded, req.amount_cents, inv.total_cents
            )));
        }

        // Call Stripe refund API if configured
        let (stripe_refund_id, refund_status) = if let Some(stripe) = &self.stripe {
            // Find the Stripe invoice to get the payment_intent
            if let Some(ref stripe_inv_id) = inv.stripe_invoice_id {
                match stripe.create_refund(stripe_inv_id, req.amount_cents).await {
                    Ok(refund) => (Some(refund.id), refund.status),
                    Err(e) => {
                        tracing::error!(error = %e, invoice_id = %invoice_id, "stripe refund failed");
                        return Err(Status::internal(format!("stripe refund failed: {e}")));
                    }
                }
            } else {
                // No Stripe invoice ID — process refund locally only
                tracing::warn!(invoice_id = %invoice_id, "no stripe_invoice_id — refund processed locally");
                (None, "succeeded".to_string())
            }
        } else {
            (None, "succeeded".to_string())
        };

        let refund_row = refunds::insert(
            &self.db,
            invoice_id,
            inv.user_id,
            admin_id,
            stripe_refund_id.as_deref(),
            None, // stripe_payment_intent_id
            req.amount_cents,
            &inv.currency,
            &req.reason,
            &refund_status,
        )
        .await?;

        // Update invoice status
        let new_total_refunded = already_refunded + req.amount_cents;
        let new_status = if new_total_refunded >= inv.total_cents {
            "refunded"
        } else {
            "partially_refunded"
        };
        invoices_v2::update_status(&self.db, invoice_id, new_status).await?;

        Ok(Response::new(CreateRefundResponse {
            refund: Some(RefundInfo {
                id: refund_row.id.to_string(),
                display_ref: refund_row.display_ref,
                invoice_id: refund_row.invoice_id.to_string(),
                user_id: refund_row.user_id.to_string(),
                admin_user_id: refund_row.admin_user_id.to_string(),
                amount_cents: refund_row.amount_cents,
                currency: refund_row.currency,
                reason: refund_row.reason,
                status: refund_row.status,
                created_at: refund_row.created_at.timestamp(),
            }),
        }))
    }

    async fn list_refunds_by_invoice(
        &self,
        request: Request<ListRefundsByInvoiceRequest>,
    ) -> Result<Response<ListRefundsByInvoiceResponse>, Status> {
        let req = request.into_inner();
        let invoice_id: Uuid = req
            .invoice_id
            .parse()
            .map_err(|_| Status::invalid_argument("bad invoice_id"))?;

        let (rows, total) = refunds::list_by_invoice(&self.db, invoice_id).await?;

        Ok(Response::new(ListRefundsByInvoiceResponse {
            refunds: rows
                .into_iter()
                .map(|r| RefundInfo {
                    id: r.id.to_string(),
                    display_ref: r.display_ref,
                    invoice_id: r.invoice_id.to_string(),
                    user_id: r.user_id.to_string(),
                    admin_user_id: r.admin_user_id.to_string(),
                    amount_cents: r.amount_cents,
                    currency: r.currency,
                    reason: r.reason,
                    status: r.status,
                    created_at: r.created_at.timestamp(),
                })
                .collect(),
            total_refunded_cents: total,
        }))
    }
}

#[tokio::main]
async fn main() {
    init_tracing("billing-service");

    let grpc_addr = env::var("BILLING_GRPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50059".to_string())
        .parse::<SocketAddr>()
        .expect("invalid BILLING_GRPC_BIND_ADDR");

    // Database pool for v2 device-first billing
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://wildon:wildon@127.0.0.1:5433/wildon".to_string()
    });
    let db = PgPool::connect(&database_url)
        .await
        .expect("failed to connect billing database");

    let run_runtime_migrations = env::var("BILLING_RUN_MIGRATIONS_ON_STARTUP")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    if run_runtime_migrations {
        tracing::info!("running billing migrations");
        let migrations_path = if std::path::Path::new("./migrations").exists() {
            std::path::PathBuf::from("./migrations")
        } else {
            std::path::PathBuf::from("services/billing-service/migrations")
        };
        let migrator = sqlx::migrate::Migrator::new(migrations_path)
            .await
            .expect("failed to load billing migrations");
        migrator.run(&db).await.expect("billing migrations failed");
    } else {
        tracing::info!("skipping billing runtime migrations");
    }

    let stripe = StripeClient::from_env();
    if stripe.is_some() {
        tracing::info!("stripe client configured");
    } else {
        tracing::warn!("STRIPE_SECRET_KEY not set — billing will run without Stripe integration");
    }

    let grpc = BillingGrpc {
        state: AppState::new(),
        internal_auth: InternalAuthPolicy::from_env("billing-service"),
        db,
        stripe,
    };

    tracing::info!(address = %grpc_addr, "billing grpc listening");
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BillingServiceServer<BillingGrpc>>()
        .await;
    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = load_server_tls_config().expect("invalid INTERNAL_TLS server config") {
        builder = builder
            .tls_config(tls)
            .expect("failed to apply billing grpc tls config");
    }
    builder
        .add_service(health_service)
        .add_service(BillingServiceServer::new(grpc))
        .serve(grpc_addr)
        .await
        .expect("billing grpc server failed");
}

fn subscription_request_hash(
    user_id: &str,
    plan: &str,
    status: &str,
    current_period_end: i64,
) -> String {
    let canonical = format!("{user_id}|{plan}|{status}|{current_period_end}");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn to_proto_transaction(record: &TransactionRecord) -> BillingTransaction {
    BillingTransaction {
        transaction_id: record.transaction_id.clone(),
        user_id: record.user_id.clone(),
        invoice_id: record.invoice_id.clone(),
        status: record.status.clone(),
        amount_cents: record.amount_cents,
        refunded_amount_cents: record.refunded_amount_cents,
        currency: record.currency.clone(),
        provider: record.provider.clone(),
        external_txn_id: record.external_txn_id.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn to_proto_invoice(record: &InvoiceRecord) -> BillingInvoice {
    BillingInvoice {
        invoice_id: record.invoice_id.clone(),
        user_id: record.user_id.clone(),
        status: record.status.clone(),
        amount_cents: record.amount_cents,
        refunded_amount_cents: record.refunded_amount_cents,
        currency: record.currency.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn to_proto_ledger_entry(record: &LedgerEntryRecord) -> BillingLedgerEntry {
    BillingLedgerEntry {
        ledger_id: record.ledger_id.clone(),
        user_id: record.user_id.clone(),
        transaction_id: record.transaction_id.clone(),
        invoice_id: record.invoice_id.clone(),
        entry_type: record.entry_type.clone(),
        amount_cents: record.amount_cents,
        currency: record.currency.clone(),
        note: record.note.clone(),
        created_at: record.created_at,
    }
}

fn to_proto_plan(record: &subscriptions::PlanRecord) -> BillingPlan {
    BillingPlan {
        plan_id: record.plan_id.clone(),
        plan_code: record.plan_code.clone(),
        name: record.name.clone(),
        description: record.description.clone(),
        priority: record.priority,
        interval: record.interval.clone(),
        price_cents: record.price_cents,
        currency: record.currency.clone(),
        device_limit: record.device_limit,
        storage_limit_bytes: record.storage_limit_bytes,
        retention_days: record.retention_days,
        status: record.status.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn to_proto_subscription(record: &subscriptions::ManagedSubscriptionRecord) -> BillingSubscription {
    BillingSubscription {
        subscription_id: record.subscription_id.clone(),
        subscription_code: record.subscription_code.clone(),
        user_id: record.user_id.clone(),
        plan_id: record.plan_id.clone(),
        plan_code: record.plan_code.clone(),
        status: record.status.clone(),
        start_date: record.start_date,
        end_date: record.end_date,
        auto_renew: record.auto_renew,
        device_count: record.device_count,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn default_subscription_end_date(start_date: i64, interval: &str) -> i64 {
    match interval {
        "monthly" => start_date + Duration::days(30).num_seconds(),
        "yearly" => start_date + Duration::days(365).num_seconds(),
        "lifetime" => start_date + Duration::days(365 * 100).num_seconds(),
        _ => start_date + Duration::days(30).num_seconds(),
    }
}

async fn resolve_plan_for_request(
    state: &AppState,
    plan_id: &str,
    plan_code: &str,
) -> Result<subscriptions::PlanRecord, Status> {
    if !plan_id.trim().is_empty() {
        let plans_catalog = state.plans_catalog.lock().await;
        return plans_catalog
            .get(plan_id.trim())
            .cloned()
            .ok_or_else(|| Status::not_found("plan not found"));
    }

    if plan_code.trim().is_empty() {
        return Err(Status::invalid_argument("plan_id or plan_code is required"));
    }

    let normalized_code = plan_code.trim().to_ascii_lowercase();
    let plan_id = {
        let index = state.plan_code_index.lock().await;
        index.get(normalized_code.as_str()).cloned()
    }
    .ok_or_else(|| Status::not_found("plan not found"))?;

    let plans_catalog = state.plans_catalog.lock().await;
    plans_catalog
        .get(plan_id.as_str())
        .cloned()
        .ok_or_else(|| Status::not_found("plan not found"))
}

fn normalize_limit(limit: u32) -> usize {
    if limit == 0 {
        50
    } else {
        limit.min(200) as usize
    }
}

fn parse_offset_cursor(cursor: &str) -> Result<usize, Status> {
    let trimmed = cursor.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| Status::invalid_argument("cursor must be an unsigned integer offset"))
}

fn paginate_items<T>(items: Vec<T>, limit: usize, cursor: usize) -> (Vec<T>, String, bool) {
    let mut page = items
        .into_iter()
        .skip(cursor)
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = page.len() > limit;
    if has_more {
        page.truncate(limit);
    }
    let next_cursor = if has_more {
        cursor.saturating_add(limit).to_string()
    } else {
        String::new()
    };
    (page, next_cursor, has_more)
}

fn next_ledger_id() -> String {
    let suffix = Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("LED-{suffix}")
}

// =========================================================================
// v2 conversion helpers
// =========================================================================

fn to_plan_info(r: subscription_plans::SubscriptionPlanRow) -> SubscriptionPlanInfo {
    SubscriptionPlanInfo {
        id: r.id.to_string(),
        display_ref: r.display_ref,
        code: r.code,
        name: r.name,
        description: r.description.unwrap_or_default(),
        billing_interval: r.billing_interval,
        price_cents: r.price_cents,
        currency: r.currency,
        trial_days: r.trial_days,
        is_active: r.is_active,
        created_at: r.created_at.timestamp(),
    }
}

fn to_device_sub_info(r: device_subscriptions::DeviceSubscriptionRow) -> DeviceSubscriptionInfo {
    DeviceSubscriptionInfo {
        id: r.id.to_string(),
        display_ref: r.display_ref,
        user_id: r.user_id.to_string(),
        device_id: r.device_id.to_string(),
        plan_id: r.plan_id.to_string(),
        plan_code: r.plan_code,
        plan_name: r.plan_name,
        status: r.status,
        price_cents: r.price_cents,
        currency: r.currency,
        billing_interval: r.billing_interval,
        current_period_start: r.current_period_start.map(|d| d.timestamp()).unwrap_or(0),
        current_period_end: r.current_period_end.map(|d| d.timestamp()).unwrap_or(0),
        cancel_at_period_end: r.cancel_at_period_end,
        canceled_at: r.canceled_at.map(|d| d.timestamp()).unwrap_or(0),
        grace_period_ends_at: r.grace_period_ends_at.map(|d| d.timestamp()).unwrap_or(0),
        created_at: r.created_at.timestamp(),
        updated_at: r.updated_at.timestamp(),
    }
}

fn to_invoice_v2_info(
    r: invoices_v2::InvoiceV2Row,
    items: Vec<invoices_v2::InvoiceItemRow>,
) -> InvoiceV2Info {
    InvoiceV2Info {
        id: r.id.to_string(),
        display_ref: r.display_ref,
        user_id: r.user_id.to_string(),
        device_id: r.device_id.map(|d| d.to_string()).unwrap_or_default(),
        subscription_id: r.subscription_id.map(|d| d.to_string()).unwrap_or_default(),
        status: r.status,
        currency: r.currency,
        subtotal_cents: r.subtotal_cents,
        tax_cents: r.tax_cents,
        tax_rate: r.tax_rate.to_string(),
        tax_region: r.tax_region,
        total_cents: r.total_cents,
        payment_method_brand: r.payment_method_brand.unwrap_or_default(),
        payment_method_last4: r.payment_method_last4.unwrap_or_default(),
        invoice_date: r.invoice_date.timestamp(),
        due_date: r.due_date.map(|d| d.timestamp()).unwrap_or(0),
        paid_at: r.paid_at.map(|d| d.timestamp()).unwrap_or(0),
        created_at: r.created_at.timestamp(),
        items: items
            .into_iter()
            .map(|i| InvoiceItemInfo {
                id: i.id.to_string(),
                description: i.description,
                quantity: i.quantity,
                unit_price_cents: i.unit_price_cents,
                total_price_cents: i.total_price_cents,
            })
            .collect(),
    }
}
