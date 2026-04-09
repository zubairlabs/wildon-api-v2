CREATE SCHEMA IF NOT EXISTS billing_app;

CREATE TABLE IF NOT EXISTS billing_app.plans (
  plan_key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS billing_app.plan_entitlements (
  plan_key TEXT NOT NULL,
  feature_key TEXT NOT NULL,
  PRIMARY KEY (plan_key, feature_key)
);

CREATE TABLE IF NOT EXISTS billing_app.subscriptions (
  user_id UUID PRIMARY KEY,
  plan_key TEXT NOT NULL,
  status TEXT NOT NULL,
  current_period_end TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS billing_app.usage_records (
  user_id UUID NOT NULL,
  metric_key TEXT NOT NULL,
  quantity BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, metric_key)
);

CREATE TABLE IF NOT EXISTS billing_app.invoices (
  invoice_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  amount_cents BIGINT NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS billing_app.transactions (
  transaction_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  external_provider TEXT NOT NULL,
  external_txn_id TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  currency TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS billing_app.stripe_webhook_events (
  event_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  processed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS billing_app.billing_idempotency_keys (
  idempotency_key TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  operation TEXT NOT NULL,
  status TEXT NOT NULL,
  response_ref TEXT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
