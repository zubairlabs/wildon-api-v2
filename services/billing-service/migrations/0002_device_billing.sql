-- Device-first billing: payment methods, subscription plans, device subscriptions,
-- invoices v2, invoice items, payment attempts, refunds.

-- Payment methods (Stripe-backed)
CREATE TABLE IF NOT EXISTS billing_app.payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    stripe_customer_id TEXT NOT NULL,
    stripe_payment_method_id TEXT NOT NULL UNIQUE,
    brand TEXT,
    last4 TEXT,
    exp_month INTEGER,
    exp_year INTEGER,
    is_default BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'removed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_payment_methods_user
    ON billing_app.payment_methods(user_id) WHERE deleted_at IS NULL;

-- Subscription plans (seed two defaults)
CREATE TABLE IF NOT EXISTS billing_app.subscription_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT UNIQUE NOT NULL,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    billing_interval TEXT NOT NULL CHECK (billing_interval IN ('monthly', 'yearly')),
    price_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'cad',
    trial_days INTEGER NOT NULL DEFAULT 0,
    stripe_price_id TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO billing_app.subscription_plans
    (display_ref, code, name, description, billing_interval, price_cents, currency, trial_days)
VALUES
    ('PLAN-GOMONTH1', 'go-monthly', 'Wildon Monthly',
     'Device monitoring — billed monthly', 'monthly', 999, 'cad', 14),
    ('PLAN-GOYEAR01', 'go-yearly', 'Wildon Yearly',
     'Device monitoring — billed yearly (save 20%)', 'yearly', 9588, 'cad', 14)
ON CONFLICT (code) DO NOTHING;

-- Device subscriptions (exactly one active subscription per device)
CREATE TABLE IF NOT EXISTS billing_app.device_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    device_id UUID NOT NULL UNIQUE,
    plan_id UUID NOT NULL REFERENCES billing_app.subscription_plans(id),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    stripe_price_id TEXT,
    payment_method_id UUID REFERENCES billing_app.payment_methods(id),
    status TEXT NOT NULL DEFAULT 'incomplete'
        CHECK (status IN ('incomplete', 'trialing', 'active', 'past_due', 'canceled', 'unpaid')),
    billing_anchor_at TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    canceled_at TIMESTAMPTZ,
    grace_period_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_device_subs_user
    ON billing_app.device_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_device_subs_stripe
    ON billing_app.device_subscriptions(stripe_subscription_id);

-- Invoices v2 (device-aware)
CREATE TABLE IF NOT EXISTS billing_app.invoices_v2 (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    device_id UUID,
    subscription_id UUID REFERENCES billing_app.device_subscriptions(id),
    stripe_invoice_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN (
            'draft', 'open', 'paid', 'partially_refunded', 'refunded',
            'void', 'uncollectible', 'failed'
        )),
    currency TEXT NOT NULL DEFAULT 'cad',
    subtotal_cents INTEGER NOT NULL,
    tax_cents INTEGER NOT NULL DEFAULT 0,
    tax_rate NUMERIC(5,2) NOT NULL DEFAULT 13.00,
    tax_region TEXT NOT NULL DEFAULT 'ON-CA',
    total_cents INTEGER NOT NULL,
    payment_method_brand TEXT,
    payment_method_last4 TEXT,
    invoice_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    due_date TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    hosted_pdf_url TEXT,
    hosted_invoice_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invoices_v2_user
    ON billing_app.invoices_v2(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_v2_sub
    ON billing_app.invoices_v2(subscription_id);

-- Invoice line items
CREATE TABLE IF NOT EXISTS billing_app.invoice_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES billing_app.invoices_v2(id),
    description TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price_cents INTEGER NOT NULL,
    total_price_cents INTEGER NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice
    ON billing_app.invoice_items(invoice_id);

-- Payment attempts (retry tracking)
CREATE TABLE IF NOT EXISTS billing_app.payment_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID REFERENCES billing_app.invoices_v2(id),
    subscription_id UUID REFERENCES billing_app.device_subscriptions(id),
    user_id UUID NOT NULL,
    stripe_payment_intent_id TEXT,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'cad',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'succeeded', 'failed')),
    failure_code TEXT,
    failure_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_invoice
    ON billing_app.payment_attempts(invoice_id);

-- Refunds (admin-only, Stripe-backed)
CREATE TABLE IF NOT EXISTS billing_app.refunds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT UNIQUE NOT NULL,
    invoice_id UUID NOT NULL REFERENCES billing_app.invoices_v2(id),
    payment_attempt_id UUID REFERENCES billing_app.payment_attempts(id),
    user_id UUID NOT NULL,
    admin_user_id UUID NOT NULL,
    stripe_refund_id TEXT UNIQUE,
    stripe_payment_intent_id TEXT,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'cad',
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'succeeded', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_refunds_invoice
    ON billing_app.refunds(invoice_id);
CREATE INDEX IF NOT EXISTS idx_refunds_user
    ON billing_app.refunds(user_id);
