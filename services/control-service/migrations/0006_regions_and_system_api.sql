CREATE TABLE IF NOT EXISTS control_app.regions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    country TEXT NOT NULL,
    country_code TEXT NOT NULL,
    flag TEXT NOT NULL DEFAULT '',
    currency TEXT NOT NULL DEFAULT 'USD',
    currency_symbol TEXT NOT NULL DEFAULT '$',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    address TEXT NOT NULL DEFAULT '',
    api_base_url TEXT NOT NULL,
    public_key TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    secret_key_hint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ONLINE' CHECK (status IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'MAINTENANCE')),
    server JSONB NOT NULL DEFAULT '{}'::jsonb,
    total_users BIGINT NOT NULL DEFAULT 0,
    total_devices BIGINT NOT NULL DEFAULT 0,
    total_organizations BIGINT NOT NULL DEFAULT 0,
    is_default BOOLEAN NOT NULL DEFAULT false,
    last_rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_regions_default_true
    ON control_app.regions (is_default)
    WHERE is_default = true;

CREATE TABLE IF NOT EXISTS control_app.system_api_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    secret_key TEXT NOT NULL,
    secret_key_hint TEXT NOT NULL DEFAULT '',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    allowed_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS control_app.system_api_nonces (
    client_id UUID NOT NULL REFERENCES control_app.system_api_clients(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    request_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_system_api_nonces_expires_at
    ON control_app.system_api_nonces (expires_at);

CREATE TABLE IF NOT EXISTS control_app.system_api_idempotency (
    client_id UUID NOT NULL REFERENCES control_app.system_api_clients(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, endpoint, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_system_api_idempotency_expires_at
    ON control_app.system_api_idempotency (expires_at);
