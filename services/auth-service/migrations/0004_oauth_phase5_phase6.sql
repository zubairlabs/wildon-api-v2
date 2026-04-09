CREATE TABLE IF NOT EXISTS auth.oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
  client_secret_hash TEXT NULL,
  redirect_uris TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  allowed_grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'],
  require_pkce_s256 BOOLEAN NOT NULL DEFAULT TRUE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_clients_active
  ON auth.oauth_clients (active);

CREATE TABLE IF NOT EXISTS auth.oauth_authorization_codes (
  id UUID PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES auth.oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  nonce TEXT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  aud TEXT NOT NULL CHECK (aud IN ('public', 'platform', 'control')),
  realm TEXT NOT NULL CHECK (realm IN ('public', 'platform', 'control')),
  device_id UUID NULL,
  device_fingerprint_hash TEXT NULL,
  user_agent TEXT NULL,
  ip_address INET NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_codes_client_id
  ON auth.oauth_authorization_codes (client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_codes_user_id
  ON auth.oauth_authorization_codes (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_codes_expires_at
  ON auth.oauth_authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS auth.oauth_provider_accounts (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('google', 'apple')),
  provider_subject TEXT NOT NULL,
  email TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_subject)
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_provider_accounts_user
  ON auth.oauth_provider_accounts (user_id);

INSERT INTO auth.oauth_clients (
  client_id, client_type, client_secret_hash, redirect_uris, allowed_grant_types, require_pkce_s256, active
)
VALUES
  (
    'wildon-android',
    'public',
    NULL,
    ARRAY['wildon://oauth/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    TRUE,
    TRUE
  ),
  (
    'wildon-ios',
    'public',
    NULL,
    ARRAY['wildon-ios://oauth/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    TRUE,
    TRUE
  ),
  (
    'wildon-web-public',
    'public',
    NULL,
    ARRAY['https://app.wildon.local/oauth/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    TRUE,
    TRUE
  ),
  (
    'wildon-control-web',
    'confidential',
    NULL,
    ARRAY['https://control.wildon.local/oauth/callback'],
    ARRAY['authorization_code', 'refresh_token', 'client_credentials'],
    TRUE,
    TRUE
  )
ON CONFLICT (client_id) DO NOTHING;
