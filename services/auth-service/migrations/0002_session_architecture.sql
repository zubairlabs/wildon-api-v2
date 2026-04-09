CREATE TABLE IF NOT EXISTS auth.users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE,
  session_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth.sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  session_family_id UUID NOT NULL,
  aud TEXT NOT NULL CHECK (aud IN ('public', 'platform', 'control')),
  realm TEXT NOT NULL CHECK (realm IN ('public', 'platform', 'control')),
  client_id TEXT NULL,
  device_id UUID NULL,
  device_fingerprint_hash TEXT NULL,
  device_public_key TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  revoked_reason TEXT NULL,
  ip_address INET NULL,
  user_agent TEXT NULL,
  mfa_level SMALLINT NOT NULL DEFAULT 0,
  CONSTRAINT chk_auth_sessions_mfa_level CHECK (mfa_level >= 0)
);

ALTER TABLE auth.sessions
ADD COLUMN IF NOT EXISTS client_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_family_id ON auth.sessions (session_family_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth.sessions (user_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
  id UUID PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  replaced_by_token_id UUID NULL REFERENCES auth.refresh_tokens(id),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  revoked_reason TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_session_id ON auth.refresh_tokens (session_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_expiry ON auth.refresh_tokens (expires_at);

CREATE TABLE IF NOT EXISTS auth.security_events (
  id BIGSERIAL PRIMARY KEY,
  event_type TEXT NOT NULL,
  user_id UUID NULL,
  session_id UUID NULL,
  request_id TEXT NULL,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_security_events_created_at ON auth.security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_security_events_user_id ON auth.security_events (user_id, created_at DESC);
