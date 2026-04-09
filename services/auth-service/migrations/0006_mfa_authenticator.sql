CREATE TABLE IF NOT EXISTS auth.mfa_factors (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK (factor_type IN ('authenticator', 'sms')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
  secret_base32 TEXT NULL,
  phone_e164 TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMPTZ NULL,
  disabled_at TIMESTAMPTZ NULL,
  last_used_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_factors_user_created
  ON auth.mfa_factors (user_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_mfa_factor_active_per_type
  ON auth.mfa_factors (user_id, factor_type)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS auth.mfa_login_challenges (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL CHECK (factor_type IN ('authenticator', 'sms')),
  challenge_hash TEXT NOT NULL UNIQUE,
  aud TEXT NOT NULL CHECK (aud IN ('public', 'platform', 'control')),
  realm TEXT NOT NULL CHECK (realm IN ('public', 'platform', 'control')),
  client_id TEXT NULL,
  device_id UUID NULL,
  device_fingerprint_hash TEXT NULL,
  user_agent TEXT NULL,
  ip_address INET NULL,
  remember_me BOOLEAN NOT NULL DEFAULT TRUE,
  attempts INT NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_login_challenges_user_created
  ON auth.mfa_login_challenges (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_login_challenges_expires
  ON auth.mfa_login_challenges (expires_at);
