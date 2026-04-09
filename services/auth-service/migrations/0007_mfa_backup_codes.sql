CREATE TABLE IF NOT EXISTS auth.mfa_backup_codes (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  factor_id UUID NOT NULL REFERENCES auth.mfa_factors(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  code_suffix TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'used', 'revoked')),
  used_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_backup_codes_user_status
  ON auth.mfa_backup_codes (user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_backup_codes_factor_status
  ON auth.mfa_backup_codes (factor_id, status, created_at DESC);
