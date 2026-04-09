CREATE TABLE IF NOT EXISTS control_app.audit_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'auditor',
  created_by UUID NOT NULL REFERENCES auth.users(id),
  expires_at TIMESTAMPTZ NOT NULL,
  allowed_ips JSONB,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT audit_accounts_role_check CHECK (role = 'auditor'),
  CONSTRAINT audit_accounts_allowed_ips_type_check CHECK (
    allowed_ips IS NULL OR jsonb_typeof(allowed_ips) = 'array'
  )
);

CREATE INDEX IF NOT EXISTS idx_control_audit_accounts_user_id
  ON control_app.audit_accounts (user_id);

CREATE INDEX IF NOT EXISTS idx_control_audit_accounts_active_expires
  ON control_app.audit_accounts (is_active, expires_at DESC);
