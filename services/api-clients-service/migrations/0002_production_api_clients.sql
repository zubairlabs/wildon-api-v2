CREATE SEQUENCE IF NOT EXISTS api_clients_app.client_number_seq;

CREATE OR REPLACE FUNCTION api_clients_app.generate_uuid()
RETURNS UUID
LANGUAGE SQL
AS $$
  SELECT md5(random()::TEXT || clock_timestamp()::TEXT)::UUID;
$$;

ALTER TABLE api_clients_app.api_clients
  ADD COLUMN IF NOT EXISTS id UUID,
  ADD COLUMN IF NOT EXISTS client_number BIGINT,
  ADD COLUMN IF NOT EXISTS client_ref TEXT,
  ADD COLUMN IF NOT EXISTS display_name TEXT,
  ADD COLUMN IF NOT EXISTS description TEXT,
  ADD COLUMN IF NOT EXISTS platform TEXT,
  ADD COLUMN IF NOT EXISTS surface TEXT,
  ADD COLUMN IF NOT EXISTS allowed_audiences TEXT[],
  ADD COLUMN IF NOT EXISTS allowed_origins TEXT[],
  ADD COLUMN IF NOT EXISTS ip_allowlist TEXT[],
  ADD COLUMN IF NOT EXISTS require_mtls BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_version_enforced BOOLEAN,
  ADD COLUMN IF NOT EXISTS max_app_version TEXT,
  ADD COLUMN IF NOT EXISTS user_rate_policy TEXT,
  ADD COLUMN IF NOT EXISTS client_safety_policy TEXT,
  ADD COLUMN IF NOT EXISTS created_by UUID,
  ADD COLUMN IF NOT EXISTS updated_by UUID,
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS notes TEXT;

UPDATE api_clients_app.api_clients
SET id = api_clients_app.generate_uuid()
WHERE id IS NULL;

UPDATE api_clients_app.api_clients
SET client_number = nextval('api_clients_app.client_number_seq')
WHERE client_number IS NULL;

UPDATE api_clients_app.api_clients
SET client_ref = 'CLT-' || LPAD(client_number::TEXT, 6, '0')
WHERE client_ref IS NULL OR TRIM(client_ref) = '';

UPDATE api_clients_app.api_clients
SET display_name = client_id
WHERE display_name IS NULL OR TRIM(display_name) = '';

UPDATE api_clients_app.api_clients
SET platform = CASE
  WHEN client_id ILIKE '%android%' THEN 'android'
  WHEN client_id ILIKE '%ios%' THEN 'ios'
  WHEN client_id ILIKE '%worker%' THEN 'internal'
  WHEN client_id ILIKE '%control%' THEN 'internal'
  ELSE 'web'
END
WHERE platform IS NULL OR TRIM(platform) = '';

UPDATE api_clients_app.api_clients
SET surface = CASE
  WHEN rate_limit_profile = 'control_v1' THEN 'control'
  WHEN rate_limit_profile = 'platform_v1' THEN 'platform'
  ELSE 'public'
END
WHERE surface IS NULL OR TRIM(surface) = '';

UPDATE api_clients_app.api_clients
SET require_mtls = FALSE
WHERE require_mtls IS NULL;

UPDATE api_clients_app.api_clients
SET is_version_enforced = FALSE
WHERE is_version_enforced IS NULL;

UPDATE api_clients_app.api_clients
SET status = 'suspended'
WHERE status = 'disabled';

UPDATE api_clients_app.api_clients
SET status = 'revoked'
WHERE status = 'deprecated';

UPDATE api_clients_app.api_clients c
SET allowed_audiences = aud.audiences
FROM (
  SELECT client_id, ARRAY_AGG(audience ORDER BY audience) AS audiences
  FROM api_clients_app.api_client_audiences
  GROUP BY client_id
) aud
WHERE c.client_id = aud.client_id
  AND (c.allowed_audiences IS NULL OR CARDINALITY(c.allowed_audiences) = 0);

UPDATE api_clients_app.api_clients
SET allowed_audiences = ARRAY[surface]
WHERE allowed_audiences IS NULL OR CARDINALITY(allowed_audiences) = 0;

UPDATE api_clients_app.api_clients
SET allowed_origins = ARRAY[]::TEXT[]
WHERE allowed_origins IS NULL;

UPDATE api_clients_app.api_clients
SET ip_allowlist = ARRAY[]::TEXT[]
WHERE ip_allowlist IS NULL;

UPDATE api_clients_app.api_clients
SET user_rate_policy = CASE
  WHEN surface = 'control' THEN 'user_control_v1'
  WHEN surface = 'platform' THEN 'user_platform_v1'
  ELSE 'user_public_v1'
END
WHERE user_rate_policy IS NULL OR TRIM(user_rate_policy) = '';

UPDATE api_clients_app.api_clients
SET client_safety_policy = CASE
  WHEN surface = 'control' THEN 'client_control_medium'
  WHEN surface = 'platform' THEN 'client_platform_medium'
  WHEN environment = 'dev' THEN 'client_dev_low'
  ELSE 'client_mobile_prod_high'
END
WHERE client_safety_policy IS NULL OR TRIM(client_safety_policy) = '';

CREATE OR REPLACE FUNCTION api_clients_app.apply_client_defaults()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.id IS NULL THEN
    NEW.id := api_clients_app.generate_uuid();
  END IF;

  IF NEW.client_number IS NULL THEN
    NEW.client_number := nextval('api_clients_app.client_number_seq');
  END IF;

  IF NEW.client_ref IS NULL OR BTRIM(NEW.client_ref) = '' THEN
    NEW.client_ref := 'CLT-' || LPAD(NEW.client_number::TEXT, 6, '0');
  END IF;

  IF NEW.display_name IS NULL OR BTRIM(NEW.display_name) = '' THEN
    NEW.display_name := NEW.client_id;
  END IF;

  IF NEW.platform IS NULL OR BTRIM(NEW.platform) = '' THEN
    NEW.platform := 'web';
  END IF;

  IF NEW.surface IS NULL OR BTRIM(NEW.surface) = '' THEN
    NEW.surface := 'public';
  END IF;

  IF NEW.allowed_audiences IS NULL OR CARDINALITY(NEW.allowed_audiences) = 0 THEN
    NEW.allowed_audiences := ARRAY[NEW.surface];
  END IF;

  IF NEW.allowed_origins IS NULL THEN
    NEW.allowed_origins := ARRAY[]::TEXT[];
  END IF;

  IF NEW.ip_allowlist IS NULL THEN
    NEW.ip_allowlist := ARRAY[]::TEXT[];
  END IF;

  IF NEW.require_mtls IS NULL THEN
    NEW.require_mtls := FALSE;
  END IF;

  IF NEW.is_version_enforced IS NULL THEN
    NEW.is_version_enforced := FALSE;
  END IF;

  IF NEW.user_rate_policy IS NULL OR BTRIM(NEW.user_rate_policy) = '' THEN
    NEW.user_rate_policy := 'user_public_v1';
  END IF;

  IF NEW.client_safety_policy IS NULL OR BTRIM(NEW.client_safety_policy) = '' THEN
    NEW.client_safety_policy := 'client_mobile_prod_high';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_apply_client_defaults ON api_clients_app.api_clients;
CREATE TRIGGER trg_apply_client_defaults
BEFORE INSERT OR UPDATE ON api_clients_app.api_clients
FOR EACH ROW
EXECUTE FUNCTION api_clients_app.apply_client_defaults();

ALTER TABLE api_clients_app.api_clients
  ALTER COLUMN id SET NOT NULL,
  ALTER COLUMN client_number SET NOT NULL,
  ALTER COLUMN client_ref SET NOT NULL,
  ALTER COLUMN display_name SET NOT NULL,
  ALTER COLUMN platform SET NOT NULL,
  ALTER COLUMN surface SET NOT NULL,
  ALTER COLUMN require_mtls SET NOT NULL,
  ALTER COLUMN is_version_enforced SET NOT NULL,
  ALTER COLUMN allowed_audiences SET NOT NULL,
  ALTER COLUMN allowed_origins SET NOT NULL,
  ALTER COLUMN ip_allowlist SET NOT NULL,
  ALTER COLUMN user_rate_policy SET NOT NULL,
  ALTER COLUMN client_safety_policy SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS api_clients_id_uq
  ON api_clients_app.api_clients (id);
CREATE UNIQUE INDEX IF NOT EXISTS api_clients_client_number_uq
  ON api_clients_app.api_clients (client_number);
CREATE UNIQUE INDEX IF NOT EXISTS api_clients_client_ref_uq
  ON api_clients_app.api_clients (client_ref);
CREATE INDEX IF NOT EXISTS api_clients_env_surface_status_idx
  ON api_clients_app.api_clients (environment, surface, status);
CREATE INDEX IF NOT EXISTS api_clients_platform_status_idx
  ON api_clients_app.api_clients (platform, status);
CREATE INDEX IF NOT EXISTS api_clients_last_used_at_desc_idx
  ON api_clients_app.api_clients (last_used_at DESC);

CREATE TABLE IF NOT EXISTS api_clients_app.api_client_secrets (
  id UUID PRIMARY KEY DEFAULT api_clients_app.generate_uuid(),
  client_pk UUID NOT NULL REFERENCES api_clients_app.api_clients(id) ON DELETE CASCADE,
  secret_version INT NOT NULL,
  secret_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID NULL,
  rotated_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  revoked_by UUID NULL,
  UNIQUE (client_pk, secret_version)
);

CREATE UNIQUE INDEX IF NOT EXISTS api_client_secrets_one_active_idx
  ON api_clients_app.api_client_secrets (client_pk)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS api_client_secrets_status_idx
  ON api_clients_app.api_client_secrets (client_pk, status, created_at DESC);

CREATE TABLE IF NOT EXISTS api_clients_app.rate_limit_policies (
  policy_name TEXT NOT NULL,
  scope TEXT NOT NULL,
  route_group TEXT NOT NULL,
  requests_per_min INT NULL,
  requests_per_hour INT NULL,
  burst INT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  immutable BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (policy_name, scope, route_group)
);

CREATE TABLE IF NOT EXISTS api_clients_app.rate_limit_policy_registry (
  policy_name TEXT NOT NULL,
  scope TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  immutable BOOLEAN NOT NULL DEFAULT TRUE,
  is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (policy_name, scope)
);

INSERT INTO api_clients_app.rate_limit_policy_registry (policy_name, scope, immutable, is_deprecated)
SELECT DISTINCT p.policy_name, p.scope, TRUE, FALSE
FROM api_clients_app.rate_limit_policies p
ON CONFLICT (policy_name, scope) DO NOTHING;

ALTER TABLE api_clients_app.rate_limit_policies
  DROP CONSTRAINT IF EXISTS rate_limit_policies_policy_fk;

ALTER TABLE api_clients_app.rate_limit_policies
  ADD CONSTRAINT rate_limit_policies_policy_fk
    FOREIGN KEY (policy_name, scope)
    REFERENCES api_clients_app.rate_limit_policy_registry (policy_name, scope)
    ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS rate_limit_policies_scope_idx
  ON api_clients_app.rate_limit_policies (scope, policy_name, route_group);

CREATE TABLE IF NOT EXISTS api_clients_app.api_client_events (
  event_id UUID PRIMARY KEY DEFAULT api_clients_app.generate_uuid(),
  client_pk UUID NOT NULL REFERENCES api_clients_app.api_clients(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  actor_user_id UUID NULL,
  payload_json JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS api_client_events_client_created_at_idx
  ON api_clients_app.api_client_events (client_pk, created_at DESC);

CREATE OR REPLACE FUNCTION api_clients_app.prevent_rate_policy_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'rate_limit_policies rows are immutable; create a new policy version';
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_rate_policy_mutation ON api_clients_app.rate_limit_policies;
CREATE TRIGGER trg_prevent_rate_policy_mutation
BEFORE UPDATE OR DELETE ON api_clients_app.rate_limit_policies
FOR EACH ROW
EXECUTE FUNCTION api_clients_app.prevent_rate_policy_mutation();

CREATE OR REPLACE FUNCTION api_clients_app.guard_policy_registry_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.policy_name <> NEW.policy_name
     OR OLD.scope <> NEW.scope
     OR OLD.created_at <> NEW.created_at
     OR OLD.immutable <> NEW.immutable THEN
    RAISE EXCEPTION 'policy registry identity is immutable; create a new version';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_policy_registry_update ON api_clients_app.rate_limit_policy_registry;
CREATE TRIGGER trg_guard_policy_registry_update
BEFORE UPDATE ON api_clients_app.rate_limit_policy_registry
FOR EACH ROW
EXECUTE FUNCTION api_clients_app.guard_policy_registry_update();

CREATE OR REPLACE FUNCTION api_clients_app.guard_policy_registry_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.scope = 'user' THEN
    IF EXISTS (
      SELECT 1
      FROM api_clients_app.api_clients c
      WHERE c.user_rate_policy = OLD.policy_name
    ) THEN
      RAISE EXCEPTION 'cannot delete referenced user policy %', OLD.policy_name;
    END IF;
  ELSIF OLD.scope = 'client' THEN
    IF EXISTS (
      SELECT 1
      FROM api_clients_app.api_clients c
      WHERE c.client_safety_policy = OLD.policy_name
    ) THEN
      RAISE EXCEPTION 'cannot delete referenced client policy %', OLD.policy_name;
    END IF;
  END IF;

  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_policy_registry_delete ON api_clients_app.rate_limit_policy_registry;
CREATE TRIGGER trg_guard_policy_registry_delete
BEFORE DELETE ON api_clients_app.rate_limit_policy_registry
FOR EACH ROW
EXECUTE FUNCTION api_clients_app.guard_policy_registry_delete();

CREATE OR REPLACE FUNCTION api_clients_app.prevent_revoked_reactivation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'revoked clients are permanent and cannot be reactivated';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_revoked_reactivation ON api_clients_app.api_clients;
CREATE TRIGGER trg_prevent_revoked_reactivation
BEFORE UPDATE ON api_clients_app.api_clients
FOR EACH ROW
EXECUTE FUNCTION api_clients_app.prevent_revoked_reactivation();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'api_clients_client_id_format_chk'
  ) THEN
    ALTER TABLE api_clients_app.api_clients
      ADD CONSTRAINT api_clients_client_id_format_chk
      CHECK (client_id ~ '^[a-z0-9-]+$');
  END IF;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'api_clients_client_id_lower_chk'
  ) THEN
    ALTER TABLE api_clients_app.api_clients
      ADD CONSTRAINT api_clients_client_id_lower_chk
      CHECK (client_id = LOWER(client_id));
  END IF;
END;
$$;
