DROP INDEX IF EXISTS api_clients_app.api_client_events_client_created_at_idx;
DROP TABLE IF EXISTS api_clients_app.api_client_events;

DROP TRIGGER IF EXISTS trg_guard_policy_registry_delete ON api_clients_app.rate_limit_policy_registry;
DROP TRIGGER IF EXISTS trg_guard_policy_registry_update ON api_clients_app.rate_limit_policy_registry;
DROP FUNCTION IF EXISTS api_clients_app.guard_policy_registry_delete();
DROP FUNCTION IF EXISTS api_clients_app.guard_policy_registry_update();

DROP TRIGGER IF EXISTS trg_prevent_rate_policy_mutation ON api_clients_app.rate_limit_policies;
DROP FUNCTION IF EXISTS api_clients_app.prevent_rate_policy_mutation();

DROP INDEX IF EXISTS api_clients_app.rate_limit_policies_scope_idx;
DROP TABLE IF EXISTS api_clients_app.rate_limit_policies;
DROP TABLE IF EXISTS api_clients_app.rate_limit_policy_registry;

DROP INDEX IF EXISTS api_clients_app.api_client_secrets_status_idx;
DROP INDEX IF EXISTS api_clients_app.api_client_secrets_one_active_idx;
DROP TABLE IF EXISTS api_clients_app.api_client_secrets;

DROP INDEX IF EXISTS api_clients_app.api_clients_last_used_at_desc_idx;
DROP INDEX IF EXISTS api_clients_app.api_clients_platform_status_idx;
DROP INDEX IF EXISTS api_clients_app.api_clients_env_surface_status_idx;
DROP INDEX IF EXISTS api_clients_app.api_clients_client_ref_uq;
DROP INDEX IF EXISTS api_clients_app.api_clients_client_number_uq;
DROP INDEX IF EXISTS api_clients_app.api_clients_id_uq;

ALTER TABLE api_clients_app.api_clients
  DROP CONSTRAINT IF EXISTS api_clients_client_id_lower_chk;
ALTER TABLE api_clients_app.api_clients
  DROP CONSTRAINT IF EXISTS api_clients_client_id_format_chk;

DROP TRIGGER IF EXISTS trg_prevent_revoked_reactivation ON api_clients_app.api_clients;
DROP FUNCTION IF EXISTS api_clients_app.prevent_revoked_reactivation();

UPDATE api_clients_app.api_clients
SET status = 'disabled'
WHERE status = 'suspended';

UPDATE api_clients_app.api_clients
SET status = 'deprecated'
WHERE status = 'revoked';

DROP TRIGGER IF EXISTS trg_apply_client_defaults ON api_clients_app.api_clients;
DROP FUNCTION IF EXISTS api_clients_app.apply_client_defaults();
DROP FUNCTION IF EXISTS api_clients_app.generate_uuid();

ALTER TABLE api_clients_app.api_clients
  DROP COLUMN IF EXISTS notes,
  DROP COLUMN IF EXISTS last_used_at,
  DROP COLUMN IF EXISTS updated_by,
  DROP COLUMN IF EXISTS created_by,
  DROP COLUMN IF EXISTS client_safety_policy,
  DROP COLUMN IF EXISTS user_rate_policy,
  DROP COLUMN IF EXISTS max_app_version,
  DROP COLUMN IF EXISTS is_version_enforced,
  DROP COLUMN IF EXISTS require_mtls,
  DROP COLUMN IF EXISTS ip_allowlist,
  DROP COLUMN IF EXISTS allowed_origins,
  DROP COLUMN IF EXISTS allowed_audiences,
  DROP COLUMN IF EXISTS surface,
  DROP COLUMN IF EXISTS platform,
  DROP COLUMN IF EXISTS description,
  DROP COLUMN IF EXISTS display_name,
  DROP COLUMN IF EXISTS client_ref,
  DROP COLUMN IF EXISTS client_number,
  DROP COLUMN IF EXISTS id;

DROP SEQUENCE IF EXISTS api_clients_app.client_number_seq;
