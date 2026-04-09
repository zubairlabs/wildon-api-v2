ALTER TABLE logs_app.audit_events
  ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS service_name TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS actor_role TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS auth_mechanism TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS resource_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS resource_owner_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS member_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS trace_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ip_address TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS path TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS status_code INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS access_purpose TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS data_sensitivity_level TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS before_json JSONB NOT NULL DEFAULT 'null'::jsonb,
  ADD COLUMN IF NOT EXISTS after_json JSONB NOT NULL DEFAULT 'null'::jsonb,
  ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS event_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS previous_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS taxonomy_version TEXT NOT NULL DEFAULT 'v1';

UPDATE logs_app.audit_events
SET occurred_at = COALESCE(occurred_at, created_at),
    service_name = CASE WHEN service_name = '' THEN consumer ELSE service_name END,
    environment = CASE WHEN environment = '' THEN 'legacy' ELSE environment END,
    actor_id = CASE WHEN actor_id = '' THEN user_id ELSE actor_id END,
    resource_id = CASE WHEN resource_id = '' THEN event_id ELSE resource_id END,
    metadata_json = COALESCE(metadata_json, '{}'::jsonb),
    event_json = CASE
      WHEN event_json = '{}'::jsonb THEN jsonb_build_object(
        'event_id', event_id,
        'timestamp', EXTRACT(EPOCH FROM COALESCE(occurred_at, created_at))::BIGINT,
        'service_name', CASE WHEN service_name = '' THEN consumer ELSE service_name END,
        'environment', CASE WHEN environment = '' THEN 'legacy' ELSE environment END,
        'action', action,
        'resource_type', CASE WHEN resource_type = '' THEN 'legacy_event' ELSE resource_type END,
        'resource_id', CASE WHEN resource_id = '' THEN event_id ELSE resource_id END,
        'metadata_json', payload_json::text,
        'taxonomy_version', taxonomy_version
      )
      ELSE event_json
    END;

CREATE INDEX IF NOT EXISTS idx_logs_audit_events_occurred_at
  ON logs_app.audit_events (occurred_at DESC, event_id DESC, service_name DESC);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_actor_id
  ON logs_app.audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_member_id
  ON logs_app.audit_events (member_id);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_resource_id
  ON logs_app.audit_events (resource_id);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_resource_owner_id
  ON logs_app.audit_events (resource_owner_id);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_service_name
  ON logs_app.audit_events (service_name);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_result
  ON logs_app.audit_events (result);
CREATE INDEX IF NOT EXISTS idx_logs_audit_events_severity
  ON logs_app.audit_events (severity);
