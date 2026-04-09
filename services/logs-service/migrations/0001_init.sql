CREATE SCHEMA IF NOT EXISTS logs_app;

CREATE TABLE IF NOT EXISTS logs_app.service_bootstrap (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs_app.audit_events (
  event_id TEXT NOT NULL,
  consumer TEXT NOT NULL,
  user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (event_id, consumer)
);
