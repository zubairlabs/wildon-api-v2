CREATE SCHEMA IF NOT EXISTS control_app;

CREATE TABLE IF NOT EXISTS control_app.service_bootstrap (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS control_app.admin_users (
  user_id TEXT PRIMARY KEY,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS control_app.user_roles (
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS control_app.feature_flags (
  key TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL,
  updated_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
