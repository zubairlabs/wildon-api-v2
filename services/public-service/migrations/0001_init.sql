CREATE SCHEMA IF NOT EXISTS public_app;

CREATE TABLE IF NOT EXISTS public_app.service_bootstrap (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
