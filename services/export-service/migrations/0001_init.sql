CREATE TABLE IF NOT EXISTS export_jobs (
  job_id UUID PRIMARY KEY,
  user_id TEXT NOT NULL,
  export_kind TEXT NOT NULL,
  format TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  artifact_key TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL UNIQUE,
  error_message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS export_kinds (
  export_kind TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_user_status ON export_jobs(user_id, status);
