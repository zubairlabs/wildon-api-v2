ALTER TABLE auth.sessions
ADD COLUMN IF NOT EXISTS remember_me BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_created_at
  ON auth.sessions (user_id, created_at DESC);
