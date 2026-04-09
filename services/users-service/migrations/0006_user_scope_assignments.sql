CREATE TABLE IF NOT EXISTS users_app.user_scope_assignments (
  user_id UUID NOT NULL REFERENCES users_app.users(user_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, scope)
);

CREATE INDEX IF NOT EXISTS idx_users_scope_assignments_user_id
  ON users_app.user_scope_assignments (user_id, created_at DESC);
