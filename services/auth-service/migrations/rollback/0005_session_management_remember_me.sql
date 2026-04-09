DROP INDEX IF EXISTS auth.idx_auth_sessions_user_created_at;

ALTER TABLE auth.sessions
DROP COLUMN IF EXISTS remember_me;
