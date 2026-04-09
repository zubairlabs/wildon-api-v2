DROP INDEX IF EXISTS idx_auth_password_reset_otps_email_created;
DROP INDEX IF EXISTS idx_auth_password_reset_otps_user_created;
DROP TABLE IF EXISTS auth.password_reset_otps;

DROP INDEX IF EXISTS idx_auth_email_otps_email_created;
DROP INDEX IF EXISTS idx_auth_email_otps_user_created;
DROP TABLE IF EXISTS auth.email_verification_otps;

DROP TABLE IF EXISTS auth.credentials_password;

ALTER TABLE auth.users
DROP COLUMN IF EXISTS email_verified_at;

ALTER TABLE auth.users
DROP COLUMN IF EXISTS email_verified;
