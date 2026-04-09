DROP INDEX IF EXISTS idx_auth_mfa_login_challenges_expires;
DROP INDEX IF EXISTS idx_auth_mfa_login_challenges_user_created;
DROP TABLE IF EXISTS auth.mfa_login_challenges;

DROP INDEX IF EXISTS uq_auth_mfa_factor_active_per_type;
DROP INDEX IF EXISTS idx_auth_mfa_factors_user_created;
DROP TABLE IF EXISTS auth.mfa_factors;
