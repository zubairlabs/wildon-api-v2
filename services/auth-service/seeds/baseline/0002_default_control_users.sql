-- WARNING:
-- These are deterministic local bootstrap credentials for control-surface access.
-- Rotate/remove before any production-like deployment.

WITH seed_accounts(email, password_hash, fallback_user_id) AS (
    VALUES
        (
            'admin@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$4t9iFO5Balbm4QTTNCur9g$b4ZsQmIS60lJK4Ta6Tu1hAo4joovczBhfBiSgQNE11M',
            '11111111-1111-4111-8111-111111111111'::UUID
        ),
        (
            'superadmin@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$d82zoGcapOv6/oifh8V2Tg$BEZw6ekQ+G+RmrprJ9NFEwepQB/EnBTiMTZCbRY/mfc',
            '22222222-2222-4222-8222-222222222222'::UUID
        ),
        (
            'manager@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$/zOWfN8Oo1fvIrvg7GEiYg$9UJq4CCRnBi23HJNIYcbKVlwmm+gj/RR3Ud1YylapZg',
            '91a99868-8d48-4b14-8ccf-6c80f8046f7d'::UUID
        ),
        (
            'user@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$iJPM1FoFaxRO9ypzxOQWJQ$Uc42pEnZEOIUzP1xtBjLkfy3nj+4rPCDenDC67SC//g',
            '33333333-3333-4333-8333-333333333333'::UUID
        ),
        (
            'numlogic@gmail.com',
            '$argon2id$v=19$m=19456,t=2,p=1$soBlQq3gMUNDCpn8OvNOiw$Y75uRiyw4rUITOxTvsbaspHi/vjeFFcudbOW42HONpA',
            'f7ce45f8-5e98-4194-9f7a-e00a5e67d354'::UUID
        )
),
upserted_users AS (
    INSERT INTO auth.users (
        id,
        email,
        email_verified,
        email_verified_at,
        created_at,
        updated_at
    )
    SELECT
        fallback_user_id,
        email,
        TRUE,
        NOW(),
        NOW(),
        NOW()
    FROM seed_accounts
    ON CONFLICT (email) DO UPDATE
    SET
        email_verified = TRUE,
        email_verified_at = COALESCE(auth.users.email_verified_at, NOW()),
        updated_at = NOW()
    RETURNING id, email
)
INSERT INTO auth.credentials_password (
    user_id,
    password_hash,
    password_updated_at,
    created_at
)
SELECT
    users.id,
    accounts.password_hash,
    NOW(),
    NOW()
FROM upserted_users AS users
INNER JOIN seed_accounts AS accounts
    ON accounts.email = users.email
ON CONFLICT (user_id) DO UPDATE
SET
    password_hash = EXCLUDED.password_hash,
    password_updated_at = NOW();
