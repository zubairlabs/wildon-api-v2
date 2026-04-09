-- Seed deterministic dashboard login accounts for shared testing.
-- These should be removed or rotated before production launch.

WITH seed_accounts(email, password_hash, fallback_user_id) AS (
    VALUES
        -- Support dashboard: support@wildon.com.au / G1Control!2026
        (
            'support@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$qgJB0v2kV+nvuwFxYSJyBA$w3eOsdYcsP8I5NsxP1AiGpu5aSIH5C1FiYpHC/+RFes',
            '18a1f9e5-5fa8-4c1c-8e11-a0df15afce01'::UUID
        ),
        -- My dashboard: my@wildon.com.au / G1Control!2026
        (
            'my@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$qgJB0v2kV+nvuwFxYSJyBA$w3eOsdYcsP8I5NsxP1AiGpu5aSIH5C1FiYpHC/+RFes',
            '4b27112c-bb43-4f18-9a6c-55a31d405f02'::UUID
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
