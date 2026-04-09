-- Bootstrap deterministic login accounts for control/testing environments.
-- Passwords are documented in .env.example — rotate immediately in production.

WITH seed_accounts(email, password_hash, fallback_user_id) AS (
    VALUES
        -- Control panel (superadmin): control@wildon.com.au / G1Control!2026
        (
            'control@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$qgJB0v2kV+nvuwFxYSJyBA$w3eOsdYcsP8I5NsxP1AiGpu5aSIH5C1FiYpHC/+RFes',
            '7e73b60e-621d-4c74-9f6f-1b347f2f2e0a'::UUID
        ),
        -- Platform (partner): platform@wildon.com.au / G1Platform!2026
        (
            'platform@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$FdU6aZwaYpjHP57p3zytSg$F4yFIaKj6dC/usvJLIaRFln16smHTwBcMRclx94Tuo4',
            '2d3ab26b-43e8-4f9c-9d3b-fca2aef2c6f8'::UUID
        ),
        -- Public (test user): testuser@wildon.com.au / G1User!2026
        (
            'testuser@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$hZdll2tAY/HYtDUAckB5iA$wb7H9QwqTQyQXkpk07Zw6578qqS6oI/IeuHzpmvreAw',
            'e5baecb1-d439-4f3f-9a6d-34fa4075334f'::UUID
        ),
        -- Owner (superadmin): zubair@wildon.com.au / Planet.23
        (
            'zubair@wildon.com.au',
            '$argon2id$v=19$m=19456,t=2,p=1$LuUoRrnEvGE4wdZBbU3zNA$0um7/g+KcsD81ajVlOoyXVo8KLXah478qeHpGoGuVZM',
            'a1b2c3d4-e5f6-7890-abcd-111111111111'::UUID
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
