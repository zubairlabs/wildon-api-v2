-- Seed deterministic profile rows and roles for shared dashboard test accounts.
-- Must run AFTER auth-service migration 0009 creates the auth.users rows.

WITH seed_accounts(email, role, full_name, username, account_number) AS (
    VALUES
        (
            'support@wildon.com.au',
            'support',
            'Wildon Support',
            'support',
            'G1-SUPP001'
        ),
        (
            'my@wildon.com.au',
            'user',
            'Wildon My',
            'myuser',
            'G1-MY001'
        )
),
resolved_users AS (
    SELECT
        users.id AS user_id,
        accounts.email,
        accounts.role,
        accounts.full_name,
        accounts.username,
        accounts.account_number
    FROM seed_accounts AS accounts
    INNER JOIN auth.users AS users
        ON users.email = accounts.email
)
INSERT INTO users_app.users (
    user_id,
    email,
    full_name,
    username,
    status,
    perm_rev,
    account_number,
    timezone,
    created_at,
    updated_at,
    settings_updated_at
)
SELECT
    user_id,
    email,
    full_name,
    username,
    'active',
    1,
    account_number,
    'UTC',
    NOW(),
    NOW(),
    NOW()
FROM resolved_users
ON CONFLICT (user_id) DO UPDATE
SET
    email = EXCLUDED.email,
    full_name = COALESCE(users_app.users.full_name, EXCLUDED.full_name),
    username = COALESCE(users_app.users.username, EXCLUDED.username),
    status = 'active',
    account_number = COALESCE(users_app.users.account_number, EXCLUDED.account_number),
    updated_at = NOW();

WITH seed_accounts(email, role) AS (
    VALUES
        ('support@wildon.com.au', 'support'),
        ('my@wildon.com.au', 'user')
),
resolved_users AS (
    SELECT
        users.id AS user_id,
        accounts.role
    FROM seed_accounts AS accounts
    INNER JOIN auth.users AS users
        ON users.email = accounts.email
)
DELETE FROM users_app.role_assignments AS assignments
USING resolved_users
WHERE assignments.user_id = resolved_users.user_id
  AND assignments.role <> resolved_users.role;

WITH seed_accounts(email, role) AS (
    VALUES
        ('support@wildon.com.au', 'support'),
        ('my@wildon.com.au', 'user')
),
resolved_users AS (
    SELECT
        users.id AS user_id,
        accounts.role
    FROM seed_accounts AS accounts
    INNER JOIN auth.users AS users
        ON users.email = accounts.email
)
INSERT INTO users_app.role_assignments (
    user_id,
    role
)
SELECT
    user_id,
    role
FROM resolved_users
ON CONFLICT (user_id, role) DO NOTHING;

WITH seed_accounts(email) AS (
    VALUES
        ('support@wildon.com.au'),
        ('my@wildon.com.au')
),
resolved_users AS (
    SELECT users.id AS user_id
    FROM seed_accounts AS accounts
    INNER JOIN auth.users AS users
        ON users.email = accounts.email
)
INSERT INTO users_app.user_notification_settings (user_id)
SELECT user_id
FROM resolved_users
ON CONFLICT (user_id) DO NOTHING;
