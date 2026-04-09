-- Create users-service records for seeded control identities.

WITH seed_accounts(email, role, account_number) AS (
    VALUES
        ('admin@wildon.com.au', 'admin', 'G1-ADMIN01'),
        ('superadmin@wildon.com.au', 'superadmin', 'G1-SUPER01'),
        ('manager@wildon.com.au', 'manager', 'G1-MANAGR01'),
        ('user@wildon.com.au', 'user', 'G1-USER000'),
        ('numlogic@gmail.com', 'user', 'G1-NUMLOG1')
),
resolved_users AS (
    SELECT
        users.id AS user_id,
        users.email,
        accounts.role,
        accounts.account_number
    FROM seed_accounts AS accounts
    INNER JOIN auth.users AS users
        ON users.email = accounts.email
)
INSERT INTO users_app.users (
    user_id,
    email,
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
    status = 'active',
    account_number = COALESCE(users_app.users.account_number, EXCLUDED.account_number),
    updated_at = NOW();

WITH seed_accounts(email, role) AS (
    VALUES
        ('admin@wildon.com.au', 'admin'),
        ('superadmin@wildon.com.au', 'superadmin'),
        ('manager@wildon.com.au', 'manager'),
        ('user@wildon.com.au', 'user'),
        ('numlogic@gmail.com', 'user')
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
WHERE assignments.user_id = resolved_users.user_id;

WITH seed_accounts(email, role) AS (
    VALUES
        ('admin@wildon.com.au', 'admin'),
        ('superadmin@wildon.com.au', 'superadmin'),
        ('manager@wildon.com.au', 'manager'),
        ('user@wildon.com.au', 'user'),
        ('numlogic@gmail.com', 'user')
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
        ('admin@wildon.com.au'),
        ('superadmin@wildon.com.au'),
        ('manager@wildon.com.au'),
        ('user@wildon.com.au'),
        ('numlogic@gmail.com')
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
