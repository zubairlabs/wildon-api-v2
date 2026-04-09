-- Seed user profiles and roles for default test accounts.
-- Must run AFTER auth-service migration 0008 creates the auth.users rows.

-- 1. Create users_app.users entries
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'users_app'
          AND table_name = 'users'
          AND column_name = 'account_number'
    ) THEN
        EXECUTE $sql$
            WITH seed_accounts(email, role, account_number) AS (
                VALUES
                    ('control@wildon.com.au', 'superadmin', 'G1-CTRL001'),
                    ('platform@wildon.com.au', 'partner', 'G1-PLAT001'),
                    ('testuser@wildon.com.au', 'user', 'G1-TEST001'),
                    ('zubair@wildon.com.au', 'superadmin', 'G1-ZUBA001')
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
                updated_at = NOW()
        $sql$;
    ELSE
        EXECUTE $sql$
            WITH seed_accounts(email, role) AS (
                VALUES
                    ('control@wildon.com.au', 'superadmin'),
                    ('platform@wildon.com.au', 'partner'),
                    ('testuser@wildon.com.au', 'user'),
                    ('zubair@wildon.com.au', 'superadmin')
            ),
            resolved_users AS (
                SELECT
                    users.id AS user_id,
                    users.email,
                    accounts.role
                FROM seed_accounts AS accounts
                INNER JOIN auth.users AS users
                    ON users.email = accounts.email
            )
            INSERT INTO users_app.users (
                user_id,
                email,
                status,
                perm_rev,
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
                'UTC',
                NOW(),
                NOW(),
                NOW()
            FROM resolved_users
            ON CONFLICT (user_id) DO UPDATE
            SET
                email = EXCLUDED.email,
                status = 'active',
                updated_at = NOW()
        $sql$;
    END IF;
END $$;

-- 2. Clean stale role assignments
WITH seed_accounts(email, role) AS (
    VALUES
        ('control@wildon.com.au', 'superadmin'),
        ('platform@wildon.com.au', 'partner'),
        ('testuser@wildon.com.au', 'user'),
        ('zubair@wildon.com.au', 'superadmin')
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

-- 3. Insert role assignments
WITH seed_accounts(email, role) AS (
    VALUES
        ('control@wildon.com.au', 'superadmin'),
        ('platform@wildon.com.au', 'partner'),
        ('testuser@wildon.com.au', 'user'),
        ('zubair@wildon.com.au', 'superadmin')
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

-- 4. Create notification settings
WITH seed_accounts(email) AS (
    VALUES
        ('control@wildon.com.au'),
        ('platform@wildon.com.au'),
        ('testuser@wildon.com.au'),
        ('zubair@wildon.com.au')
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
