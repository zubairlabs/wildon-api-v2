-- User account numbers: G1-{8 random alphanumeric}
-- Used for: support identification, care circle sharing invitations, invoices

CREATE OR REPLACE FUNCTION users_app.random_account_number() RETURNS TEXT AS $$
DECLARE
  chars TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  result TEXT := '';
BEGIN
  FOR i IN 1..8 LOOP
    result := result || substr(chars, floor(random() * 36 + 1)::int, 1);
  END LOOP;
  RETURN 'G1-' || result;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE users_app.users ADD COLUMN IF NOT EXISTS account_number TEXT;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_account_number_key'
  ) THEN
    ALTER TABLE users_app.users
      ADD CONSTRAINT users_account_number_key UNIQUE (account_number);
  END IF;
END;
$$;

UPDATE users_app.users SET account_number = users_app.random_account_number() WHERE account_number IS NULL;
ALTER TABLE users_app.users ALTER COLUMN account_number SET NOT NULL;

DROP FUNCTION IF EXISTS users_app.random_account_number();
