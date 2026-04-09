ALTER TABLE users_app.users
ADD COLUMN IF NOT EXISTS full_name TEXT,
ADD COLUMN IF NOT EXISTS username TEXT,
ADD COLUMN IF NOT EXISTS phone TEXT,
ADD COLUMN IF NOT EXISTS profile_photo_object_key TEXT,
ADD COLUMN IF NOT EXISTS bio TEXT,
ADD COLUMN IF NOT EXISTS language TEXT NOT NULL DEFAULT 'en',
ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC',
ADD COLUMN IF NOT EXISTS date_format TEXT NOT NULL DEFAULT 'YYYY-MM-DD',
ADD COLUMN IF NOT EXISTS clock_format TEXT NOT NULL DEFAULT '24h',
ADD COLUMN IF NOT EXISTS distance_unit TEXT NOT NULL DEFAULT 'km',
ADD COLUMN IF NOT EXISTS temperature_unit TEXT NOT NULL DEFAULT 'C',
ADD COLUMN IF NOT EXISTS settings_version INT NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS settings_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username_ci
  ON users_app.users ((LOWER(username)))
  WHERE username IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_date_format'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_date_format
      CHECK (date_format IN ('YYYY-MM-DD', 'DD-MM-YYYY'));
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_clock_format'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_clock_format
      CHECK (clock_format IN ('12h', '24h'));
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_distance_unit'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_distance_unit
      CHECK (distance_unit IN ('km', 'miles'));
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_temperature_unit'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_temperature_unit
      CHECK (temperature_unit IN ('C', 'F'));
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_timezone_non_empty'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_timezone_non_empty
      CHECK (BTRIM(timezone) <> '');
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_language_non_empty'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_language_non_empty
      CHECK (BTRIM(language) <> '');
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_username_format'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_username_format
      CHECK (username IS NULL OR username ~ '^[a-z0-9][a-z0-9._-]{2,31}$');
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_users_phone_e164'
  ) THEN
    ALTER TABLE users_app.users
    ADD CONSTRAINT chk_users_phone_e164
      CHECK (phone IS NULL OR phone ~ '^\+[1-9][0-9]{7,14}$');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS users_app.user_notification_settings (
  user_id UUID PRIMARY KEY REFERENCES users_app.users(user_id) ON DELETE CASCADE,
  push_new_photo_captured BOOLEAN NOT NULL DEFAULT TRUE,
  push_species_detected BOOLEAN NOT NULL DEFAULT TRUE,
  push_device_offline BOOLEAN NOT NULL DEFAULT TRUE,
  push_low_battery BOOLEAN NOT NULL DEFAULT TRUE,
  push_storage_full BOOLEAN NOT NULL DEFAULT TRUE,
  push_subscription_renewal_reminder BOOLEAN NOT NULL DEFAULT TRUE,
  push_trip_activity_updates BOOLEAN NOT NULL DEFAULT TRUE,
  email_new_photo_captured BOOLEAN NOT NULL DEFAULT TRUE,
  email_species_detected BOOLEAN NOT NULL DEFAULT TRUE,
  email_device_offline BOOLEAN NOT NULL DEFAULT TRUE,
  email_low_battery BOOLEAN NOT NULL DEFAULT TRUE,
  email_storage_full BOOLEAN NOT NULL DEFAULT TRUE,
  email_subscription_renewal_reminder BOOLEAN NOT NULL DEFAULT TRUE,
  email_trip_activity_updates BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO users_app.user_notification_settings (user_id)
SELECT user_id
FROM users_app.users
ON CONFLICT (user_id) DO NOTHING;
