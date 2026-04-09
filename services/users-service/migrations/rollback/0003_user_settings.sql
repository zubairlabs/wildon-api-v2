DROP TABLE IF EXISTS users_app.user_notification_settings;

ALTER TABLE users_app.users
DROP CONSTRAINT IF EXISTS chk_users_phone_e164,
DROP CONSTRAINT IF EXISTS chk_users_username_format,
DROP CONSTRAINT IF EXISTS chk_users_language_non_empty,
DROP CONSTRAINT IF EXISTS chk_users_timezone_non_empty,
DROP CONSTRAINT IF EXISTS chk_users_temperature_unit,
DROP CONSTRAINT IF EXISTS chk_users_distance_unit,
DROP CONSTRAINT IF EXISTS chk_users_clock_format,
DROP CONSTRAINT IF EXISTS chk_users_date_format;

DROP INDEX IF EXISTS users_app.ux_users_username_ci;

ALTER TABLE users_app.users
DROP COLUMN IF EXISTS settings_updated_at,
DROP COLUMN IF EXISTS settings_version,
DROP COLUMN IF EXISTS temperature_unit,
DROP COLUMN IF EXISTS distance_unit,
DROP COLUMN IF EXISTS clock_format,
DROP COLUMN IF EXISTS date_format,
DROP COLUMN IF EXISTS language,
DROP COLUMN IF EXISTS bio,
DROP COLUMN IF EXISTS profile_photo_object_key,
DROP COLUMN IF EXISTS phone,
DROP COLUMN IF EXISTS username,
DROP COLUMN IF EXISTS full_name;
