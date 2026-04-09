-- Replace single full_name with structured name fields for healthcare identity model.
--
--   first_name      — legal given name (required at registration)
--   last_name       — legal family name (required at registration)
--   middle_name     — optional legal middle name(s)
--   preferred_name  — what the person likes to be called (caregivers, notifications)
--   display_name    — how they appear in the app UI (care circle cards, avatars)
--
-- full_name is now computed: TRIM(first_name || ' ' || COALESCE(middle_name || ' ', '') || last_name)
-- The column is kept for backward-compat queries but populated via trigger.

ALTER TABLE users_app.users
ADD COLUMN IF NOT EXISTS first_name TEXT,
ADD COLUMN IF NOT EXISTS last_name TEXT,
ADD COLUMN IF NOT EXISTS middle_name TEXT,
ADD COLUMN IF NOT EXISTS preferred_name TEXT,
ADD COLUMN IF NOT EXISTS display_name TEXT;

-- Migrate existing full_name data into first_name as a best-effort fallback.
UPDATE users_app.users
SET first_name = BTRIM(full_name)
WHERE full_name IS NOT NULL
  AND BTRIM(full_name) <> ''
  AND first_name IS NULL;

-- Keep full_name column in sync automatically.
CREATE OR REPLACE FUNCTION users_app.compute_full_name()
RETURNS TRIGGER AS $$
BEGIN
  NEW.full_name := BTRIM(
    COALESCE(NEW.first_name, '') || ' ' ||
    COALESCE(NEW.middle_name || ' ', '') ||
    COALESCE(NEW.last_name, '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_compute_full_name ON users_app.users;
CREATE TRIGGER trg_compute_full_name
  BEFORE INSERT OR UPDATE OF first_name, middle_name, last_name
  ON users_app.users
  FOR EACH ROW
  EXECUTE FUNCTION users_app.compute_full_name();

-- Backfill full_name for rows that already have first/last populated.
UPDATE users_app.users
SET full_name = BTRIM(
  COALESCE(first_name, '') || ' ' ||
  COALESCE(middle_name || ' ', '') ||
  COALESCE(last_name, '')
)
WHERE first_name IS NOT NULL OR last_name IS NOT NULL;
