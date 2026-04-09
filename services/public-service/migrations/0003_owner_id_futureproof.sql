ALTER TABLE public_app.user_profiles
ADD COLUMN IF NOT EXISTS owner_id TEXT;

UPDATE public_app.user_profiles
SET owner_id = user_id
WHERE owner_id IS NULL;

ALTER TABLE public_app.user_profiles
ALTER COLUMN owner_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_public_user_profiles_owner_id
  ON public_app.user_profiles (owner_id);

ALTER TABLE public_app.user_devices
ADD COLUMN IF NOT EXISTS owner_id TEXT;

UPDATE public_app.user_devices
SET owner_id = user_id
WHERE owner_id IS NULL;

ALTER TABLE public_app.user_devices
ALTER COLUMN owner_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_public_user_devices_owner_id
  ON public_app.user_devices (owner_id);
