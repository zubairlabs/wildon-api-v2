DROP INDEX IF EXISTS public_app.idx_public_user_devices_owner_id;
ALTER TABLE public_app.user_devices DROP COLUMN IF EXISTS owner_id;

DROP INDEX IF EXISTS public_app.idx_public_user_profiles_owner_id;
ALTER TABLE public_app.user_profiles DROP COLUMN IF EXISTS owner_id;
