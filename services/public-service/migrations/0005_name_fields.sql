-- Add structured name fields to user_profiles alongside existing display_name.

ALTER TABLE public_app.user_profiles
ADD COLUMN IF NOT EXISTS first_name TEXT,
ADD COLUMN IF NOT EXISTS last_name TEXT,
ADD COLUMN IF NOT EXISTS middle_name TEXT,
ADD COLUMN IF NOT EXISTS preferred_name TEXT;
