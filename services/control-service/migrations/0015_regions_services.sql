ALTER TABLE control_app.regions
    ADD COLUMN services JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE control_app.regions
    DROP COLUMN IF EXISTS is_primary;

DROP INDEX IF EXISTS idx_regions_primary_true;
