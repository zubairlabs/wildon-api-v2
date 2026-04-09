ALTER TABLE control_app.regions
    DROP COLUMN IF EXISTS services;

ALTER TABLE control_app.regions
    ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS idx_regions_primary_true
    ON control_app.regions (is_primary)
    WHERE is_primary = true;
