-- Rename is_default → is_primary on regions table
-- is_primary better describes the architectural role (PRIMARY vs REGIONAL deployment)

ALTER TABLE control_app.regions RENAME COLUMN is_default TO is_primary;

DROP INDEX IF EXISTS idx_regions_default_true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_regions_primary_true
    ON control_app.regions (is_primary)
    WHERE is_primary = true;
