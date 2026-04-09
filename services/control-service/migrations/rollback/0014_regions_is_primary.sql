-- Rollback: rename is_primary back to is_default on regions table

ALTER TABLE control_app.regions RENAME COLUMN is_primary TO is_default;

DROP INDEX IF EXISTS idx_regions_primary_true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_regions_default_true
    ON control_app.regions (is_default)
    WHERE is_default = true;
