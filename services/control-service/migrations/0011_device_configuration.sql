CREATE TABLE IF NOT EXISTS control_app.device_configuration (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    config JSONB NOT NULL,
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
