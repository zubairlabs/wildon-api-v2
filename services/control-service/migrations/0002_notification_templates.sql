CREATE TABLE IF NOT EXISTS control_app.email_templates (
  template_key TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email')),
  subject_template TEXT NOT NULL,
  html_template TEXT NOT NULL,
  placeholders TEXT[] NOT NULL DEFAULT '{}',
  updated_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (template_key, channel)
);

DO $$
BEGIN
  -- 0004_email_template_names.sql replaces this table schema and removes `channel`.
  -- Because deploy reapplies historical migrations, guard the legacy index creation.
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'control_app'
      AND table_name = 'email_templates'
      AND column_name = 'channel'
  ) THEN
    CREATE INDEX IF NOT EXISTS idx_control_app_email_templates_channel
      ON control_app.email_templates (channel);
  END IF;
END
$$;
