DROP TABLE IF EXISTS control_app.email_templates;

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

CREATE INDEX IF NOT EXISTS idx_control_app_email_templates_channel
  ON control_app.email_templates (channel);
