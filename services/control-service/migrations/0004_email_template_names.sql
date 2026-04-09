DROP INDEX IF EXISTS idx_control_app_email_templates_channel;
DROP TABLE IF EXISTS control_app.email_templates;

CREATE TABLE IF NOT EXISTS control_app.email_templates (
  template_name TEXT PRIMARY KEY
    CHECK (
      template_name IN (
        'email-otp',
        'welcome',
        'password-reset-request',
        'password-changed-success'
      )
    ),
  subject_template TEXT NOT NULL,
  html_template TEXT NOT NULL,
  placeholders TEXT[] NOT NULL DEFAULT '{}',
  updated_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
