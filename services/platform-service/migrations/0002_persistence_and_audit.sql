-- 0002_persistence_and_audit.sql
-- Wire ticket persistence + partner settings to Postgres

-- Add source column to differentiate support/desk/partner tickets
ALTER TABLE platform_app.support_tickets
  ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'support';

-- Add contact_email for ticket follow-up dispatch
ALTER TABLE platform_app.support_tickets
  ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';

-- Index for fast lookups by source + status (dashboard queries)
CREATE INDEX IF NOT EXISTS idx_support_tickets_source_status
  ON platform_app.support_tickets (source, status);

-- Partner settings table
CREATE TABLE IF NOT EXISTS platform_app.partner_settings (
  key         TEXT PRIMARY KEY,
  notifications_enabled BOOLEAN NOT NULL DEFAULT true,
  alert_email TEXT NOT NULL DEFAULT 'support@wildon.local',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default partner settings row
INSERT INTO platform_app.partner_settings (key, notifications_enabled, alert_email)
VALUES ('default', true, 'support@wildon.local')
ON CONFLICT (key) DO NOTHING;
