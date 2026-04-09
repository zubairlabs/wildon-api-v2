CREATE TABLE IF NOT EXISTS control_app.invoice_settings (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
  logo_url TEXT NOT NULL DEFAULT '',
  logo_size_px INTEGER NOT NULL DEFAULT 96 CHECK (logo_size_px BETWEEN 16 AND 1024),
  business_name TEXT NOT NULL DEFAULT '',
  business_legal_name TEXT NOT NULL DEFAULT '',
  business_address TEXT NOT NULL DEFAULT '',
  support_phone TEXT NOT NULL DEFAULT '',
  invoice_email TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT 'system',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO control_app.invoice_settings (
  singleton,
  logo_url,
  logo_size_px,
  business_name,
  business_legal_name,
  business_address,
  support_phone,
  invoice_email,
  updated_by
)
VALUES (
  TRUE,
  '',
  96,
  'Wildon',
  'Wildon Inc.',
  '',
  '',
  'billing@wildon.local',
  'migration:0003'
)
ON CONFLICT (singleton) DO NOTHING;
