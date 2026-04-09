INSERT INTO platform_app.service_bootstrap (key, value)
VALUES ('support_portal_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
