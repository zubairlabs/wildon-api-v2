INSERT INTO core_app.service_bootstrap (key, value)
VALUES ('entitlements_engine_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
