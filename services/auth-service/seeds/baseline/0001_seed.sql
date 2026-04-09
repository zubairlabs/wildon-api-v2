INSERT INTO auth.service_bootstrap (key, value)
VALUES ('realm_public_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
