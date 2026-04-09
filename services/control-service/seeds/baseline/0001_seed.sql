INSERT INTO control_app.service_bootstrap (key, value)
VALUES ('control_surface_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
