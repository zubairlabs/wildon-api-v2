INSERT INTO public_app.service_bootstrap (key, value)
VALUES ('users_module_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
