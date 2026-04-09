INSERT INTO public_app.service_bootstrap (key, value)
VALUES ('feature_profile_write', 'enabled')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public_app.service_bootstrap (key, value)
VALUES ('feature_device_manage', 'enabled')
ON CONFLICT (key) DO NOTHING;
