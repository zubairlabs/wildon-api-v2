INSERT INTO api_clients_app.rate_limit_profiles (profile_name, default_user_rpm, default_client_rpm, enabled)
VALUES
  ('public_mobile_v1', 60, 5000, TRUE),
  ('platform_v1', 30, 1000, TRUE),
  ('control_v1', 20, 500, TRUE)
ON CONFLICT (profile_name) DO NOTHING;

INSERT INTO api_clients_app.api_clients (client_id, client_type, status, environment, rate_limit_profile)
VALUES
  ('wildon-android', 'public', 'active', 'prod', 'public_mobile_v1'),
  ('wildon-ios', 'public', 'active', 'prod', 'public_mobile_v1'),
  ('wildon-web-public', 'public', 'active', 'prod', 'public_mobile_v1'),
  ('wildon-control-web', 'public', 'active', 'prod', 'control_v1')
ON CONFLICT (client_id) DO NOTHING;
