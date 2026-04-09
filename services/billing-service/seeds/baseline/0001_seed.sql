INSERT INTO billing_app.plans (plan_key, name)
VALUES
  ('free', 'Free'),
  ('pro', 'Pro')
ON CONFLICT (plan_key) DO NOTHING;

INSERT INTO billing_app.plan_entitlements (plan_key, feature_key)
VALUES
  ('free', 'profile_read'),
  ('pro', 'profile_read'),
  ('pro', 'profile_write'),
  ('pro', 'device_manage')
ON CONFLICT (plan_key, feature_key) DO NOTHING;
