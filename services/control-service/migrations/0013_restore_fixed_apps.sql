INSERT INTO control_app.system_apps (
    platform, display_name, description, status, app_version, api_version, min_supported_version,
    latest_available_version, force_update_version, last_updated_at, update_policy, release_channel,
    health_score, last_incident_at, last_incident_type, uptime_percent, features, supported_devices,
    bundle_id, store_url, environment, notes,
    stats_guests_count, stats_registered_users, stats_users_online, stats_peak_online_today,
    stats_avg_session_minutes, stats_crash_rate_percent, stats_api_status, stats_api_latency_ms, stats_device_distribution
)
VALUES
(
    'android', 'Android App', 'Wildon mobile application for Android devices', 'online',
    '2.4.1', 'v1', '2.0.0', NULL, '2.2.0', NOW(), 'recommended', 'stable',
    94, NOW() - INTERVAL '26 days', 'GPS drift spike on L17 devices', 99.8,
    '{"new_dashboard": true, "ai_alerts": false, "beta_mode": true, "offline_mode": true, "biometric_login": true}'::jsonb,
    '["L16","L17","B08"]'::jsonb,
    'com.wildon.app', 'https://play.google.com/store/apps/details?id=com.wildon.app', 'production',
    'Primary mobile app for caregivers and family members',
    12450, 8230, 342, 578, 12.4, 0.8, 'healthy', 120, '{"L16": 60, "L17": 30, "B08": 10}'::jsonb
),
(
    'ios', 'iOS App', 'Wildon mobile application for iOS devices', 'online',
    '2.3.8', 'v1', '2.0.0', '2.4.1', '2.1.0', NOW(), 'recommended', 'stable',
    97, NOW() - INTERVAL '36 days', 'Notification delivery failure on iOS 18', 99.9,
    '{"new_dashboard": true, "ai_alerts": false, "beta_mode": false, "offline_mode": true, "biometric_login": true}'::jsonb,
    '["L16","L17","B08"]'::jsonb,
    'com.wildon.app', 'https://apps.apple.com/app/wildon/id1234567890', 'production',
    'iOS version trails Android by about one week due to store review',
    9870, 6540, 287, 452, 14.2, 0.3, 'healthy', 115, '{"L16": 55, "L17": 35, "B08": 10}'::jsonb
),
(
    'web-users', 'Web App (Users)', 'Browser-based dashboard for caregivers and family members', 'online',
    '1.12.0', 'v1', '1.8.0', NULL, '1.10.0', NOW(), 'silent', 'stable',
    99, NOW() - INTERVAL '80 days', 'CDN cache invalidation delay', 99.95,
    '{"new_dashboard": true, "ai_alerts": true, "beta_mode": false, "live_location": true, "export_reports": true}'::jsonb,
    '["L16","L17","P12","B08"]'::jsonb,
    NULL, NULL, 'production',
    'Highest traffic app, auto-deployed on main',
    45200, 15800, 1024, 1856, 8.6, 0.1, 'healthy', 95, '{"L16": 40, "L17": 30, "P12": 20, "B08": 10}'::jsonb
),
(
    'web-support', 'Web App (Support)', 'Support team dashboard for ticket and device troubleshooting', 'online',
    '1.12.0', 'v1', '1.10.0', NULL, NULL, NOW(), 'silent', 'stable',
    98, NOW() - INTERVAL '54 days', 'SSO token refresh timeout', 99.9,
    '{"new_dashboard": true, "ai_alerts": true, "remote_diagnostics": true, "escalation_workflows": true}'::jsonb,
    '["all"]'::jsonb,
    NULL, NULL, 'production',
    'Internal support staff only',
    0, 48, 12, 24, 42.8, 0.0, 'healthy', 88, '{}'::jsonb
),
(
    'web-admins', 'Web App (Admins)', 'Admin control panel for system management and configuration', 'maintenance',
    '1.12.0', 'v1', '1.10.0', NULL, NULL, NOW(), 'silent', 'stable',
    72, NOW() - INTERVAL '8 days', 'Deployment rollback and timeout spike', 98.5,
    '{"new_dashboard": false, "ai_alerts": false, "audit_logs": true, "bulk_operations": true, "feature_flags_manager": true}'::jsonb,
    '["all"]'::jsonb,
    NULL, NULL, 'production',
    'Currently in maintenance while apps section updates are in progress',
    0, 8, 3, 6, 35.2, 0.5, 'degraded', 340, '{}'::jsonb
)
ON CONFLICT (platform) DO NOTHING;

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'android', '2.4.1', NOW() - INTERVAL '14 days', 'Fixed GPS drift on L17 devices', 'v1', 100, 'stable', 'current'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'android' AND version = '2.4.1' AND channel = 'stable' AND status = 'current'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'android', '2.4.0', NOW() - INTERVAL '28 days', 'New dashboard layout and biometric login', 'v1', 100, 'stable', 'previous'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'android' AND version = '2.4.0' AND channel = 'stable' AND status = 'previous'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'ios', '2.3.8', NOW() - INTERVAL '18 days', 'Fixed notification delivery on iOS 18', 'v1', 100, 'stable', 'current'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'ios' AND version = '2.3.8' AND channel = 'stable' AND status = 'current'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'ios', '2.3.5', NOW() - INTERVAL '31 days', 'Performance improvements and widget support', 'v1', 100, 'stable', 'previous'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'ios' AND version = '2.3.5' AND channel = 'stable' AND status = 'previous'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'web-users', '1.12.0', NOW() - INTERVAL '11 days', 'AI alerts integration and location tracking', 'v1', 100, 'stable', 'current'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'web-users' AND version = '1.12.0' AND channel = 'stable' AND status = 'current'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'web-support', '1.12.0', NOW() - INTERVAL '11 days', 'Remote diagnostics v2 and workflow automation', 'v1', 100, 'stable', 'current'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'web-support' AND version = '1.12.0' AND channel = 'stable' AND status = 'current'
);

INSERT INTO control_app.system_app_versions (
    platform, version, released_at, release_notes, api_version, rollout_percentage, channel, status
)
SELECT 'web-admins', '1.12.0', NOW() - INTERVAL '8 days', 'Apps management section and bulk operations', 'v1', 50, 'beta', 'current'
WHERE NOT EXISTS (
    SELECT 1 FROM control_app.system_app_versions
    WHERE platform = 'web-admins' AND version = '1.12.0' AND channel = 'beta' AND status = 'current'
);
