INSERT INTO logs_app.service_bootstrap (key, value)
VALUES ('audit_ingestion_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
