CREATE SCHEMA IF NOT EXISTS api_clients_app;

CREATE TABLE IF NOT EXISTS api_clients_app.api_clients (
  client_id TEXT PRIMARY KEY,
  client_type TEXT NOT NULL,
  status TEXT NOT NULL,
  environment TEXT NOT NULL,
  rate_limit_profile TEXT NOT NULL,
  min_app_version TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_clients_app.api_client_audiences (
  client_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  PRIMARY KEY (client_id, audience)
);

CREATE TABLE IF NOT EXISTS api_clients_app.rate_limit_profiles (
  profile_name TEXT PRIMARY KEY,
  default_user_rpm INT NOT NULL,
  default_client_rpm INT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS api_clients_app.rate_limit_route_overrides (
  profile_name TEXT NOT NULL,
  route_id TEXT NOT NULL,
  user_rpm INT NULL,
  client_rpm INT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (profile_name, route_id)
);
