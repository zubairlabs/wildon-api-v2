#!/usr/bin/env bash
set -euo pipefail

for service in auth-service users-service api-clients-service billing-service public-service platform-service control-service core-service storage-service export-service logs-service; do
  test -d "services/$service/migrations"
  test -d "services/$service/seeds"
  echo "verified db directories for $service"
done
