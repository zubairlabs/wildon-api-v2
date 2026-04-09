#!/usr/bin/env bash
set -euo pipefail

bootstrap_script="scripts/dev/db-bootstrap.sh"
migrate_line=$(grep -n 'db-migrate.sh' "$bootstrap_script" | head -n1 | cut -d: -f1)
seed_line=$(grep -n 'db-seed.sh' "$bootstrap_script" | head -n1 | cut -d: -f1)

if [ -z "$migrate_line" ] || [ -z "$seed_line" ]; then
  echo "failed to find migrate/seed calls in $bootstrap_script"
  exit 1
fi

if [ "$migrate_line" -ge "$seed_line" ]; then
  echo "migration-before-seed ordering is invalid in $bootstrap_script"
  exit 1
fi

echo "migration-before-seed ordering is valid in $bootstrap_script"

for service in auth-service users-service api-clients-service billing-service public-service platform-service control-service core-service storage-service export-service logs-service; do
  migrations=$(find "services/$service/migrations" -maxdepth 1 -type f -name '*.sql' | wc -l)
  seeds=$(find "services/$service/seeds/baseline" -maxdepth 1 -type f -name '*.sql' | wc -l)

  if [ "$migrations" -lt 1 ]; then
    echo "service '$service' has no migration sql files"
    exit 1
  fi

  if [ "$seeds" -lt 1 ]; then
    echo "service '$service' has no baseline seed sql files"
    exit 1
  fi

  echo "verified migration/seed presence for $service"
done
