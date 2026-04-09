#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <service-name> [profile]"
  exit 1
fi

service="$1"
profile="${2:-baseline}"
service_dir="services/$service"
seeds_dir="$service_dir/seeds/$profile"
environment="${APP_ENV:-${ENVIRONMENT:-development}}"

if [ ! -d "$service_dir" ]; then
  echo "service '$service' not found"
  exit 1
fi

if [[ "$environment" =~ ^(prod|production)$ ]] && [ "$profile" != "baseline" ]; then
  echo "profile '$profile' is not allowed in production environment (baseline only)"
  exit 1
fi

if [ ! -d "$seeds_dir" ]; then
  echo "no seeds for '$service' profile '$profile'"
  exit 0
fi

COMPOSE_FILE="infra/docker/docker-compose.yml"
DB_HOST="${DATABASE_HOST:-yugabyte}"
DB_PORT="${DATABASE_PORT:-5433}"
DB_USER="${DATABASE_USER:-yugabyte}"
DB_NAME="${DATABASE_NAME:-wildon}"

files=$(find "$seeds_dir" -maxdepth 1 -type f -name '*.sql' | sort || true)
if [ -z "$files" ]; then
  echo "no seed files for '$service' profile '$profile'"
  exit 0
fi

while IFS= read -r file; do
  [ -z "$file" ] && continue
  echo "applying seed: $file"
  cat "$file" | docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1

done <<< "$files"

echo "seeds completed for '$service' profile '$profile'"
