#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <service-name>"
  exit 1
fi

service="$1"
service_dir="services/$service"
migrations_dir="$service_dir/migrations"

if [ ! -d "$service_dir" ]; then
  echo "service '$service' not found"
  exit 1
fi

"$(dirname "$0")/db-create.sh"

if [ ! -d "$migrations_dir" ]; then
  echo "no migrations directory for '$service'"
  exit 0
fi

files=$(find "$migrations_dir" -maxdepth 1 -type f -name '*.sql' | sort || true)
if [ -z "$files" ]; then
  echo "no migration files for '$service'"
  exit 0
fi

COMPOSE_FILE="infra/docker/docker-compose.yml"
DB_HOST="${DATABASE_HOST:-yugabyte}"
DB_PORT="${DATABASE_PORT:-5433}"
DB_USER="${DATABASE_USER:-yugabyte}"
DB_NAME="${DATABASE_NAME:-wildon}"

while IFS= read -r file; do
  [ -z "$file" ] && continue
  echo "applying migration: $file"
  cat "$file" | docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1

done <<< "$files"

echo "migrations completed for '$service'"
