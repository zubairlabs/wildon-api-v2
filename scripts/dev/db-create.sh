#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="infra/docker/docker-compose.yml"
DB_HOST="${DATABASE_HOST:-yugabyte}"
DB_PORT="${DATABASE_PORT:-5433}"
DB_USER="${DATABASE_USER:-yugabyte}"
DB_NAME="${DATABASE_NAME:-wildon}"

exists=$(docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
  ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d yugabyte -tAc \
  "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME';" || true)

if [ "${exists//[[:space:]]/}" = "1" ]; then
  echo "database '$DB_NAME' already exists"
  exit 0
fi

docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
  ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d yugabyte -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE \"$DB_NAME\";"

echo "database '$DB_NAME' created"
