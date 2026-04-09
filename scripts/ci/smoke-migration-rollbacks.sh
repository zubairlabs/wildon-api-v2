#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="infra/docker/docker-compose.yml"
DB_HOST="yugabyte"
DB_PORT=5433
DB_USER="yugabyte"
DB_NAME="wildon_rollback_smoke"
SERVICES=(
  auth-service
  users-service
  api-clients-service
  billing-service
  public-service
  platform-service
  control-service
  core-service
  storage-service
  export-service
  logs-service
)

cleanup() {
  docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f "$COMPOSE_FILE" up -d yugabyte >/dev/null

echo "waiting for yugabyte readiness for rollback smoke test..."
for _ in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d yugabyte -c "SELECT 1;" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
  ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d yugabyte -c "DROP DATABASE IF EXISTS $DB_NAME;" >/dev/null

docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
  ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d yugabyte -c "CREATE DATABASE $DB_NAME;" >/dev/null

for service in "${SERVICES[@]}"; do
  migration_dir="services/$service/migrations"
  rollback_dir="$migration_dir/rollback"

  migrations=$(find "$migration_dir" -maxdepth 1 -type f -name '*.sql' | sort || true)
  if [ -z "$migrations" ]; then
    echo "rollback smoke failed: no migrations found for $service"
    exit 1
  fi

  echo "[rollback smoke] applying migrations for $service"
  while IFS= read -r migration; do
    [ -z "$migration" ] && continue
    cat "$migration" | docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
      ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null
  done <<< "$migrations"

  echo "[rollback smoke] applying rollbacks for $service"
  while IFS= read -r migration; do
    [ -z "$migration" ] && continue
    base=$(basename "$migration")
    rollback="$rollback_dir/$base"
    if [ ! -f "$rollback" ]; then
      echo "rollback smoke failed: missing rollback file $rollback"
      exit 1
    fi

    cat "$rollback" | docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
      ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null
  done <<< "$(echo "$migrations" | tac)"
done

echo "migration rollback smoke checks passed"
