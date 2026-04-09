#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-infra/docker/docker-compose.yml}"
SRC_DB="${SRC_DB:-wildon}"
DB_HOST="${DB_HOST:-yugabyte}"
DB_PORT="${DB_PORT:-5433}"
DB_USER="${DB_USER:-yugabyte}"
BACKUP_DIR="${BACKUP_DIR:-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
MODE="${1:-drill}"
RESTORE_FILE="${2:-}"

mkdir -p "$BACKUP_DIR"
DUMP_FILE="${BACKUP_DIR}/${SRC_DB}-${STAMP}.sql"
DRILL_DB="${SRC_DB}_drill_${STAMP//-/}"

ysql_exec() {
  docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$1" -c "$2"
}

dump_db() {
  local src_db="$1"
  local output_file="$2"

  docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysql_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$src_db" > "$output_file"
  echo "backup created: $output_file"
}

restore_db() {
  local target_db="$1"
  local input_file="$2"

  if [ ! -f "$input_file" ]; then
    echo "restore file not found: $input_file"
    exit 1
  fi

  ysql_exec yugabyte "DROP DATABASE IF EXISTS ${target_db};"
  ysql_exec yugabyte "CREATE DATABASE ${target_db};"

  cat "$input_file" | docker compose -f "$COMPOSE_FILE" exec -T yugabyte \
    ysqlsh -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$target_db" >/dev/null

  echo "restore completed into database: $target_db"
}

verify_restore() {
  local db_name="$1"
  ysql_exec "$db_name" "SELECT current_database() AS db, now() AS restored_at;"
}

case "$MODE" in
  backup)
    dump_db "$SRC_DB" "$DUMP_FILE"
    ;;
  restore)
    if [ -z "$RESTORE_FILE" ]; then
      echo "usage: $0 restore <dump_file>"
      exit 1
    fi
    restore_db "$DRILL_DB" "$RESTORE_FILE"
    verify_restore "$DRILL_DB"
    ;;
  drill)
    dump_db "$SRC_DB" "$DUMP_FILE"
    restore_db "$DRILL_DB" "$DUMP_FILE"
    verify_restore "$DRILL_DB"
    echo "drill succeeded: source=${SRC_DB}, restored=${DRILL_DB}"
    ;;
  *)
    echo "usage: $0 [backup|restore <dump_file>|drill]"
    exit 1
    ;;
esac
