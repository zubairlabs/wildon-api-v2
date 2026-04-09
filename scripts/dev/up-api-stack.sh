#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"
if [ ! -f "$ENV_FILE" ]; then
  echo "missing env file: $ENV_FILE"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Local stack should behave like a development deployment unless explicitly overridden.
export APP_ENV="${APP_ENV:-${ENVIRONMENT:-development}}"
export ENVIRONMENT="${ENVIRONMENT:-$APP_ENV}"

ensure_min_disk_space() {
  local min_kb=2097152 # 2 GiB
  local avail_kb
  avail_kb="$(df -Pk / | awk 'NR==2 {print $4}')"

  if [ -z "$avail_kb" ]; then
    echo "failed to determine free disk space"
    exit 1
  fi

  if [ "$avail_kb" -lt "$min_kb" ]; then
    local avail_mb=$((avail_kb / 1024))
    echo "insufficient disk space for local stack startup (${avail_mb}MB free on /)."
    echo "free at least 2GB, then run scripts/dev/up-api-stack.sh again."
    exit 1
  fi
}

port_in_use() {
  local port="$1"
  ss -ltnH | awk '{print $4}' | grep -Eq "(^|:)$port$"
}

find_next_free_port() {
  local start_port="$1"
  local candidate=$((start_port + 1))
  local limit=$((start_port + 200))

  while [ "$candidate" -le "$limit" ]; do
    if ! port_in_use "$candidate"; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done

  return 1
}

auto_remap_port_if_busy() {
  local port_var="$1"
  local url_var="$2"
  local url_prefix="$3"
  local current_port="${!port_var:-}"

  if [ -z "$current_port" ]; then
    return 0
  fi

  if ! port_in_use "$current_port"; then
    return 0
  fi

  local next_port
  next_port="$(find_next_free_port "$current_port")" || {
    echo "unable to find free port near $current_port for $port_var"
    exit 1
  }

  echo "port $current_port is busy, remapping $port_var -> $next_port for this run"
  export "$port_var=$next_port"
  export "$url_var=$url_prefix$next_port"
}

# Avoid local host-port collisions for optional infra ports.
auto_remap_port_if_busy REDIS_HOST_PORT REDIS_URL "redis://127.0.0.1:"
auto_remap_port_if_busy NATS_HOST_PORT NATS_URL "nats://127.0.0.1:"
auto_remap_port_if_busy NATS_MONITOR_HOST_PORT NATS_MONITOR_URL "http://127.0.0.1:"

ensure_min_disk_space

STATE_DIR=".run/local-api-stack"
PID_FILE="$STATE_DIR/pids"
LOG_DIR="$STATE_DIR/logs"
mkdir -p "$LOG_DIR"

STATEFUL_SERVICES=(
  auth-service
  users-service
  api-clients-service
  billing-service
  public-service
  core-service
  storage-service
  export-service
  logs-service
  platform-service
  control-service
)

SERVICES=(
  users-service
  api-clients-service
  logs-service
  storage-service
  export-service
  billing-service
  public-service
  auth-service
  core-service
  platform-service
  control-service
  gateway-service
)

check_not_running() {
  if [ ! -f "$PID_FILE" ]; then
    return 0
  fi

  while read -r pid _service; do
    [ -z "${pid:-}" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      echo "local api stack already running (pid=$pid)."
      echo "run scripts/dev/down-api-stack.sh first"
      exit 1
    fi
  done < "$PID_FILE"
}

cleanup_on_error() {
  if [ ! -f "$PID_FILE" ]; then
    return 0
  fi

  while read -r pid _service; do
    [ -z "${pid:-}" ] && continue
    kill "$pid" 2>/dev/null || true
  done < "$PID_FILE"
}

start_service() {
  local service="$1"
  local log_file="$LOG_DIR/${service}.log"
  local binary="$ROOT_DIR/target/debug/$service"

  echo "  - starting $service"
  if [ ! -x "$binary" ]; then
    echo "missing binary for $service at $binary"
    exit 1
  fi

  nohup "$binary" >"$log_file" 2>&1 < /dev/null &

  local pid=$!
  echo "$pid $service" >> "$PID_FILE"
  sleep 1

  if ! kill -0 "$pid" 2>/dev/null; then
    echo "failed to start $service"
    echo "--- $log_file (tail) ---"
    tail -n 80 "$log_file" || true
    exit 1
  fi
}

check_not_running
: > "$PID_FILE"
trap cleanup_on_error ERR

echo "[1/4] starting local infra"
scripts/dev/up-local.sh

echo "[2/4] running migrations and seeds"
for service in "${STATEFUL_SERVICES[@]}"; do
  DATABASE_HOST=yugabyte DATABASE_PORT=5433 scripts/dev/db-bootstrap.sh "$service" baseline
done

echo "[3/4] building api services"
cargo build \
  -p users-service \
  -p api-clients-service \
  -p logs-service \
  -p storage-service \
  -p export-service \
  -p billing-service \
  -p public-service \
  -p auth-service \
  -p core-service \
  -p platform-service \
  -p control-service \
  -p gateway-service

echo "[4/4] starting api services and waiting for gateway health"
for service in "${SERVICES[@]}"; do
  start_service "$service"
done

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-180}"
for _ in $(seq 1 "$HEALTH_WAIT_SECONDS"); do
  if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
    echo ""
    echo "local api stack is ready"
    echo "gateway:  $BASE_URL"
    echo "swagger:  $BASE_URL/docs"
    echo "openapi:  $BASE_URL/openapi/gateway-v1.json"
    echo "logs:     $LOG_DIR"
    exit 0
  fi
  sleep 1
done

echo "gateway failed to become healthy in time"
echo "--- $LOG_DIR/gateway-service.log (tail) ---"
tail -n 120 "$LOG_DIR/gateway-service.log" || true
exit 1
