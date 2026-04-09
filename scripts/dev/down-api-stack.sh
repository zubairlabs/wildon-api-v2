#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

STATE_DIR=".run/local-api-stack"
PID_FILE="$STATE_DIR/pids"
LOG_DIR="$STATE_DIR/logs"

stop_services() {
  if [ ! -f "$PID_FILE" ]; then
    echo "no local api pid file found; skipping service shutdown"
    return
  fi

  echo "stopping local api services"

  while read -r pid service; do
    [ -z "${pid:-}" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      echo "  - stopping $service (pid=$pid)"
      kill "$pid" 2>/dev/null || true
    fi
  done < "$PID_FILE"

  for _ in $(seq 1 20); do
    local alive=0
    while read -r pid _service; do
      [ -z "${pid:-}" ] && continue
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
        break
      fi
    done < "$PID_FILE"

    if [ "$alive" -eq 0 ]; then
      break
    fi
    sleep 0.5
  done

  while read -r pid service; do
    [ -z "${pid:-}" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      echo "  - force stopping $service (pid=$pid)"
      kill -9 "$pid" 2>/dev/null || true
    fi
  done < "$PID_FILE"

  rm -f "$PID_FILE"
}

stop_services

echo "stopping local infra containers"
scripts/dev/down-local.sh

echo "local api stack stopped"
if [ -d "$LOG_DIR" ]; then
  echo "logs kept at: $LOG_DIR"
fi
