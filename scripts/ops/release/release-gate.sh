#!/usr/bin/env bash
set -euo pipefail

WITH_LOAD=0
SKIP_UP_LOCAL=0
SKIP_DB_BOOTSTRAP=0
SKIP_WORKSPACE_CHECK=0
SKIP_SMOKE=0
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"

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

usage() {
  cat <<USAGE
Usage:
  scripts/ops/release/release-gate.sh [options]

Options:
  --with-load              Run load tests at the end
  --skip-up-local          Skip local infra bootstrap
  --skip-db-bootstrap      Skip migrations + seeds
  --skip-workspace-check   Skip scripts/ci/check-workspace.sh
  --skip-smoke             Skip gateway smoke checks
  --base-url <url>         Gateway base URL for smoke/load checks
  -h, --help               Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-load)
      WITH_LOAD=1
      shift
      ;;
    --skip-up-local)
      SKIP_UP_LOCAL=1
      shift
      ;;
    --skip-db-bootstrap)
      SKIP_DB_BOOTSTRAP=1
      shift
      ;;
    --skip-workspace-check)
      SKIP_WORKSPACE_CHECK=1
      shift
      ;;
    --skip-smoke)
      SKIP_SMOKE=1
      shift
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [ "$SKIP_UP_LOCAL" -eq 0 ]; then
  echo "[gate] starting local infra"
  scripts/dev/up-local.sh
fi

if [ "$SKIP_DB_BOOTSTRAP" -eq 0 ]; then
  echo "[gate] running migrations and seeds"
  for service in "${STATEFUL_SERVICES[@]}"; do
    scripts/dev/db-bootstrap.sh "$service" baseline
  done
fi

if [ "$SKIP_WORKSPACE_CHECK" -eq 0 ]; then
  echo "[gate] running workspace checks"
  scripts/ci/check-workspace.sh
fi

if [ "$SKIP_SMOKE" -eq 0 ]; then
  echo "[gate] running gateway smoke checks against ${BASE_URL}"
  curl -fsS "${BASE_URL}/health" >/dev/null
  curl -fsS "${BASE_URL}/v1/public/ping" >/dev/null
  curl -fsS "${BASE_URL}/.well-known/openid-configuration" >/dev/null
  curl -fsS -X POST "${BASE_URL}/v1/auth/register" \
    -H 'x-client-id: wildon-web-public' \
    -H 'content-type: application/json' \
    -d '{"email":"release-gate@example.com","password":"ReleaseGate123","display_name":"Release Gate"}' >/dev/null || true
fi

if [ "$WITH_LOAD" -eq 1 ]; then
  echo "[gate] running load tests"
  BASE_URL="$BASE_URL" scripts/ops/load/run-load-tests.sh
fi

echo "[gate] local release gate passed"
