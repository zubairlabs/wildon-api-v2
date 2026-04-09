#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
APP_ID="${APP_ID:-wildon}"
LOGIN_SUB="${LOGIN_SUB:-load-user}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 is required. Install from https://k6.io/docs/get-started/installation/"
  exit 1
fi

echo "running smoke load test against ${BASE_URL}"
BASE_URL="$BASE_URL" k6 run scripts/ops/load/k6-smoke.js

echo "running soak load test against ${BASE_URL}"
BASE_URL="$BASE_URL" APP_ID="$APP_ID" LOGIN_SUB="$LOGIN_SUB" k6 run scripts/ops/load/k6-soak.js

echo "load tests completed"
