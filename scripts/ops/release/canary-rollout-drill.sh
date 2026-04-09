#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wildon}"
DEPLOYMENTS=(
  gateway-service
  auth-service
  users-service
  api-clients-service
  billing-service
)

echo "[canary] namespace=${NAMESPACE}"
echo "[canary] target deployments: ${DEPLOYMENTS[*]}"

for deployment in "${DEPLOYMENTS[@]}"; do
  echo "[canary] checking rollout status for ${deployment}"
  kubectl -n "${NAMESPACE}" rollout status deploy/"${deployment}" --timeout=120s
done

echo "[canary] smoke checks"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
curl -fsS "${BASE_URL}/health" >/dev/null
curl -fsS "${BASE_URL}/v1/public/ping" >/dev/null
curl -fsS "${BASE_URL}/.well-known/openid-configuration" >/dev/null

echo "[canary] drill passed"
