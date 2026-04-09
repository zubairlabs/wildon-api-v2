#!/usr/bin/env bash
set -euo pipefail

echo "[jwks] drill prep"
echo "1) rotate key material and set new kid in auth-service config"
echo "2) keep previous key published in JWKS during overlap window"
echo "3) deploy auth-service and validate discovery/jwks endpoints"
echo "4) verify old + new token verification"
echo "5) remove old key only after old-token TTL expires"

echo "[jwks] execute discovery sanity check if BASE_URL is provided"
BASE_URL="${BASE_URL:-}"
if [[ -n "${BASE_URL}" ]]; then
  curl -fsS "${BASE_URL}/.well-known/openid-configuration" | jq . >/dev/null
  curl -fsS "${BASE_URL}/oauth2/jwks.json" | jq . >/dev/null
  echo "[jwks] discovery/jwks endpoints reachable"
fi

echo "[jwks] drill checklist complete (manual rollout validation required)"
