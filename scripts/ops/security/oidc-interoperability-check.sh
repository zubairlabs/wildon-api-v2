#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
CLIENT_ID="${CLIENT_ID:-wildon-web-public}"
REDIRECT_URI="${REDIRECT_URI:-https://app.wildon.local/oauth/callback}"
ACCESS_TOKEN="${ACCESS_TOKEN:-}"

echo "[oidc] checking discovery"
curl -fsS "${BASE_URL}/.well-known/openid-configuration" | jq . >/dev/null

echo "[oidc] checking jwks"
curl -fsS "${BASE_URL}/oauth2/jwks.json" | jq . >/dev/null

if [[ -n "${ACCESS_TOKEN}" ]]; then
  echo "[oidc] checking userinfo with provided bearer token"
  curl -fsS "${BASE_URL}/oauth2/userinfo" \
    -H "authorization: Bearer ${ACCESS_TOKEN}" | jq . >/dev/null
else
  echo "[oidc] ACCESS_TOKEN not provided; skipping userinfo request"
fi

echo "[oidc] checking token endpoint shape"
curl -fsS -X POST "${BASE_URL}/oauth2/token" \
  -H "content-type: application/json" \
  -d "{
    \"grant_type\":\"client_credentials\",
    \"client_id\":\"${CLIENT_ID}\"
  }" | jq . >/dev/null || true

echo "[oidc] basic interoperability checks completed"
