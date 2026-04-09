#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://staging-api.wildon.local}"
CLIENT_ID="${CLIENT_ID:-wildon-web-public}"
GOOGLE_ID_TOKEN="${GOOGLE_ID_TOKEN:-}"
APPLE_ID_TOKEN="${APPLE_ID_TOKEN:-}"

if [[ -z "${GOOGLE_ID_TOKEN}" && -z "${APPLE_ID_TOKEN}" ]]; then
  echo "set GOOGLE_ID_TOKEN and/or APPLE_ID_TOKEN"
  exit 1
fi

if [[ -n "${GOOGLE_ID_TOKEN}" ]]; then
  echo "[social] validating google login flow"
  curl -fsS -X POST "${BASE_URL}/v1/auth/social/google" \
    -H "content-type: application/json" \
    -H "x-client-id: ${CLIENT_ID}" \
    -d "{
      \"id_token\":\"${GOOGLE_ID_TOKEN}\",
      \"nonce\":\"staging-google-nonce\"
    }" | jq . >/dev/null
fi

if [[ -n "${APPLE_ID_TOKEN}" ]]; then
  echo "[social] validating apple login flow"
  curl -fsS -X POST "${BASE_URL}/v1/auth/social/apple" \
    -H "content-type: application/json" \
    -H "x-client-id: ${CLIENT_ID}" \
    -d "{
      \"id_token\":\"${APPLE_ID_TOKEN}\",
      \"nonce\":\"staging-apple-nonce\"
    }" | jq . >/dev/null
fi

echo "[social] staging checks completed"
