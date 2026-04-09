#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION_CONTEXT=""
MAIN_CONTEXT=""
REGION_NAMESPACE="${REGION_NAMESPACE:-wildon}"
MAIN_NAMESPACE="${MAIN_NAMESPACE:-wildon}"
NAME=""
COUNTRY=""
COUNTRY_CODE=""
FLAG=""
CURRENCY="USD"
CURRENCY_SYMBOL="$"
TIMEZONE="UTC"
ADDRESS=""
API_HOST=""
API_BASE_URL=""
TLS_SECRET_NAME=""
DEFAULT_FLAG=0

usage() {
  cat <<USAGE
Usage:
  $0 --region-context <ctx> --main-context <ctx> --name <name> --country <country> --country-code <code> --api-host <host> [options]

One-shot helper that:
1) bootstraps /v1/system access on the regional cluster
2) generates the regional system API client keys
3) registers that region in the main control registry

Options:
  --region-context <ctx>      kubectl context for the regional cluster
  --main-context <ctx>        kubectl context for the main control cluster
  --region-namespace <name>   Namespace on the regional cluster (default: wildon)
  --main-namespace <name>     Namespace on the main cluster (default: wildon)
  --name <name>               Region display name
  --country <country>         Country name
  --country-code <code>       ISO country code
  --flag <emoji>              Optional flag emoji
  --currency <code>           Currency code (default: USD)
  --currency-symbol <sym>     Currency symbol (default: $)
  --timezone <tz>             Timezone (default: UTC)
  --address <text>            Optional address/notes
  --api-host <host>           Regional API host, e.g. api.wildon.ca
  --api-base-url <url>        Regional API base URL (default: https://<api-host>)
  --tls-secret <name>         Optional ingress TLS secret on the regional cluster
  --default                   Register this as the default region in main control
  -h, --help                  Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --region-context)
      REGION_CONTEXT="${2:-}"
      shift 2
      ;;
    --main-context)
      MAIN_CONTEXT="${2:-}"
      shift 2
      ;;
    --region-namespace)
      REGION_NAMESPACE="${2:-}"
      shift 2
      ;;
    --main-namespace)
      MAIN_NAMESPACE="${2:-}"
      shift 2
      ;;
    --name)
      NAME="${2:-}"
      shift 2
      ;;
    --country)
      COUNTRY="${2:-}"
      shift 2
      ;;
    --country-code)
      COUNTRY_CODE="${2:-}"
      shift 2
      ;;
    --flag)
      FLAG="${2:-}"
      shift 2
      ;;
    --currency)
      CURRENCY="${2:-}"
      shift 2
      ;;
    --currency-symbol)
      CURRENCY_SYMBOL="${2:-}"
      shift 2
      ;;
    --timezone)
      TIMEZONE="${2:-}"
      shift 2
      ;;
    --address)
      ADDRESS="${2:-}"
      shift 2
      ;;
    --api-host)
      API_HOST="${2:-}"
      shift 2
      ;;
    --api-base-url)
      API_BASE_URL="${2:-}"
      shift 2
      ;;
    --tls-secret)
      TLS_SECRET_NAME="${2:-}"
      shift 2
      ;;
    --default)
      DEFAULT_FLAG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

for required in REGION_CONTEXT MAIN_CONTEXT NAME COUNTRY COUNTRY_CODE; do
  if [ -z "${!required}" ]; then
    echo "missing required argument for ${required}" >&2
    usage
    exit 1
  fi
done

if [ -z "$API_HOST" ] && [ -z "$API_BASE_URL" ]; then
  echo "--api-host or --api-base-url is required" >&2
  exit 1
fi

if [ -z "$API_BASE_URL" ]; then
  API_BASE_URL="https://${API_HOST}"
fi

if [ -z "$API_HOST" ]; then
  API_HOST="${API_BASE_URL#http://}"
  API_HOST="${API_HOST#https://}"
  API_HOST="${API_HOST%%/*}"
fi

bootstrap_env="$(mktemp)"
bootstrap_args=(
  --kube-context "$REGION_CONTEXT"
  --namespace "$REGION_NAMESPACE"
  --api-host "$API_HOST"
  --api-base-url "$API_BASE_URL"
)

if [ -n "$TLS_SECRET_NAME" ]; then
  bootstrap_args+=(--tls-secret "$TLS_SECRET_NAME")
fi

cleanup() {
  rm -f "$bootstrap_env"
}
trap cleanup EXIT

"${SCRIPT_DIR}/bootstrap-region-system-access.sh" "${bootstrap_args[@]}" > "$bootstrap_env"

# shellcheck disable=SC1090
. "$bootstrap_env"

register_args=(
  --kube-context "$MAIN_CONTEXT"
  --namespace "$MAIN_NAMESPACE"
  --name "$NAME"
  --country "$COUNTRY"
  --country-code "$COUNTRY_CODE"
  --flag "$FLAG"
  --currency "$CURRENCY"
  --currency-symbol "$CURRENCY_SYMBOL"
  --timezone "$TIMEZONE"
  --address "$ADDRESS"
  --api-base-url "$API_BASE_URL"
  --public-key "$SYSTEM_API_PUBLIC_KEY"
  --secret-key "$SYSTEM_API_SECRET_KEY"
)

if [ "$DEFAULT_FLAG" -eq 1 ]; then
  register_args+=(--default)
fi

"${SCRIPT_DIR}/register-region.sh" "${register_args[@]}"

printf 'SYSTEM_API_PUBLIC_KEY=%q\n' "$SYSTEM_API_PUBLIC_KEY"
printf 'SYSTEM_API_SECRET_KEY=%q\n' "$SYSTEM_API_SECRET_KEY"
printf 'REGION_API_BASE_URL=%q\n' "$API_BASE_URL"
