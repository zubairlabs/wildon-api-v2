#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <service-package-name>"
  exit 1
fi

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export APP_ENV="${APP_ENV:-${ENVIRONMENT:-development}}"
export ENVIRONMENT="${ENVIRONMENT:-$APP_ENV}"

cargo run -p "$1"
