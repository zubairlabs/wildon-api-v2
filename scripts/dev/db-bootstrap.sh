#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <service-name> [profile]"
  exit 1
fi

service="$1"
profile="${2:-baseline}"

"$(dirname "$0")/db-migrate.sh" "$service"
"$(dirname "$0")/db-seed.sh" "$service" "$profile"
