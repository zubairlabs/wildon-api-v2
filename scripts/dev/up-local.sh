#!/usr/bin/env bash
set -euo pipefail

docker compose -f infra/docker/docker-compose.yml up -d

echo "waiting for yugabyte ysql to become ready..."
for _ in $(seq 1 60); do
  if docker compose -f infra/docker/docker-compose.yml exec -T yugabyte \
    ysqlsh -h yugabyte -p 5433 -U yugabyte -d yugabyte -c "SELECT 1;" >/dev/null 2>&1; then
    echo "yugabyte is ready"
    exit 0
  fi
  sleep 2
done

echo "timed out waiting for yugabyte readiness"
exit 1
