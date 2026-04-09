#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-focused}"

run_focused() {
  echo "[1/2] Running focused API-client related tests"
  cargo test -p api-clients-service -p gateway-service -p control-service -- --nocapture

  echo "[2/2] Focused test run completed"
  echo "Note: this validates current automated tests; matrix integration tests can be added later under scripts/tests/api-clients/."
}

run_workspace() {
  echo "[1/1] Running full workspace tests"
  cargo test --workspace -- --nocapture
}

case "$MODE" in
  focused)
    run_focused
    ;;
  workspace)
    run_workspace
    ;;
  *)
    echo "usage: $0 [focused|workspace]"
    exit 1
    ;;
esac
