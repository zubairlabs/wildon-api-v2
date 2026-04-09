#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-focused}"

run_focused() {
  echo "[1/2] Running focused user-settings tests"
  cargo test -p users-service -p storage-service -p gateway-service -- --nocapture

  echo "[2/2] Focused user-settings test run completed"
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
