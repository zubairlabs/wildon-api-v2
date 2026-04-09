#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings -A clippy::result_large_err -A clippy::too_many_arguments -A clippy::collapsible_match
cargo test --workspace
cargo build --workspace
scripts/ci/proto-lint.sh
scripts/ci/proto-breaking-check.sh
scripts/ci/verify-db-bootstrap.sh
scripts/ci/enforce-migration-before-seed.sh
scripts/ci/smoke-migration-rollbacks.sh
