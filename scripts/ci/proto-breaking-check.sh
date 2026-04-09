#!/usr/bin/env bash
set -euo pipefail

if ! git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
  echo "proto breaking check skipped: not enough git history"
  exit 0
fi

changed=$(git diff --name-only HEAD~1..HEAD -- crates/contracts/proto/*.proto || true)
if [ -z "$changed" ]; then
  echo "proto breaking check passed: no proto changes"
  exit 0
fi

status=0
for file in $changed; do
  if ! git show "HEAD~1:$file" >/dev/null 2>&1; then
    # New proto files are additive.
    continue
  fi

  old_pkg=$(git show "HEAD~1:$file" | sed -n 's/^package[[:space:]]\+\([^;]*\);/\1/p' | head -n1)
  new_pkg=$(sed -n 's/^package[[:space:]]\+\([^;]*\);/\1/p' "$file" | head -n1)

  if [ -z "$old_pkg" ] || [ -z "$new_pkg" ]; then
    echo "proto breaking check failed: could not parse package in $file"
    status=1
    continue
  fi

  if [ "$old_pkg" = "$new_pkg" ]; then
    removed=$(git diff --unified=0 HEAD~1..HEAD -- "$file" \
      | rg '^-\s*(rpc|message|enum|service|oneof|repeated|optional|required|map<|[A-Za-z_][A-Za-z0-9_<>]*\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[0-9]+;)' \
      | rg -v '^---' || true)

    if [ -n "$removed" ]; then
      echo "proto breaking check failed: potential breaking removals in $file without version bump"
      echo "$removed"
      status=1
    fi
  else
    old_version=$(echo "$old_pkg" | sed -n 's/.*\.v\([0-9][0-9]*\)$/\1/p')
    new_version=$(echo "$new_pkg" | sed -n 's/.*\.v\([0-9][0-9]*\)$/\1/p')

    if [ -z "$old_version" ] || [ -z "$new_version" ]; then
      echo "proto breaking check failed: invalid package version format in $file"
      status=1
      continue
    fi

    if [ "$new_version" -le "$old_version" ]; then
      echo "proto breaking check failed: package version must increase for breaking changes in $file ($old_pkg -> $new_pkg)"
      status=1
    fi
  fi
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "proto breaking checks passed"
