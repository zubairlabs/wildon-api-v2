#!/usr/bin/env bash
set -euo pipefail

proto_dir="crates/contracts/proto"

if [ ! -d "$proto_dir" ]; then
  echo "missing proto directory: $proto_dir"
  exit 1
fi

if command -v rg >/dev/null 2>&1; then
  has_match() {
    rg -q "$1" "$2"
  }

  has_tab() {
    rg -q '\t' "$1"
  }
else
  has_match() {
    grep -Eq "$1" "$2"
  }

  has_tab() {
    grep -q $'\t' "$1"
  }
fi

status=0
for file in "$proto_dir"/*.proto; do
  [ -f "$file" ] || continue

  if ! has_match '^syntax[[:space:]]*=[[:space:]]*"proto3";' "$file"; then
    echo "proto lint failed: missing proto3 syntax in $file"
    status=1
  fi

  if ! has_match '^package[[:space:]]+wildon\.[a-z_]+\.v[0-9]+;' "$file"; then
    echo "proto lint failed: package must match wildon.<service>.vN in $file"
    status=1
  fi

  base="$(basename "$file")"
  if [ "$base" != "common.proto" ] && [ "$base" != "auth_context.proto" ]; then
    if ! has_match '^service[[:space:]]+[A-Za-z0-9_]+' "$file"; then
      echo "proto lint failed: missing service declaration in $file"
      status=1
    fi
  fi

  if has_tab "$file"; then
    echo "proto lint failed: tab characters are not allowed in $file"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "proto lint checks passed"
