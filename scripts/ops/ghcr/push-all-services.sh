#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io/zyrobytehq/wildon-api}"
PLATFORM="${PLATFORM:-linux/amd64}"
TAG="${TAG:-}"

SERVICES=(
  gateway-service
  auth-service
  users-service
  api-clients-service
  billing-service
  public-service
  platform-service
  control-service
  core-service
  storage-service
  export-service
  logs-service
)

usage() {
  cat <<USAGE
Usage:
  scripts/ops/ghcr/push-all-services.sh [options]

Required env:
  GHCR_USER
  GHCR_TOKEN

Options:
  --tag <tag>          Image tag (default: sha-<git-short-sha>)
  --registry <prefix>  Registry prefix (default: ghcr.io/zyrobytehq/wildon-api)
  --platform <target>  Build platform (default: linux/amd64)
  --services <csv>     Comma-separated service subset
  -h, --help           Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --registry)
      REGISTRY="${2:-}"
      shift 2
      ;;
    --platform)
      PLATFORM="${2:-}"
      shift 2
      ;;
    --services)
      IFS=',' read -r -a SERVICES <<< "${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [ -z "${GHCR_USER:-}" ] || [ -z "${GHCR_TOKEN:-}" ]; then
  echo "GHCR_USER and GHCR_TOKEN are required"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required"
  exit 1
fi

if [ -z "$TAG" ]; then
  if git rev-parse --short HEAD >/dev/null 2>&1; then
    TAG="sha-$(git rev-parse --short HEAD)"
  else
    echo "--tag is required when git metadata is unavailable"
    exit 1
  fi
fi

echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

for svc in "${SERVICES[@]}"; do
  image="${REGISTRY}/${svc}:${TAG}"
  echo "building and pushing ${image}"
  docker buildx build --platform "$PLATFORM" \
    -f "services/${svc}/Dockerfile" \
    -t "$image" \
    --push .
done

echo "GHCR publish complete for tag ${TAG}"
