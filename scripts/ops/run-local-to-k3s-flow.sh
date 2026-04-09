#!/usr/bin/env bash
set -euo pipefail

TAG="${TAG:-}"
NAMESPACE="${NAMESPACE:-${K3S_NAMESPACE:-wildon}}"
SERVER_URL="${SERVER_URL:-${K3S_API_URL:-https://10.10.0.1:6443}}"
KUBE_CONTEXT="${KUBE_CONTEXT:-${K3S_DEPLOYER_CONTEXT:-wildon-deployer}}"
CA_FILE="${CA_FILE:-}"
INSECURE_SKIP_TLS=0
WITH_LOAD=1

usage() {
  cat <<USAGE
Usage:
  scripts/ops/run-local-to-k3s-flow.sh [options]

Runs these steps in order:
1) WireGuard setup
2) Internal endpoint checks (Grafana/ArgoCD/k3s API)
3) Local release gate (infra + migrations/seeds + workspace checks + smoke + optional load)
4) GHCR image publish (all services)
5) Deployer context bootstrap (if needed)
6) k3s deploy by image tag
7) Observer kubeconfig bootstrap for secure monitoring

Required env vars:
  WG_PRIVATE_KEY        WireGuard client private key
  GHCR_USER             GitHub username
  GHCR_TOKEN            GHCR token with package write access
  OBSERVER_TOKEN        wildon-observer service-account token from k3s

Optional env var:
  DEPLOYER_TOKEN        wildon-deployer token; used to auto-bootstrap deployer context if missing

TLS options for bootstrap steps:
  - Pass --ca-file for secure TLS verification (recommended)
  - Or use --insecure-skip-tls-verify for temporary setup only

Options:
  --tag <tag>                   Image tag to push/deploy (default: sha-<git-short-sha>)
  --namespace <name>            k3s namespace (default: wildon)
  --kube-context <name>         kubectl context for deploy step (default: wildon-deployer)
  --server-url <url>            k3s API URL (default: https://10.10.0.1:6443)
  --ca-file <path>              CA certificate path for kubectl context bootstrap
  --insecure-skip-tls-verify    Skip TLS verification for observer context bootstrap
  --no-load-tests               Skip load tests during release gate
  -h, --help                    Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --kube-context)
      KUBE_CONTEXT="${2:-}"
      shift 2
      ;;
    --server-url)
      SERVER_URL="${2:-}"
      shift 2
      ;;
    --ca-file)
      CA_FILE="${2:-}"
      shift 2
      ;;
    --insecure-skip-tls-verify)
      INSECURE_SKIP_TLS=1
      shift
      ;;
    --no-load-tests)
      WITH_LOAD=0
      shift
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

if [ -z "${WG_PRIVATE_KEY:-}" ]; then
  echo "missing required env var: WG_PRIVATE_KEY"
  exit 1
fi
if [ -z "${GHCR_USER:-}" ]; then
  echo "missing required env var: GHCR_USER"
  exit 1
fi
if [ -z "${GHCR_TOKEN:-}" ]; then
  echo "missing required env var: GHCR_TOKEN"
  exit 1
fi
if [ -z "${OBSERVER_TOKEN:-}" ]; then
  echo "missing required env var: OBSERVER_TOKEN"
  exit 1
fi

if [ "$INSECURE_SKIP_TLS" -eq 0 ] && [ -z "$CA_FILE" ]; then
  echo "either --ca-file must be provided or --insecure-skip-tls-verify must be set"
  exit 1
fi

if [ -z "$TAG" ]; then
  if git rev-parse --short HEAD >/dev/null 2>&1; then
    TAG="sha-$(git rev-parse --short HEAD)"
  else
    echo "unable to derive tag from git; pass --tag explicitly"
    exit 1
  fi
fi

step() {
  echo
  echo "=== $1 ==="
}

step "1/7 WireGuard setup"
WG_PRIVATE_KEY="$WG_PRIVATE_KEY" scripts/ops/wireguard/setup-wg0.sh

step "2/7 Internal endpoint checks"
scripts/ops/wireguard/check-internal-endpoints.sh

step "3/7 Local release gate"
if [ "$WITH_LOAD" -eq 1 ]; then
  scripts/ops/release/release-gate.sh --with-load
else
  scripts/ops/release/release-gate.sh
fi

step "4/7 GHCR image publish"
GHCR_USER="$GHCR_USER" GHCR_TOKEN="$GHCR_TOKEN" \
  scripts/ops/ghcr/push-all-services.sh --tag "$TAG"

step "5/7 deployer context bootstrap (if needed)"
if ! kubectl config get-contexts -o name 2>/dev/null | rg -x "$KUBE_CONTEXT" >/dev/null 2>&1; then
  if [ -z "${DEPLOYER_TOKEN:-}" ]; then
    echo "deployer context '$KUBE_CONTEXT' is missing and DEPLOYER_TOKEN is not set"
    echo "either bootstrap deployer context first or provide DEPLOYER_TOKEN"
    exit 1
  fi
  if [ "$INSECURE_SKIP_TLS" -eq 1 ]; then
    scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh \
      --token "$DEPLOYER_TOKEN" \
      --server-url "$SERVER_URL" \
      --insecure-skip-tls-verify \
      --context-name "$KUBE_CONTEXT" \
      --namespace "$NAMESPACE"
  else
    scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh \
      --token "$DEPLOYER_TOKEN" \
      --server-url "$SERVER_URL" \
      --ca-file "$CA_FILE" \
      --context-name "$KUBE_CONTEXT" \
      --namespace "$NAMESPACE"
  fi
else
  echo "deployer context '$KUBE_CONTEXT' already exists; continuing"
fi

step "6/7 k3s deploy"
scripts/ops/deploy-k3s.sh --tag "$TAG" --namespace "$NAMESPACE" --kube-context "$KUBE_CONTEXT"

step "7/7 observer kubeconfig bootstrap"
if [ "$INSECURE_SKIP_TLS" -eq 1 ]; then
  scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh \
    --token "$OBSERVER_TOKEN" \
    --server-url "$SERVER_URL" \
    --insecure-skip-tls-verify
else
  scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh \
    --token "$OBSERVER_TOKEN" \
    --server-url "$SERVER_URL" \
    --ca-file "$CA_FILE"
fi

echo
printf 'Flow complete. Deployed tag: %s\n' "$TAG"
