#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${SERVER_URL:-${K3S_API_URL:-https://10.10.0.1:6443}}"
CLUSTER_NAME="${CLUSTER_NAME:-${K3S_CLUSTER_NAME:-wildon-k3s}}"
USER_NAME="${USER_NAME:-wildon-deployer}"
CONTEXT_NAME="${CONTEXT_NAME:-${K3S_DEPLOYER_CONTEXT:-wildon-deployer}}"
NAMESPACE="${NAMESPACE:-${K3S_NAMESPACE:-wildon}}"
TOKEN="${TOKEN:-}"
CA_FILE="${CA_FILE:-}"
INSECURE_SKIP_TLS=0

usage() {
  cat <<USAGE
Usage:
  scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh [options]

Options:
  --token <token>             Deployer service-account token (or set TOKEN env)
  --server-url <url>          k3s API URL (default: https://10.10.0.1:6443)
  --ca-file <path>            CA cert path for secure TLS verification
  --insecure-skip-tls-verify  Skip TLS verification (temporary only)
  --cluster-name <name>       kubeconfig cluster name (default: wildon-k3s)
  --user-name <name>          kubeconfig user name (default: wildon-deployer)
  --context-name <name>       kubeconfig context name (default: wildon-deployer)
  --namespace <name>          namespace (default: wildon)
  -h, --help                  Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token)
      TOKEN="${2:-}"
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
    --cluster-name)
      CLUSTER_NAME="${2:-}"
      shift 2
      ;;
    --user-name)
      USER_NAME="${2:-}"
      shift 2
      ;;
    --context-name)
      CONTEXT_NAME="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
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

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required"
  exit 1
fi

if [ -z "$TOKEN" ]; then
  echo "token is required (use --token or TOKEN env)"
  exit 1
fi

if [ "$INSECURE_SKIP_TLS" -eq 0 ]; then
  if [ -z "$CA_FILE" ] || [ ! -f "$CA_FILE" ]; then
    echo "valid --ca-file is required unless --insecure-skip-tls-verify is set"
    exit 1
  fi
  kubectl config set-cluster "$CLUSTER_NAME" \
    --server="$SERVER_URL" \
    --certificate-authority="$CA_FILE"
else
  echo "warning: using insecure TLS skip verify for cluster context"
  kubectl config set-cluster "$CLUSTER_NAME" \
    --server="$SERVER_URL" \
    --insecure-skip-tls-verify=true
fi

kubectl config set-credentials "$USER_NAME" --token="$TOKEN"
kubectl config set-context "$CONTEXT_NAME" \
  --cluster="$CLUSTER_NAME" \
  --user="$USER_NAME" \
  --namespace="$NAMESPACE"
kubectl config use-context "$CONTEXT_NAME"

if ! kubectl auth can-i patch deployment -n "$NAMESPACE" >/dev/null 2>&1; then
  echo "deployer context configured, but write access check failed"
  exit 1
fi

if kubectl auth can-i create secrets -n "$NAMESPACE" >/dev/null 2>&1; then
  echo "warning: deployer can create secrets; consider tightening RBAC if not required"
fi

echo "deployer context configured and write access check passed"
