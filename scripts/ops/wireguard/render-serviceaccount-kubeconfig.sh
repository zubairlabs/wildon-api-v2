#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${SERVER_URL:-${K3S_API_URL:-https://10.10.0.1:6443}}"
CLUSTER_NAME="${CLUSTER_NAME:-${K3S_CLUSTER_NAME:-wildon-k3s}}"
USER_NAME="${USER_NAME:-wildon-deployer}"
CONTEXT_NAME="${CONTEXT_NAME:-${K3S_DEPLOYER_CONTEXT:-wildon-deployer}}"
NAMESPACE="${NAMESPACE:-${K3S_NAMESPACE:-wildon}}"
TOKEN="${TOKEN:-}"
CA_FILE="${CA_FILE:-}"
OUTPUT_FILE="${OUTPUT_FILE:-./kubeconfig.sa.yaml}"
INSECURE_SKIP_TLS=0
PRINT_B64=0

usage() {
  cat <<USAGE
Usage:
  scripts/ops/wireguard/render-serviceaccount-kubeconfig.sh [options]

Options:
  --token <token>             Service account token (or TOKEN env)
  --ca-file <path>            CA certificate file (required unless insecure mode)
  --server-url <url>          API server URL (default: https://10.10.0.1:6443)
  --cluster-name <name>       Cluster name in kubeconfig (default: wildon-k3s)
  --user-name <name>          User name in kubeconfig (default: wildon-deployer)
  --context-name <name>       Context name in kubeconfig (default: wildon-deployer)
  --namespace <name>          Namespace (default: wildon)
  --output <path>             Output kubeconfig file (default: ./kubeconfig.sa.yaml)
  --insecure-skip-tls-verify  Skip TLS verification (temporary only)
  --print-b64                 Print base64 (single-line) for GitHub secret
  -h, --help                  Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    --ca-file)
      CA_FILE="${2:-}"
      shift 2
      ;;
    --server-url)
      SERVER_URL="${2:-}"
      shift 2
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
    --output)
      OUTPUT_FILE="${2:-}"
      shift 2
      ;;
    --insecure-skip-tls-verify)
      INSECURE_SKIP_TLS=1
      shift
      ;;
    --print-b64)
      PRINT_B64=1
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

if [ -z "$TOKEN" ]; then
  echo "token is required"
  exit 1
fi

CA_DATA_LINE=""
if [ "$INSECURE_SKIP_TLS" -eq 0 ]; then
  if [ -z "$CA_FILE" ] || [ ! -f "$CA_FILE" ]; then
    echo "valid --ca-file is required unless --insecure-skip-tls-verify is set"
    exit 1
  fi
  CA_DATA_LINE="    certificate-authority-data: $(base64 -w 0 "$CA_FILE")"
fi

cat > "$OUTPUT_FILE" <<EOF_CFG
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${SERVER_URL}
${CA_DATA_LINE}
users:
  - name: ${USER_NAME}
    user:
      token: ${TOKEN}
contexts:
  - name: ${CONTEXT_NAME}
    context:
      cluster: ${CLUSTER_NAME}
      user: ${USER_NAME}
      namespace: ${NAMESPACE}
current-context: ${CONTEXT_NAME}
EOF_CFG

if [ "$INSECURE_SKIP_TLS" -eq 1 ]; then
  # replace empty CA line with insecure flag
  sed -i '/^$/d' "$OUTPUT_FILE"
  sed -i '/server:/a\      insecure-skip-tls-verify: true' "$OUTPUT_FILE"
fi

echo "wrote kubeconfig: $OUTPUT_FILE"

if [ "$PRINT_B64" -eq 1 ]; then
  echo "--- base64 (for GitHub secret) ---"
  base64 -w 0 "$OUTPUT_FILE"
  echo
fi
