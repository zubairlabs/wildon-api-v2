#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wildon}"
KUBE_CONTEXT="${KUBE_CONTEXT:-${K3S_DEPLOYER_CONTEXT:-}}"
API_HOST=""
API_BASE_URL=""
TLS_SECRET_NAME="${TLS_SECRET_NAME:-}"
CLIENT_NAME=""
SKIP_INGRESS=0
SKIP_ALLOWED_HOSTS=0
SKIP_CLIENT=0
WAIT_TIMEOUT="${WAIT_TIMEOUT:-180s}"

usage() {
  cat <<USAGE
Usage:
  $0 --api-host <host> [options]

Bootstraps regional /v1/system access on a region cluster by:
1) routing /v1/system/* on the region API host to control-service
2) allowing that host through CONTROL_ALLOWED_HOSTS
3) generating a system API client for the control dashboard

Options:
  --api-host <host>            Regional API host, e.g. api.wildon.ca
  --api-base-url <url>         Regional API base URL (default: https://<api-host>)
  --namespace <name>           Kubernetes namespace (default: wildon)
  --kube-context <name>        kubectl context to use
  --tls-secret <name>          Optional ingress TLS secret name
  --client-name <name>         Display name for the generated client
  --skip-ingress               Do not apply the regional ingress
  --skip-allowed-hosts         Do not patch control-service allowed hosts
  --skip-client                Do not generate a system API client
  --wait-timeout <duration>    Rollout wait timeout when patching control-service
  -h, --help                   Show this help

Output:
  Shell-safe KEY=VALUE lines suitable for sourcing or piping into register-region.sh
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-host)
      API_HOST="${2:-}"
      shift 2
      ;;
    --api-base-url)
      API_BASE_URL="${2:-}"
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
    --tls-secret)
      TLS_SECRET_NAME="${2:-}"
      shift 2
      ;;
    --client-name)
      CLIENT_NAME="${2:-}"
      shift 2
      ;;
    --skip-ingress)
      SKIP_INGRESS=1
      shift
      ;;
    --skip-allowed-hosts)
      SKIP_ALLOWED_HOSTS=1
      shift
      ;;
    --skip-client)
      SKIP_CLIENT=1
      shift
      ;;
    --wait-timeout)
      WAIT_TIMEOUT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$API_HOST" ] && [ -z "$API_BASE_URL" ]; then
  echo "--api-host or --api-base-url is required" >&2
  exit 1
fi

if [ -z "$API_BASE_URL" ]; then
  API_BASE_URL="https://${API_HOST}"
fi

if [ -z "$API_HOST" ]; then
  API_HOST="${API_BASE_URL#http://}"
  API_HOST="${API_HOST#https://}"
  API_HOST="${API_HOST%%/*}"
fi

if [ -z "$CLIENT_NAME" ]; then
  CLIENT_NAME="Control Dashboard (${API_HOST})"
fi

if command -v kubectl >/dev/null 2>&1; then
  KUBECTL_CMD=(kubectl)
elif command -v k3s >/dev/null 2>&1; then
  KUBECTL_CMD=(k3s kubectl)
else
  echo "kubectl is required (or k3s with embedded kubectl)" >&2
  exit 1
fi

if [ -n "$KUBE_CONTEXT" ]; then
  KUBECTL_CMD+=(--context "$KUBE_CONTEXT")
fi

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool is missing: $1" >&2
    exit 1
  fi
}

require_tool openssl
require_tool sed

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

random_hex() {
  openssl rand -hex "$1"
}

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

emit_kv() {
  printf '%s=%q\n' "$1" "$2"
}

run_sql_job() {
  local sql="$1"
  local slug="$2"

  local hash
  hash="$(printf '%s' "$sql" | sha1sum | cut -c1-10)"
  local cm_name="region-sql-${slug}-${hash}"
  local job_name="region-sql-${slug}-${hash}"
  local tmp_sql
  tmp_sql="$(mktemp)"
  printf '%s\n' "$sql" > "$tmp_sql"

  cleanup() {
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete job "$job_name" --ignore-not-found >/dev/null 2>&1 || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true
    rm -f "$tmp_sql"
  }
  trap cleanup RETURN

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete job "$job_name" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" create configmap "$cm_name" --from-file="run.sql=$tmp_sql" --dry-run=client -o yaml | "${KUBECTL_CMD[@]}" apply -f - >/dev/null

  cat <<EOF | "${KUBECTL_CMD[@]}" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: psql
          image: postgres:16-alpine
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -lc
            - psql "\$DATABASE_URL" -v ON_ERROR_STOP=1 -At -f /sql/run.sql
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: wildon-runtime-secrets
                  key: DATABASE_URL
          volumeMounts:
            - name: sql
              mountPath: /sql
              readOnly: true
      volumes:
        - name: sql
          configMap:
            name: ${cm_name}
EOF

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" wait --for=condition=complete "job/${job_name}" --timeout="$WAIT_TIMEOUT" >/dev/null
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "job/${job_name}"
}

if [ "$SKIP_INGRESS" -eq 0 ]; then
  if [ -n "$TLS_SECRET_NAME" ]; then
    cat <<EOF | "${KUBECTL_CMD[@]}" apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: regional-api-surface
  namespace: ${NAMESPACE}
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - ${API_HOST}
      secretName: ${TLS_SECRET_NAME}
  rules:
    - host: ${API_HOST}
      http:
        paths:
          - path: /v1/system
            pathType: Prefix
            backend:
              service:
                name: control-service
                port:
                  number: 8084
          - path: /
            pathType: Prefix
            backend:
              service:
                name: gateway-service
                port:
                  number: 8080
EOF
  else
    cat <<EOF | "${KUBECTL_CMD[@]}" apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: regional-api-surface
  namespace: ${NAMESPACE}
spec:
  ingressClassName: nginx
  rules:
    - host: ${API_HOST}
      http:
        paths:
          - path: /v1/system
            pathType: Prefix
            backend:
              service:
                name: control-service
                port:
                  number: 8084
          - path: /
            pathType: Prefix
            backend:
              service:
                name: gateway-service
                port:
                  number: 8080
EOF
  fi
fi

if [ "$SKIP_ALLOWED_HOSTS" -eq 0 ]; then
  allowed_hosts="${API_HOST},control-api.wildon.internal,localhost,127.0.0.1"
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" set env deployment/control-service "CONTROL_ALLOWED_HOSTS=${allowed_hosts}" >/dev/null
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" rollout status deployment/control-service --timeout="$WAIT_TIMEOUT" >/dev/null
fi

if [ "$SKIP_CLIENT" -eq 1 ]; then
  emit_kv "API_HOST" "$API_HOST"
  emit_kv "API_BASE_URL" "$API_BASE_URL"
  exit 0
fi

scopes="ARRAY['system.devices.read','system.devices.write','system.device_categories.read','system.device_categories.write','system.device_models.read','system.device_models.write']::text[]"
public_key="pk_live_$(slugify "$API_HOST")_$(random_hex 8)"
secret_key="sk_live_$(slugify "$API_HOST")_$(random_hex 16)"
secret_key_hint="••••${secret_key: -6}"
client_name_escaped="$(sql_escape "$CLIENT_NAME")"
public_key_escaped="$(sql_escape "$public_key")"
secret_key_escaped="$(sql_escape "$secret_key")"
secret_key_hint_escaped="$(sql_escape "$secret_key_hint")"
slug="$(slugify "$API_HOST")"

sql="
INSERT INTO control_app.system_api_clients
  (name, public_key, secret_key, secret_key_hint, scopes, status)
VALUES
  ('${client_name_escaped}', '${public_key_escaped}', '${secret_key_escaped}', '${secret_key_hint_escaped}', ${scopes}, 'active')
RETURNING id, public_key, secret_key_hint, array_to_string(scopes, ',');
"

result="$(run_sql_job "$sql" "$slug")"
client_id="$(printf '%s\n' "$result" | head -n1 | cut -d'|' -f1)"

emit_kv "API_HOST" "$API_HOST"
emit_kv "API_BASE_URL" "$API_BASE_URL"
emit_kv "SYSTEM_API_CLIENT_ID" "$client_id"
emit_kv "SYSTEM_API_PUBLIC_KEY" "$public_key"
emit_kv "SYSTEM_API_SECRET_KEY" "$secret_key"
emit_kv "SYSTEM_API_SECRET_KEY_HINT" "$secret_key_hint"
emit_kv "SYSTEM_API_CLIENT_NAME" "$CLIENT_NAME"
