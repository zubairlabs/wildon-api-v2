#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wildon}"
KUBE_CONTEXT="${KUBE_CONTEXT:-${K3S_DEPLOYER_CONTEXT:-}}"
NAME=""
COUNTRY=""
COUNTRY_CODE=""
FLAG=""
CURRENCY="USD"
CURRENCY_SYMBOL="$"
TIMEZONE="UTC"
ADDRESS=""
API_BASE_URL=""
PUBLIC_KEY=""
SECRET_KEY=""
STATUS="ONLINE"
SERVICES='[]'

usage() {
  cat <<USAGE
Usage:
  $0 --name <name> --country <country> --country-code <code> --api-base-url <url> --public-key <pk> --secret-key <sk> [options]

Registers or updates a region in the main control registry database.

Options:
  --name <name>               Region display name
  --country <country>         Country name
  --country-code <code>       ISO country code, e.g. CA
  --flag <emoji>              Optional flag emoji
  --currency <code>           Currency code (default: USD)
  --currency-symbol <sym>     Currency symbol (default: $)
  --timezone <tz>             Timezone (default: UTC)
  --address <text>            Address/notes
  --api-base-url <url>        Regional API base URL, e.g. https://api.wildon.ca
  --public-key <pk>           Regional system API public key
  --secret-key <sk>           Regional system API secret key
  --status <status>           ONLINE | DEGRADED | OFFLINE | MAINTENANCE
  --services <json>           JSON array of services, e.g. '[{"name":"gateway","url":"https://api.wildon.com.au","port":8080}]'
  --namespace <name>          Kubernetes namespace (default: wildon)
  --kube-context <name>       kubectl context to use
  -h, --help                  Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      NAME="${2:-}"
      shift 2
      ;;
    --country)
      COUNTRY="${2:-}"
      shift 2
      ;;
    --country-code)
      COUNTRY_CODE="${2:-}"
      shift 2
      ;;
    --flag)
      FLAG="${2:-}"
      shift 2
      ;;
    --currency)
      CURRENCY="${2:-}"
      shift 2
      ;;
    --currency-symbol)
      CURRENCY_SYMBOL="${2:-}"
      shift 2
      ;;
    --timezone)
      TIMEZONE="${2:-}"
      shift 2
      ;;
    --address)
      ADDRESS="${2:-}"
      shift 2
      ;;
    --api-base-url)
      API_BASE_URL="${2:-}"
      shift 2
      ;;
    --public-key)
      PUBLIC_KEY="${2:-}"
      shift 2
      ;;
    --secret-key)
      SECRET_KEY="${2:-}"
      shift 2
      ;;
    --status)
      STATUS="${2:-}"
      shift 2
      ;;
    --services)
      SERVICES="${2:-[]}"
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

for required in NAME COUNTRY COUNTRY_CODE API_BASE_URL PUBLIC_KEY SECRET_KEY; do
  if [ -z "${!required}" ]; then
    echo "missing required argument for ${required}" >&2
    usage
    exit 1
  fi
done

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

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

emit_kv() {
  printf '%s=%q\n' "$1" "$2"
}

run_sql_job() {
  local sql="$1"
  local slug="$2"

  local hash
  hash="$(printf '%s' "$sql" | sha1sum | cut -c1-10)"
  local cm_name="region-reg-${slug}-${hash}"
  local job_name="region-reg-${slug}-${hash}"
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

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" wait --for=condition=complete "job/${job_name}" --timeout=180s >/dev/null
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "job/${job_name}"
}

slug="$(echo "$COUNTRY_CODE" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g')"
name_escaped="$(sql_escape "$NAME")"
country_escaped="$(sql_escape "$COUNTRY")"
country_code_escaped="$(sql_escape "$(printf '%s' "$COUNTRY_CODE" | tr '[:lower:]' '[:upper:]')")"
flag_escaped="$(sql_escape "$FLAG")"
currency_escaped="$(sql_escape "$CURRENCY")"
currency_symbol_escaped="$(sql_escape "$CURRENCY_SYMBOL")"
timezone_escaped="$(sql_escape "$TIMEZONE")"
address_escaped="$(sql_escape "$ADDRESS")"
api_base_url_escaped="$(sql_escape "$API_BASE_URL")"
public_key_escaped="$(sql_escape "$PUBLIC_KEY")"
secret_key_escaped="$(sql_escape "$SECRET_KEY")"
secret_key_hint_escaped="$(sql_escape "••••${SECRET_KEY: -6}")"
status_escaped="$(sql_escape "$STATUS")"
services_escaped="$(sql_escape "$SERVICES")"

sql="
DO \$\$
DECLARE
  existing_id uuid;
BEGIN
  SELECT id INTO existing_id
  FROM control_app.regions
  WHERE api_base_url = '${api_base_url_escaped}'
  ORDER BY created_at ASC
  LIMIT 1;

  IF existing_id IS NULL THEN
    INSERT INTO control_app.regions
      (display_ref, name, country, country_code, flag, currency, currency_symbol, timezone,
       address, api_base_url, public_key, secret_key, secret_key_hint, status, services)
    VALUES
      ('REG-' || upper(substr(md5(gen_random_uuid()::text), 1, 8)),
       '${name_escaped}', '${country_escaped}', '${country_code_escaped}', '${flag_escaped}',
       '${currency_escaped}', '${currency_symbol_escaped}', '${timezone_escaped}', '${address_escaped}',
       '${api_base_url_escaped}', '${public_key_escaped}', '${secret_key_escaped}',
       '${secret_key_hint_escaped}', '${status_escaped}', '${services_escaped}'::jsonb);
  ELSE
    UPDATE control_app.regions
    SET
      name = '${name_escaped}',
      country = '${country_escaped}',
      country_code = '${country_code_escaped}',
      flag = '${flag_escaped}',
      currency = '${currency_escaped}',
      currency_symbol = '${currency_symbol_escaped}',
      timezone = '${timezone_escaped}',
      address = '${address_escaped}',
      api_base_url = '${api_base_url_escaped}',
      public_key = '${public_key_escaped}',
      secret_key = '${secret_key_escaped}',
      secret_key_hint = '${secret_key_hint_escaped}',
      status = '${status_escaped}',
      services = '${services_escaped}'::jsonb,
      updated_at = NOW()
    WHERE id = existing_id;
  END IF;
END
\$\$;

SELECT id, display_ref, name, api_base_url, public_key, services
FROM control_app.regions
WHERE api_base_url = '${api_base_url_escaped}'
ORDER BY created_at ASC
LIMIT 1;
"

result="$(run_sql_job "$sql" "$slug")"
region_id="$(printf '%s\n' "$result" | tail -n1 | cut -d'|' -f1)"
display_ref="$(printf '%s\n' "$result" | tail -n1 | cut -d'|' -f2)"

emit_kv "REGION_ID" "$region_id"
emit_kv "REGION_DISPLAY_REF" "$display_ref"
emit_kv "REGION_NAME" "$NAME"
emit_kv "REGION_API_BASE_URL" "$API_BASE_URL"
