#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wildon}"
CA_CERT="${CA_CERT:-/etc/ssl/wildon-internal/ca.crt}"
CA_KEY="${CA_KEY:-/etc/ssl/wildon-internal/ca.key}"
OUT_DIR="${OUT_DIR:-/tmp/wildon-internal-grpc-tls}"
DAYS="${DAYS:-365}"
DRY_RUN=0
SERVICES_CSV=""
KUBECTL_CMD=()

DEFAULT_SERVICES=(
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
  cat <<EOF
Usage:
  $0 [options]

Options:
  --namespace <name>      Kubernetes namespace (default: wildon)
  --ca-cert <path>        Internal CA cert path (default: /etc/ssl/wildon-internal/ca.crt)
  --ca-key <path>         Internal CA private key path (default: /etc/ssl/wildon-internal/ca.key)
  --out-dir <path>        Output directory for generated cert material (default: /tmp/wildon-internal-grpc-tls)
  --days <num>            Service cert validity days (default: 365)
  --services <csv>        Comma-separated services (default: all Wildon services)
  --dry-run               Print rendered Secret manifests without applying
  -h, --help              Show help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --ca-cert)
      CA_CERT="${2:-}"
      shift 2
      ;;
    --ca-key)
      CA_KEY="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --days)
      DAYS="${2:-}"
      shift 2
      ;;
    --services)
      SERVICES_CSV="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
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

if command -v kubectl >/dev/null 2>&1; then
  KUBECTL_CMD=(kubectl)
elif command -v k3s >/dev/null 2>&1; then
  KUBECTL_CMD=(k3s kubectl)
else
  echo "kubectl is required (or k3s with embedded kubectl)"
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required"
  exit 1
fi

if [ ! -f "$CA_CERT" ]; then
  echo "missing CA cert: $CA_CERT"
  exit 1
fi

if [ ! -f "$CA_KEY" ]; then
  echo "missing CA key: $CA_KEY"
  exit 1
fi

if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
  echo "--days must be a positive integer"
  exit 1
fi

mkdir -p "$OUT_DIR"
SERIAL_FILE="$OUT_DIR/ca.srl"

SERVICES=()
if [ -n "$SERVICES_CSV" ]; then
  IFS=',' read -r -a SERVICES <<< "$SERVICES_CSV"
else
  SERVICES=("${DEFAULT_SERVICES[@]}")
fi

echo "namespace: $NAMESPACE"
echo "services: ${SERVICES[*]}"
echo "ca cert: $CA_CERT"
echo "ca key:  $CA_KEY"
echo "out dir: $OUT_DIR"
echo "dry run: $DRY_RUN"

for service in "${SERVICES[@]}"; do
  if [ -z "$service" ]; then
    continue
  fi

  service_dir="$OUT_DIR/$service"
  key_file="$service_dir/tls.key"
  csr_file="$service_dir/tls.csr"
  cert_file="$service_dir/tls.crt"
  ext_file="$service_dir/openssl-ext.cnf"
  secret_name="${service}-grpc-tls"

  mkdir -p "$service_dir"

  openssl genrsa -out "$key_file" 2048 >/dev/null 2>&1

  openssl req -new -key "$key_file" -out "$csr_file" -subj "/CN=$service" >/dev/null 2>&1

  cat > "$ext_file" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=URI:spiffe://wildon.internal/service/${service},DNS:${service},DNS:${service}.${NAMESPACE}.svc,DNS:${service}.${NAMESPACE}.svc.cluster.local
EOF

  openssl x509 -req \
    -in "$csr_file" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAserial "$SERIAL_FILE" \
    -CAcreateserial \
    -out "$cert_file" \
    -days "$DAYS" \
    -sha256 \
    -extfile "$ext_file" >/dev/null 2>&1

  create_secret_cmd=(
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" create secret generic "$secret_name"
    --from-file=ca.crt="$CA_CERT"
    --from-file=tls.crt="$cert_file"
    --from-file=tls.key="$key_file"
    --dry-run=client -o yaml
  )

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "----- $secret_name -----"
    "${create_secret_cmd[@]}"
  else
    "${create_secret_cmd[@]}" | "${KUBECTL_CMD[@]}" apply -f -
    echo "applied secret: $secret_name"
  fi
done

echo "done"
