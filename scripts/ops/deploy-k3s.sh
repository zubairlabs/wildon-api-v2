#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="wildon"
REGISTRY="ghcr.io/zyrobytehq/wildon-api"
TAG=""
TIMEOUT="600s"
ROLLBACK_ONLY=0
DRY_RUN=0
SKIP_MIGRATIONS=0
KUBE_CONTEXT="${KUBE_CONTEXT:-${K3S_DEPLOYER_CONTEXT:-}}"
GHCR_PULL_SECRET="${GHCR_PULL_SECRET:-ghcr-pull-secret}"
GHCR_PULL_USER="${GHCR_PULL_USER:-${GHCR_USER:-}}"
GHCR_PULL_TOKEN="${GHCR_PULL_TOKEN:-${GHCR_TOKEN:-}}"

DEFAULT_SERVICES=(
  users-service
  api-clients-service
  billing-service
  logs-service
  storage-service
  export-service
  core-service
  auth-service
  public-service
  platform-service
  control-service
  gateway-service
)
SERVICES=("${DEFAULT_SERVICES[@]}")

STATEFUL_SERVICES=(
  auth-service
  users-service
  api-clients-service
  billing-service
  public-service
  core-service
  storage-service
  export-service
  logs-service
  platform-service
  control-service
)

usage() {
  cat <<USAGE
Usage:
  $0 --tag <ghcr_tag> [options]
  $0 --rollback-only [options]

Options:
  --tag <tag>                 GHCR image tag to deploy (e.g. sha-abc123, v1.2.3)
  --namespace <name>          Kubernetes namespace (default: wildon)
  --registry <path>           Image registry prefix (default: ghcr.io/zyrobytehq/wildon-api)
  --services <csv>            Comma-separated subset of services
  --timeout <duration>        Rollout timeout per deployment (default: 600s)
  --kube-context <name>       kubectl context to use (default: \$K3S_DEPLOYER_CONTEXT)
  --skip-migrations           Skip DB migrations before rollout
  --rollback-only             Roll back selected deployments to previous revision
  --dry-run                   Print commands without mutating cluster

Environment:
  GHCR_PULL_USER / GHCR_PULL_TOKEN
      Optional credentials to create/update namespace image pull secret (${GHCR_PULL_SECRET}).
      Falls back to GHCR_USER / GHCR_TOKEN when set.
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
    --registry)
      REGISTRY="${2:-}"
      shift 2
      ;;
    --services)
      IFS=',' read -r -a SERVICES <<< "${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT="${2:-}"
      shift 2
      ;;
    --kube-context)
      KUBE_CONTEXT="${2:-}"
      shift 2
      ;;
    --skip-migrations)
      SKIP_MIGRATIONS=1
      shift
      ;;
    --rollback-only)
      ROLLBACK_ONLY=1
      shift
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

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required"
  exit 1
fi

if [ "$ROLLBACK_ONLY" -eq 0 ] && [ -z "$TAG" ]; then
  echo "--tag is required unless --rollback-only is set"
  exit 1
fi

KUBECTL_CMD=(kubectl)
if [ -n "$KUBE_CONTEXT" ]; then
  KUBECTL_CMD+=(--context "$KUBE_CONTEXT")
fi

run() {
  echo "+ $*"
  if [ "$DRY_RUN" -eq 0 ]; then
    "$@"
  fi
}

array_contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [ "$item" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

decode_base64() {
  if base64 --help 2>&1 | grep -q -- '--decode'; then
    base64 --decode
  else
    base64 -d
  fi
}

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

run_migration_job() {
  local service="$1"
  local file="$2"
  local dollar='$'

  local file_base
  file_base="$(basename "$file" .sql)"
  local slug
  slug="$(slugify "${service}-${file_base}")"
  local hash
  hash="$(printf '%s' "$file" | sha1sum | cut -c1-10)"
  local cm_name
  cm_name="dbmig-cm-${hash}"
  local job_name
  job_name="dbmig-${slug}"
  if [ "${#job_name}" -gt 52 ]; then
    job_name="${job_name:0:52}"
  fi
  job_name="${job_name}-${hash:0:8}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "+ kubectl -n ${NAMESPACE} create configmap ${cm_name} --from-file=migration.sql=${file} --dry-run=client -o yaml | kubectl apply -f -"
    echo "+ kubectl -n ${NAMESPACE} apply -f <job ${job_name}>"
    echo "+ kubectl -n ${NAMESPACE} wait --for=condition=complete job/${job_name} --timeout=${TIMEOUT}"
    echo "+ kubectl -n ${NAMESPACE} delete job/${job_name} configmap/${cm_name} --ignore-not-found"
    return
  fi

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete job "$job_name" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" create configmap "$cm_name" --from-file="migration.sql=${file}" --dry-run=client -o yaml | "${KUBECTL_CMD[@]}" apply -f - >/dev/null

  cat <<EOF | "${KUBECTL_CMD[@]}" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: db-migration
    app.kubernetes.io/part-of: wildon
    wildon.service: ${service}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: postgres:16-alpine
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -lc
            - psql "${dollar}DATABASE_URL" -v ON_ERROR_STOP=1 -f /migration/migration.sql
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: wildon-runtime-secrets
                  key: DATABASE_URL
          volumeMounts:
            - name: migration-sql
              mountPath: /migration
              readOnly: true
      volumes:
        - name: migration-sql
          configMap:
            name: ${cm_name}
EOF

  if ! "${KUBECTL_CMD[@]}" -n "$NAMESPACE" wait --for=condition=complete "job/${job_name}" --timeout="$TIMEOUT"; then
    echo "migration job failed: ${job_name}"
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" describe job "$job_name" || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l job-name="$job_name" -o wide || true
    local pod_name
    pod_name="$("${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l job-name="$job_name" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -n "$pod_name" ]; then
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod_name" --tail=200 || true
    fi
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete job "$job_name" --ignore-not-found >/dev/null 2>&1 || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true
    exit 1
  fi

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete job "$job_name" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true
}

run_migration_deployment() {
  local service="$1"
  local file="$2"
  local dollar='$'

  local file_base
  file_base="$(basename "$file" .sql)"
  local slug
  slug="$(slugify "${service}-${file_base}")"
  local hash
  hash="$(printf '%s' "$file" | sha1sum | cut -c1-10)"
  local cm_name
  cm_name="dbmig-cm-${hash}"
  local deploy_name
  deploy_name="dbmig-${slug}"
  if [ "${#deploy_name}" -gt 52 ]; then
    deploy_name="${deploy_name:0:52}"
  fi
  deploy_name="${deploy_name}-${hash:0:8}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "+ kubectl -n ${NAMESPACE} create configmap ${cm_name} --from-file=migration.sql=${file} --dry-run=client -o yaml | kubectl apply -f -"
    echo "+ kubectl -n ${NAMESPACE} apply -f <deployment ${deploy_name}>"
    echo "+ kubectl -n ${NAMESPACE} rollout status deployment/${deploy_name} --timeout=${TIMEOUT}"
    echo "+ kubectl -n ${NAMESPACE} scale deployment/${deploy_name} --replicas=0"
    echo "+ kubectl -n ${NAMESPACE} delete deployment/${deploy_name} configmap/${cm_name} --ignore-not-found"
    return
  fi

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete deployment "$deploy_name" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" create configmap "$cm_name" --from-file="migration.sql=${file}" --dry-run=client -o yaml | "${KUBECTL_CMD[@]}" apply -f - >/dev/null

  cat <<EOF | "${KUBECTL_CMD[@]}" apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${deploy_name}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: db-migration
    app.kubernetes.io/part-of: wildon
    wildon.service: ${service}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${deploy_name}
  template:
    metadata:
      labels:
        app: ${deploy_name}
        app.kubernetes.io/name: db-migration
        app.kubernetes.io/part-of: wildon
        wildon.service: ${service}
    spec:
      restartPolicy: Always
      initContainers:
        - name: migrate
          image: postgres:16-alpine
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -lc
            - psql "${dollar}DATABASE_URL" -v ON_ERROR_STOP=1 -f /migration/migration.sql
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: wildon-runtime-secrets
                  key: DATABASE_URL
          volumeMounts:
            - name: migration-sql
              mountPath: /migration
              readOnly: true
      containers:
        - name: hold
          image: alpine:3.20
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -lc
            - sleep 3600
      volumes:
        - name: migration-sql
          configMap:
            name: ${cm_name}
EOF

  if ! "${KUBECTL_CMD[@]}" -n "$NAMESPACE" rollout status "deployment/${deploy_name}" --timeout="$TIMEOUT"; then
    echo "migration deployment failed: ${deploy_name}"
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" describe deployment "$deploy_name" || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l app="$deploy_name" -o wide || true
    local pod_name
    pod_name="$("${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l app="$deploy_name" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -n "$pod_name" ]; then
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" describe pod "$pod_name" || true
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod_name" -c migrate --tail=200 || true
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod_name" -c migrate --previous --tail=200 || true
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod_name" -c hold --tail=200 || true
    fi
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" scale deployment "$deploy_name" --replicas=0 >/dev/null 2>&1 || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete deployment "$deploy_name" --ignore-not-found >/dev/null 2>&1 || true
    "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true
    exit 1
  fi

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" scale deployment "$deploy_name" --replicas=0 >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete deployment "$deploy_name" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" delete configmap "$cm_name" --ignore-not-found >/dev/null 2>&1 || true
}

run_db_migrations() {
  if [ "$SKIP_MIGRATIONS" -eq 1 ]; then
    echo "skipping DB migrations (--skip-migrations)"
    return
  fi

  local migration_runner="jobs"
  if [ "$DRY_RUN" -eq 0 ]; then
    if ! "${KUBECTL_CMD[@]}" auth can-i create jobs.batch -n "$NAMESPACE" >/dev/null 2>&1; then
      if "${KUBECTL_CMD[@]}" auth can-i create deployment -n "$NAMESPACE" >/dev/null 2>&1; then
        migration_runner="deployments"
        echo "deployer cannot create jobs; falling back to migration deployments"
      else
        echo "current kubectl identity cannot create jobs or deployments in namespace '$NAMESPACE'"
        echo "cannot run DB migrations with current RBAC"
        exit 1
      fi
    fi
    if ! "${KUBECTL_CMD[@]}" auth can-i create configmaps -n "$NAMESPACE" >/dev/null 2>&1; then
      echo "current kubectl identity cannot create configmaps in namespace '$NAMESPACE'"
      echo "apply updated infra/k3s/security/rbac-access.yaml on the cluster control-plane"
      exit 1
    fi
    if ! "${KUBECTL_CMD[@]}" auth can-i get secret -n "$NAMESPACE" >/dev/null 2>&1; then
      echo "current kubectl identity cannot read secrets in namespace '$NAMESPACE'"
      echo "apply updated infra/k3s/security/rbac-access.yaml on the cluster control-plane"
      exit 1
    fi
    if ! "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get secret wildon-runtime-secrets >/dev/null 2>&1; then
      echo "missing required secret 'wildon-runtime-secrets' in namespace '$NAMESPACE'"
      exit 1
    fi
    if ! "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get secret wildon-runtime-secrets -o jsonpath='{.data.DATABASE_URL}' | decode_base64 >/dev/null 2>&1; then
      echo "secret 'wildon-runtime-secrets' is missing key DATABASE_URL"
      exit 1
    fi
  fi

  local selected_stateful=()
  local svc
  for svc in "${SERVICES[@]}"; do
    if array_contains "$svc" "${STATEFUL_SERVICES[@]}" && ! array_contains "$svc" "${selected_stateful[@]}"; then
      selected_stateful+=("$svc")
    fi
  done

  if [ "${#selected_stateful[@]}" -eq 0 ]; then
    echo "no stateful services selected; skipping DB migrations"
    return
  fi

  local migration_dir
  local files
  local file
  for svc in "${selected_stateful[@]}"; do
    migration_dir="services/${svc}/migrations"
    if [ ! -d "$migration_dir" ]; then
      echo "no migrations directory for ${svc}; skipping"
      continue
    fi

    files=$(find "$migration_dir" -maxdepth 1 -type f -name '*.sql' | sort || true)
    if [ -z "$files" ]; then
      echo "no migration files for ${svc}; skipping"
      continue
    fi

    echo "running migrations for ${svc}"
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      echo "applying migration: $file"
      if [ "$migration_runner" = "jobs" ]; then
        run_migration_job "$svc" "$file"
      else
        run_migration_deployment "$svc" "$file"
      fi
    done <<< "$files"
  done
}

ensure_image_pull_secret() {
  if [ -n "$GHCR_PULL_USER" ] && [ -n "$GHCR_PULL_TOKEN" ]; then
    if [ "$DRY_RUN" -eq 0 ]; then
      if ! "${KUBECTL_CMD[@]}" auth can-i create secret -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "current kubectl identity cannot create secrets in namespace '$NAMESPACE'"
        echo "apply updated infra/k3s/security/rbac-access.yaml on the cluster control-plane"
        exit 1
      fi
      if ! "${KUBECTL_CMD[@]}" auth can-i patch serviceaccount -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "current kubectl identity cannot patch serviceaccounts in namespace '$NAMESPACE'"
        echo "apply updated infra/k3s/security/rbac-access.yaml on the cluster control-plane"
        exit 1
      fi
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
      echo "+ kubectl -n ${NAMESPACE} create/apply docker-registry secret ${GHCR_PULL_SECRET} (credentials redacted)"
      echo "+ kubectl -n ${NAMESPACE} patch serviceaccount default --type merge -p '{\"imagePullSecrets\":[{\"name\":\"${GHCR_PULL_SECRET}\"}]}'"
    else
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" create secret docker-registry "$GHCR_PULL_SECRET" \
        --docker-server=ghcr.io \
        --docker-username="$GHCR_PULL_USER" \
        --docker-password="$GHCR_PULL_TOKEN" \
        --dry-run=client -o yaml | "${KUBECTL_CMD[@]}" apply -f - >/dev/null

      run "${KUBECTL_CMD[@]}" -n "$NAMESPACE" patch serviceaccount default --type merge \
        -p "{\"imagePullSecrets\":[{\"name\":\"${GHCR_PULL_SECRET}\"}]}" >/dev/null

      echo "configured image pull secret: $GHCR_PULL_SECRET"
    fi
    return
  fi

  if "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get secret "$GHCR_PULL_SECRET" >/dev/null 2>&1; then
    echo "using existing image pull secret: $GHCR_PULL_SECRET"
    return
  fi

  echo "missing GHCR image pull credentials and secret '$GHCR_PULL_SECRET' not found in namespace '$NAMESPACE'"
  echo "set GHCR_PULL_USER/GHCR_PULL_TOKEN (or GHCR_USER/GHCR_TOKEN) for deploy job, or pre-create the secret in cluster"
  exit 1
}

apply_base_manifests() {
  if "${KUBECTL_CMD[@]}" auth can-i get namespaces --quiet >/dev/null 2>&1; then
    run "${KUBECTL_CMD[@]}" apply -f infra/k3s/namespaces.yaml
  else
    echo "skipping namespace apply: current identity has no cluster-scope namespace access"
  fi

  ensure_image_pull_secret

  if "${KUBECTL_CMD[@]}" get crd scaledobjects.keda.sh >/dev/null 2>&1; then
    run "${KUBECTL_CMD[@]}" apply -f infra/k3s/deployments
  else
    echo "keda CRD not found (scaledobjects.keda.sh); skipping keda scaledobjects"
    local manifest
    for manifest in infra/k3s/deployments/*.yaml; do
      if [ "$(basename "$manifest")" = "keda-scaledobjects.yaml" ]; then
        continue
      fi
      run "${KUBECTL_CMD[@]}" apply -f "$manifest"
    done
  fi
}

rollback_services() {
  local svc
  for svc in "${SERVICES[@]}"; do
    run "${KUBECTL_CMD[@]}" -n "$NAMESPACE" rollout undo deployment/"$svc"
  done
}

print_rollout_diagnostics() {
  local svc="$1"
  echo "----- rollout diagnostics for ${svc} -----"
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get deployment "$svc" -o wide || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get rs -l app="$svc" -o wide || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l app="$svc" -o wide || true
  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" describe deployment "$svc" || true

  local pods
  pods="$("${KUBECTL_CMD[@]}" -n "$NAMESPACE" get pods -l app="$svc" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  if [ -n "$pods" ]; then
    while IFS= read -r pod; do
      [ -n "$pod" ] || continue
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" describe pod "$pod" || true
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod" --tail=200 || true
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" logs "$pod" --previous --tail=200 || true
    done <<< "$pods"
  fi

  "${KUBECTL_CMD[@]}" -n "$NAMESPACE" get events --sort-by=.metadata.creationTimestamp | tail -n 50 || true
  echo "----- end diagnostics for ${svc} -----"
}

if [ "$ROLLBACK_ONLY" -eq 1 ]; then
  rollback_services
  exit 0
fi

if [ "$DRY_RUN" -eq 0 ]; then
  if ! "${KUBECTL_CMD[@]}" auth can-i patch deployment -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "current kubectl identity cannot patch deployments in namespace '$NAMESPACE'"
    echo "use --kube-context wildon-deployer or configure K3S_DEPLOYER_CONTEXT"
    exit 1
  fi
fi

run_db_migrations
apply_base_manifests

updated_services=()
for svc in "${SERVICES[@]}"; do
  image="${REGISTRY}/${svc}:${TAG}"
  run "${KUBECTL_CMD[@]}" -n "$NAMESPACE" set image deployment/"$svc" "$svc"="$image"
  updated_services+=("$svc")

  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -n "$KUBE_CONTEXT" ]; then
      echo "+ kubectl --context ${KUBE_CONTEXT} -n ${NAMESPACE} rollout status deployment/${svc} --timeout=${TIMEOUT}"
    else
      echo "+ kubectl -n ${NAMESPACE} rollout status deployment/${svc} --timeout=${TIMEOUT}"
    fi
    continue
  fi

  if ! "${KUBECTL_CMD[@]}" -n "$NAMESPACE" rollout status deployment/"$svc" --timeout="$TIMEOUT"; then
    print_rollout_diagnostics "$svc"
    echo "rollout failed for ${svc}; starting rollback"
    for rollback_svc in "${updated_services[@]}"; do
      "${KUBECTL_CMD[@]}" -n "$NAMESPACE" rollout undo deployment/"$rollback_svc" || true
    done
    exit 1
  fi
done

echo "deployment succeeded for tag ${TAG}"
