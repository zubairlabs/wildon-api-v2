# k3s VPN Access and RBAC Replication Runbook

Purpose:
- Recreate the same secure access model when moving to a new server.
- Keep Grafana/ArgoCD/kubectl internal over WireGuard.
- Preserve least-privilege access: observer (read-only) and deployer (write-limited).

Scope:
- Operator workstation setup.
- k3s control-plane setup for observer access.
- Validation checks that prove the setup is correct.

## 1. Target Access Model

- Grafana: `https://grafana.wildon.internal` over WireGuard.
- ArgoCD: `https://argocd.wildon.internal` over WireGuard.
- Kubernetes API: `https://10.10.0.1:6443` over WireGuard.
- SSH: temporarily public only during migration window, then restricted to VPN CIDR.

## 2. Prerequisites

Workstation:
- WireGuard client installed.
- `kubectl` installed.
- Repo checked out with scripts under `scripts/ops/wireguard`.

k3s control-plane:
- `sudo k3s kubectl` available.
- `wildon` namespace exists.
- RBAC manifest available at `infra/k3s/security/rbac-access.yaml`.

## 3. Workstation VPN Setup

Run on workstation:
```bash
WG_PRIVATE_KEY='<wireguard-private-key>' scripts/ops/wireguard/setup-wg0.sh
scripts/ops/wireguard/check-internal-endpoints.sh
```

Expected result:
- `wg0` interface is up.
- `grafana.wildon.internal` and `argocd.wildon.internal` resolve to internal address.
- `https://10.10.0.1:6443/version` is reachable (401 Unauthorized is acceptable before kubeconfig auth).

## 4. Apply Observer RBAC on k3s Server

Run on k3s control-plane:
```bash
sudo k3s kubectl apply -f - <<'EOF_RBAC'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: wildon-observer
  namespace: wildon
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildon-observer-role
  namespace: wildon
rules:
  - apiGroups: ["", "apps", "batch", "autoscaling", "policy", "keda.sh"]
    resources:
      - pods
      - pods/log
      - services
      - endpoints
      - events
      - deployments
      - replicasets
      - jobs
      - horizontalpodautoscalers
      - poddisruptionbudgets
      - scaledobjects
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: wildon-observer-binding
  namespace: wildon
subjects:
  - kind: ServiceAccount
    name: wildon-observer
    namespace: wildon
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: wildon-observer-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildon-observer-metrics
rules:
  - apiGroups: ["metrics.k8s.io"]
    resources: ["nodes", "pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wildon-observer-metrics-binding
subjects:
  - kind: ServiceAccount
    name: wildon-observer
    namespace: wildon
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wildon-observer-metrics
EOF_RBAC
```

## 5. Generate Observer Token and CA from k3s Server

Run on k3s control-plane:
```bash
sudo k3s kubectl -n wildon create token wildon-observer --duration=8h
sudo k3s kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}'
```

Save outputs securely:
- `OBSERVER_TOKEN`
- `CA_BASE64`

## 6. Bootstrap kubectl Context on Workstation

On workstation:
```bash
echo '<CA_BASE64>' | base64 -d > /tmp/k3s-ca.crt
scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh \
  --token '<OBSERVER_TOKEN>' \
  --server-url https://10.10.0.1:6443 \
  --ca-file /tmp/k3s-ca.crt
```

Temporary fallback (only if CA is unavailable):
```bash
scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh \
  --token '<OBSERVER_TOKEN>' \
  --server-url https://10.10.0.1:6443 \
  --insecure-skip-tls-verify
```

## 7. Validation Checklist

Run on workstation:
```bash
kubectl config current-context
kubectl cluster-info
kubectl -n wildon get pods
kubectl auth can-i get pods -n wildon
kubectl auth can-i patch deployment -n wildon
```

Expected outcomes:
- context is `wildon-observer`.
- `cluster-info` succeeds.
- namespace reads succeed (`get pods` returns list or empty list).
- `can-i get pods` is `yes`.
- `can-i patch deployment` is `no`.

## 8. Deployer Access (for production changes)

Do not use observer context for deployments.
Use a separate deployer identity with limited write access in `wildon` namespace.

Bootstrap deployer context on workstation:
```bash
scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh \
  --token '<DEPLOYER_TOKEN>' \
  --server-url https://10.10.0.1:6443 \
  --ca-file /tmp/k3s-ca.crt
```

Deployment command:
```bash
scripts/ops/deploy-k3s.sh --tag <sha-tag> --namespace wildon
```

Rollback command:
```bash
scripts/ops/deploy-k3s.sh --rollback-only --namespace wildon
```

## 9. Server Migration Procedure (new k3s server)

1. Configure WireGuard peer/routes for new server.
2. Point internal DNS records (`*.wildon.internal`) to the new internal endpoint.
3. Re-apply observer RBAC on new cluster.
4. Generate new observer token and CA.
5. Re-bootstrap kubeconfig context on workstation.
6. Run validation checklist.
7. Run deploy dry-run and smoke checks.
8. Restrict SSH to VPN CIDR after stability window.

## 10. Troubleshooting

`kubectl` hits `localhost:8080`:
- No kubeconfig context configured. Re-run bootstrap script.

`401 Unauthorized` on k3s `/version`:
- API is reachable but auth is missing or invalid. Check token/context.

`Forbidden` on `get pods`:
- Token is valid but RBAC is missing. Re-apply observer RBAC.

ArgoCD login returns redirect loops:
- Ingress/backend protocol mismatch. Validate ingress TLS/proxy headers.

CA decode errors:
- Base64 content is truncated. Re-copy full CA from server command.

## 11. Security Baseline

- Never commit tokens, private keys, or credentials.
- Keep API and dashboards internal over VPN.
- Rotate observer/deployer tokens regularly.
- Use short token durations.
- Keep observer and deployer contexts separated.
