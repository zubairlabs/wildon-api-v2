# Local To GHCR To k3s Validation Plan

This plan is the required gate before any remote k3s rollout.

Execution companion:
- `docs/instructions/LOCAL_TO_K3S_EXECUTION.md` (what each script does, why it exists, and exact run commands including one-command flow).
- `docs/instructions/K3S_VPN_ACCESS_REPLICATION.md` (full replication runbook for VPN, k3s kubeconfig, RBAC, and server migration).
- `docs/instructions/DEPLOYER_GHCR_PRODUCTION_SETUP.md` (deployer context + GHCR production rollout setup).
- `docs/instructions/AUTH_IDENTITY_SECURITY_IMPLEMENTATION_PLAN.md` (feature plan for auth, OAuth/OIDC, RBAC/scope, and auth security controls).

## 1. Objective
- Build and validate everything locally first.
- Publish only validated images to GHCR.
- Deploy to k3s by image tag.
- Monitor k3s from local with authenticated, least-privilege access.

## 2. Local Validation Gate (must pass before push)

### 2.1 Bring up local infra
```bash
scripts/dev/up-local.sh
```

### 2.2 Run migrations and seeds for stateful services
```bash
scripts/dev/db-bootstrap.sh auth-service baseline
scripts/dev/db-bootstrap.sh public-service baseline
scripts/dev/db-bootstrap.sh core-service baseline
scripts/dev/db-bootstrap.sh storage-service baseline
scripts/dev/db-bootstrap.sh export-service baseline
scripts/dev/db-bootstrap.sh logs-service baseline
scripts/dev/db-bootstrap.sh platform-service baseline
scripts/dev/db-bootstrap.sh control-service baseline
```

### 2.3 Run workspace quality gate
```bash
scripts/ci/check-workspace.sh
```

### 2.4 Start services and smoke-check critical paths
Run in separate terminals:
```bash
scripts/dev/run-service.sh auth-service
scripts/dev/run-service.sh public-service
scripts/dev/run-service.sh core-service
scripts/dev/run-service.sh gateway-service
```

Smoke checks:
```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/v1/public/ping
curl -s -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"sub":"local-user"}'
```

### 2.5 Run load gate (optional per commit, required before production promotion)
```bash
scripts/ops/load/run-load-tests.sh
```

### 2.6 One-command local gate
```bash
scripts/ops/release/release-gate.sh --with-load
```

## 3. GHCR Promotion Gate

### 3.1 Recommended path
- Push commit to git remote.
- Let GitHub Actions build and publish GHCR images.
- Use produced `sha-<shortsha>` tags for deploy.

### 3.2 Manual local publish path (if needed)
```bash
GHCR_USER='<github-username>' \
GHCR_TOKEN='<ghcr-token>' \
scripts/ops/ghcr/push-all-services.sh --tag "sha-$(git rev-parse --short HEAD)"
```

## 4. k3s Deployment Gate

Bootstrap deployer context (one-time per workstation):
```bash
scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh \
  --token <deployer-token-from-admin-host> \
  --server-url https://10.10.0.1:6443 \
  --ca-file <ca.crt>
```

Use tagged image rollout:
```bash
scripts/ops/deploy-k3s.sh --tag <sha-tag> --namespace wildon --kube-context wildon-deployer
```

Rollback:
```bash
scripts/ops/deploy-k3s.sh --rollback-only --namespace wildon
```

## 5. Secure Local Access To k3s

## 5.1 Network security
- Do not expose k3s API publicly.
- Access k3s only over private network tunnel (WireGuard or Tailscale).
- Restrict API server source IPs to admin and CI runners only.

## 5.2 Authentication model
- Human operators: OIDC SSO (preferred) or short-lived kubeconfig credentials.
- Automation: dedicated service account credentials, scoped by RBAC.
- Never use cluster-admin kubeconfig for daily operations.

## 5.3 Authorization model
- `wildon-deployer`: can deploy workloads in `wildon` namespace only.
- `wildon-observer`: read-only access for pods/events/hpa/metrics.
- Apply baseline RBAC in `infra/k3s/security/rbac-access.yaml`.

## 5.4 Credential handling
- Keep kubeconfigs outside repo.
- Store credentials in secret manager.
- Rotate service-account tokens on schedule.

## 6. Secure Monitoring From Local

## 6.1 Metrics stack in k3s
- Install metrics-server.
- Install Prometheus + Grafana in `monitoring` namespace.
- Keep Prometheus private (ClusterIP only).

## 6.2 Authenticated dashboard access
- Expose Grafana via ingress + TLS + SSO (for example `oauth2-proxy`).
- Enforce role mapping in Grafana (Viewer for observer users).
- Disable anonymous Grafana access.

## 6.3 CLI monitoring from local
- Use read-only kubeconfig context:
```bash
kubectl config use-context wildon-observer
kubectl -n wildon get pods
kubectl -n wildon get hpa
kubectl top pods -n wildon
```

## 6.4 Create authenticated observer context (one-time bootstrap)
On k3s admin host:
```bash
kubectl apply -f infra/k3s/security/rbac-access.yaml
kubectl -n wildon create token wildon-observer --duration=8h
```

On local machine:
```bash
scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh \
  --token <token-from-admin-host> \
  --server-url https://10.10.0.1:6443 \
  --ca-file <ca.crt>
```

## 6.5 WireGuard access and internal tool endpoints
- VPN: WireGuard (`wg0`) with internal network `10.10.0.0/24`.
- Grafana URL (internal): `http://grafana.wildon.internal`
- ArgoCD URL (internal): `http://argocd.wildon.internal`
- kubectl API endpoint (WireGuard): `https://10.10.0.1:6443`
- Keep credentials out of git; use password manager or local secret store.

Setup helpers:
```bash
WG_PRIVATE_KEY='<your-private-key>' scripts/ops/wireguard/setup-wg0.sh
scripts/ops/wireguard/check-internal-endpoints.sh
```

If internal DNS does not resolve from VPN client:
- Ask infra to enable DNS forwarding for `*.wildon.internal` via `10.10.0.1`.
- As a temporary fallback, add static `/etc/hosts` entries.

## 6.6 Current access summary
| Service | How to access | URL/Command |
|---|---|---|
| Grafana | VPN + browser | `http://grafana.wildon.internal` |
| ArgoCD | VPN + browser | `http://argocd.wildon.internal` |
| kubectl | VPN + kubeconfig | `https://10.10.0.1:6443` |
| SSH | Public (temporary) | `ssh ubuntu@148.113.225.41` |

Kube contexts:
- `wildon-deployer` for deployments/rollouts.
- `wildon-observer` for read-only monitoring.

## 6.7 SSH hardening transition (after VPN stability window)
- Keep SSH public only during initial VPN validation period.
- Restrict SSH ingress to WireGuard network (`10.10.0.0/24`) at firewall/security-group layer.
- Disable password authentication and require SSH keys only.
- Optionally move SSH fully to private address and disable public SSH listener.
- Confirm break-glass access path before locking down.

## 7. Promotion Criteria (release checklist)
- Local infra smoke passed.
- `scripts/ci/check-workspace.sh` passed.
- Migrations and seeds successful.
- Load/soak baseline met.
- GHCR images published for target tag.
- k3s rollout healthy for all services.
- Post-deploy smoke checks passed.
- Rollback command tested for the release window.
