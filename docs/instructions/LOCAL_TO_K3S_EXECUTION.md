# Local To GHCR To k3s Execution Instructions

This guide is the execution layer for the Wildon deployment workflow.

Replication companion:
- `docs/instructions/K3S_VPN_ACCESS_REPLICATION.md` for re-provisioning the same access model on future servers.
- `docs/instructions/DEPLOYER_GHCR_PRODUCTION_SETUP.md` for deployer and GHCR production release setup.

Goal:
- Validate locally first.
- Publish only validated images to GHCR.
- Deploy exact image tags to k3s over WireGuard.
- Keep operations access authenticated and least-privilege.

## Script Index (What + Why + How)

| Script | What it does | Why run it | How to run |
|---|---|---|---|
| `scripts/ops/wireguard/setup-wg0.sh` | Installs `wireguard-tools` (if missing), writes `/etc/wireguard/wg0.conf`, brings tunnel up. | Required for access to internal Grafana/ArgoCD/k3s API endpoints. | `WG_PRIVATE_KEY='<key>' scripts/ops/wireguard/setup-wg0.sh` |
| `scripts/ops/wireguard/check-internal-endpoints.sh` | Checks VPN interface, internal DNS, and HTTP/API reachability (`grafana`, `argocd`, `k3s /version`). | Confirms VPN path and internal endpoint health before deployment actions. | `scripts/ops/wireguard/check-internal-endpoints.sh` |
| `scripts/ops/release/release-gate.sh` | Runs local infra bootstrap, migrations/seeds, workspace checks, smoke tests, optional load tests. | Prevents pushing broken builds or schema drift to GHCR/k3s. | `scripts/ops/release/release-gate.sh --with-load` |
| `scripts/ops/ghcr/push-all-services.sh` | Builds and pushes all service images to GHCR for one tag. | Produces immutable artifacts that k3s deploys. | `GHCR_USER=... GHCR_TOKEN=... scripts/ops/ghcr/push-all-services.sh --tag <tag>` |
| `scripts/ops/deploy-k3s.sh` | Applies manifests, sets deployment images by tag, waits rollout, rolls back on failure. | Enforces controlled promotion and safe rollback in cluster. | `scripts/ops/deploy-k3s.sh --tag <tag> --namespace wildon` |
| `scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh` | Creates deployer kubeconfig context with write checks. | Required for controlled production updates from workstation. | `scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh --token <token> --server-url https://10.10.0.1:6443 --ca-file <ca.crt>` |
| `scripts/ops/wireguard/render-serviceaccount-kubeconfig.sh` | Renders minimal service-account kubeconfig and optional base64 output. | Used to build deployer kubeconfig secret for GitHub Actions (`K3S_DEPLOYER_KUBECONFIG_B64`). | `scripts/ops/wireguard/render-serviceaccount-kubeconfig.sh --token <token> --ca-file <ca.crt> --print-b64` |
| `scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh` | Creates read-only observer kubeconfig context for k3s. | Secure monitoring access without cluster-admin credentials. | `scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh --token <token> --server-url https://10.10.0.1:6443 --ca-file <ca.crt>` |
| `scripts/ops/run-local-to-k3s-flow.sh` | Runs the full 1->7 sequence in order (includes deployer bootstrap check). | Single-command execution for repeatable releases. | See “One-command run” below. |

## Current Internal Access Model

- Grafana: `http://grafana.wildon.internal` (VPN)
- ArgoCD: `http://argocd.wildon.internal` (VPN)
- kubectl API: `https://10.10.0.1:6443` (VPN + kubeconfig)
- SSH: `ssh ubuntu@148.113.225.41` (temporary public access)

## One-command run (recommended)

Required environment variables:
- `WG_PRIVATE_KEY`
- `GHCR_USER`
- `GHCR_TOKEN`
- `OBSERVER_TOKEN`
- `DEPLOYER_TOKEN` (required if `wildon-deployer` context is not already configured)

Optional defaults from `.env`:
- `INTERNAL_GRAFANA_URL`
- `INTERNAL_ARGOCD_URL`
- `K3S_API_URL`
- `K3S_NAMESPACE`
- `K3S_CLUSTER_NAME`
- `K3S_OBSERVER_CONTEXT`
- `K3S_DEPLOYER_CONTEXT`

Recommended secure run with CA verification:
```bash
WG_PRIVATE_KEY='<wireguard-private-key>' \
GHCR_USER='<github-username>' \
GHCR_TOKEN='<ghcr-token>' \
DEPLOYER_TOKEN='<wildon-deployer-token>' \
OBSERVER_TOKEN='<wildon-observer-token>' \
scripts/ops/run-local-to-k3s-flow.sh \
  --tag "sha-$(git rev-parse --short HEAD)" \
  --namespace wildon \
  --server-url https://10.10.0.1:6443 \
  --ca-file <ca.crt>
```

If CA is not available yet (temporary only):
```bash
WG_PRIVATE_KEY='<wireguard-private-key>' \
GHCR_USER='<github-username>' \
GHCR_TOKEN='<ghcr-token>' \
DEPLOYER_TOKEN='<wildon-deployer-token>' \
OBSERVER_TOKEN='<wildon-observer-token>' \
scripts/ops/run-local-to-k3s-flow.sh \
  --tag "sha-$(git rev-parse --short HEAD)" \
  --namespace wildon \
  --server-url https://10.10.0.1:6443 \
  --insecure-skip-tls-verify
```

## Manual step-by-step run

1. `WG_PRIVATE_KEY='<private-key>' scripts/ops/wireguard/setup-wg0.sh`
2. `scripts/ops/wireguard/check-internal-endpoints.sh`
3. `scripts/ops/release/release-gate.sh --with-load`
4. `GHCR_USER='<user>' GHCR_TOKEN='<token>' scripts/ops/ghcr/push-all-services.sh --tag "sha-$(git rev-parse --short HEAD)"`
5. `scripts/ops/wireguard/bootstrap-deployer-kubeconfig.sh --token <deployer-token> --server-url https://10.10.0.1:6443 --ca-file <ca.crt>`
6. `scripts/ops/deploy-k3s.sh --tag "sha-$(git rev-parse --short HEAD)" --namespace wildon --kube-context wildon-deployer`
7. `scripts/ops/wireguard/bootstrap-observer-kubeconfig.sh --token <observer-token> --server-url https://10.10.0.1:6443 --ca-file <ca.crt>`

## Why this order matters

1. VPN first: no internal network access means all downstream operations fail.
2. Endpoint checks next: catches DNS/routing issues early.
3. Local gate before build/push: avoids publishing broken artifacts.
4. GHCR publish before deploy: k3s deploy is tag-based and should only consume existing images.
5. Deployer context before deploy: enforces least-privilege write identity.
6. Deploy uses explicit deployer context and tag-based images from GHCR.
7. Observer context last: secure post-deploy monitoring access with least privilege.

## Security notes

- Never commit tokens, private keys, or platform credentials to git.
- Prefer passing sensitive values as environment variables at runtime.
- Restrict SSH to WireGuard CIDR (`10.10.0.0/24`) after VPN stability window.
- Keep `kubectl` deploy credentials and observer credentials separate.
