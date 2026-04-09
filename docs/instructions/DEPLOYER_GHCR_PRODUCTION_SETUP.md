# Deployer + GHCR Production Setup

Purpose:
- Configure least-privilege deployer access for k3s updates.
- Use GHCR image tags as the only deployment artifact source.
- Wire GitHub Actions to deploy with deployer-only kubeconfig.

## 1. Apply RBAC (k3s server)

Run on k3s control-plane:
```bash
sudo k3s kubectl apply -f infra/k3s/security/rbac-access.yaml
```

Verify deployer write scope:
```bash
sudo k3s kubectl auth can-i patch deployment \
  --as=system:serviceaccount:wildon:wildon-deployer \
  -n wildon
```
Expected: `yes`

## 2. Generate deployer token + CA (k3s server)

```bash
DEPLOYER_TOKEN=$(sudo k3s kubectl -n wildon create token wildon-deployer --duration=24h)
CA_B64=$(sudo k3s kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

echo "$DEPLOYER_TOKEN"
echo "$CA_B64"
```

## 3. Build deployer kubeconfig (workstation)

```bash
echo '<CA_B64>' | base64 -d > /tmp/k3s-ca.crt

scripts/ops/wireguard/render-serviceaccount-kubeconfig.sh \
  --token '<DEPLOYER_TOKEN>' \
  --ca-file /tmp/k3s-ca.crt \
  --server-url https://10.10.0.1:6443 \
  --cluster-name wildon-k3s \
  --user-name wildon-deployer \
  --context-name wildon-deployer \
  --namespace wildon \
  --output /tmp/kubeconfig.wildon-deployer.yaml \
  --print-b64
```

The printed base64 is used for GitHub secret:
- `K3S_DEPLOYER_KUBECONFIG_B64`

## 4. Configure GitHub secrets (repo settings)

Required secrets:
- `K3S_DEPLOYER_KUBECONFIG_B64`

Used by existing workflows:
- Publish images: `.github/workflows/ghcr-publish.yml`
- Deploy to k3s: `.github/workflows/deploy-k3s.yml`

## 5. GHCR production release flow

1. Push code to `main`.
2. `Publish GHCR Images` workflow publishes service images with `sha-<shortsha>` tags.
3. `Deploy To k3s` workflow deploys same tag using deployer kubeconfig.
4. If rollout fails, deployment script auto-rolls back.

Manual deployment (same model):
```bash
export TAG="sha-$(git rev-parse --short HEAD)"

GHCR_USER='<github-username>' \
GHCR_TOKEN='<ghcr-token>' \
scripts/ops/ghcr/push-all-services.sh --tag "$TAG"

scripts/ops/deploy-k3s.sh \
  --tag "$TAG" \
  --namespace wildon \
  --kube-context wildon-deployer
```

## 6. Validate deployer context (workstation)

```bash
kubectl config use-context wildon-deployer
kubectl auth can-i patch deployment -n wildon
kubectl auth can-i create secrets -n wildon
kubectl -n wildon get deploy,po,svc
```

Expected:
- patch deployment: `yes`
- create secrets: preferably `no` (tighten RBAC if `yes`)

## 7. Tightening recommendations

- Keep deployer token short-lived for manual use.
- Use separate kubeconfigs for CI deployer and human deployer.
- Use protected branches + required checks before GHCR publish/deploy.
- Keep observer context read-only and separate.
