# Regional API Bring-Up Runbook

This runbook explains how to launch Wildon API into a new region, generate the regional `/v1/system/*` API client keys, register that region in the main control registry, and make it available in the SvelteKit control dashboard.

Example regional hosts:

- `https://api.wildon.ca`
- `https://api.wildon.de`

This flow is built around the new regional control model:

- each region runs the normal Wildon API stack
- each region exposes `GET/POST/PATCH/DELETE /v1/system/*`
- the control dashboard server signs requests to each region using a regional `public_key` and `secret_key`
- the browser never receives the regional secret key

## What Gets Created

On the regional cluster:

- ingress routing for `https://<region-host>/v1/system/*` to `control-service`
- normal API routing for all other paths on the same host to `gateway-service`
- a row in `control_app.system_api_clients`

On the main control cluster:

- a row in `control_app.regions`

## Scripts

The bring-up flow uses these scripts:

- [bootstrap-region-system-access.sh](/home/ubuntu/wildon-api/scripts/ops/regions/bootstrap-region-system-access.sh)
- [register-region.sh](/home/ubuntu/wildon-api/scripts/ops/regions/register-region.sh)
- [provision-region.sh](/home/ubuntu/wildon-api/scripts/ops/regions/provision-region.sh)

## Prerequisites

Before you start, make sure:

1. The target regional cluster already has the Wildon API stack deployed.
2. DNS for the regional host points to that cluster ingress.
3. TLS is already set up for the regional host, or you know the TLS secret name to use with the ingress.
4. The regional cluster has the `wildon-runtime-secrets` secret with a valid `DATABASE_URL`.
5. You have working `kubectl` contexts for:
   - the regional cluster
   - the main control cluster
6. Your kube identity can:
   - patch deployments
   - create configmaps/jobs
   - read logs in the target namespace

Default namespace used by the scripts:

- `wildon`

## Step 1: Deploy The API Stack Into The Region

Deploy the standard stack first. Use the normal tag-based deploy flow.

```bash
cd /home/ubuntu/wildon-api
scripts/ops/deploy-k3s.sh --kube-context wildon-ca --tag <tag>
```

Replace:

- `wildon-ca` with the kube context for that region
- `<tag>` with the GHCR image tag you want to run

If you need the full release path from local -> GHCR -> k3s, see:

- [LOCAL_TO_K3S_EXECUTION.md](/home/ubuntu/wildon-api/docs/instructions/LOCAL_TO_K3S_EXECUTION.md)

## Step 2: Bootstrap Regional `/v1/system/*` Access And Generate Keys

Run the bootstrap script on the regional cluster:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/bootstrap-region-system-access.sh \
  --kube-context wildon-ca \
  --api-host api.wildon.ca
```

What this script does:

1. Applies a regional ingress:
   - `/v1/system` -> `control-service:8084`
   - `/` -> `gateway-service:8080`
2. Patches `CONTROL_ALLOWED_HOSTS` on the regional `control-service`
3. Generates a regional system API client in `control_app.system_api_clients`

The script prints shell-safe output like:

```bash
API_HOST=api.wildon.ca
API_BASE_URL=https://api.wildon.ca
SYSTEM_API_CLIENT_ID=...
SYSTEM_API_PUBLIC_KEY=pk_live_api-wildon-ca_...
SYSTEM_API_SECRET_KEY=sk_live_api-wildon-ca_...
SYSTEM_API_SECRET_KEY_HINT=...
SYSTEM_API_CLIENT_NAME=...
```

Save the `SYSTEM_API_PUBLIC_KEY` and `SYSTEM_API_SECRET_KEY`. Those are the credentials the control dashboard will use.

### Optional TLS Secret

If your ingress needs an explicit TLS secret:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/bootstrap-region-system-access.sh \
  --kube-context wildon-ca \
  --api-host api.wildon.ca \
  --tls-secret wildon-ca-api-tls
```

## Step 3: Register The Region In Main Control

Once you have the regional keys, register the region in the main control registry:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/register-region.sh \
  --kube-context wildon-main \
  --name "Wildon Canada" \
  --country "Canada" \
  --country-code "CA" \
  --flag "🇨🇦" \
  --currency "CAD" \
  --currency-symbol "$" \
  --timezone "America/Toronto" \
  --api-base-url "https://api.wildon.ca" \
  --public-key "<SYSTEM_API_PUBLIC_KEY>" \
  --secret-key "<SYSTEM_API_SECRET_KEY>"
```

This script upserts the row in `control_app.regions`.

It prints output like:

```bash
REGION_ID=...
REGION_DISPLAY_REF=REG-...
REGION_NAME=Wildon Canada
REGION_API_BASE_URL=https://api.wildon.ca
```

## Step 4: One-Command Provisioning

If you want to do the regional bootstrap and main registration in one go, use:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/provision-region.sh \
  --region-context wildon-ca \
  --main-context wildon-main \
  --name "Wildon Canada" \
  --country "Canada" \
  --country-code "CA" \
  --flag "🇨🇦" \
  --currency "CAD" \
  --currency-symbol "$" \
  --timezone "America/Toronto" \
  --api-host api.wildon.ca
```

This command:

1. bootstraps `/v1/system/*` on the regional cluster
2. generates the regional system client keys
3. registers the region in the main control registry

At the end it prints:

```bash
SYSTEM_API_PUBLIC_KEY=...
SYSTEM_API_SECRET_KEY=...
REGION_API_BASE_URL=https://api.wildon.ca
```

## Step 5: Verify The Region

### In Kubernetes

Check the regional ingress:

```bash
kubectl --context wildon-ca -n wildon get ingress regional-api-surface
```

Check that `control-service` rolled out after the host allow-list patch:

```bash
kubectl --context wildon-ca -n wildon rollout status deployment/control-service
```

### In The Main Registry

Confirm the new region exists in the main cluster:

```bash
kubectl --context wildon-main -n wildon logs job/<recent-region-reg-job>
```

Or load it through the control backend:

```bash
GET /v1/system/regions
```

### In The Control Dashboard

The control dashboard region-aware device flows load regions from:

- [routes/(app)/+layout.server.ts](/var/www/wildon-web-apps/control/src/routes/(app)/+layout.server.ts)
- [regional-system.ts](/var/www/wildon-web-apps/control/src/lib/server/regional-system.ts)

The Regions settings pages now read from the live registry:

- [+page.server.ts](/var/www/wildon-web-apps/control/src/routes/(app)/system-settings/regions/+page.server.ts)
- [[id]/+page.server.ts](/var/www/wildon-web-apps/control/src/routes/(app)/system-settings/regions/[id]/+page.server.ts)

Once the region is registered, it should appear in:

- the main region selector in the control app
- `System Settings -> Regions`

## Current Scope Set

The generated regional API client currently receives the device phase-one scopes:

- `system.devices.read`
- `system.devices.write`
- `system.device_categories.read`
- `system.device_categories.write`
- `system.device_models.read`
- `system.device_models.write`

That is enough for the current control devices implementation.

## Example: Germany

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/provision-region.sh \
  --region-context wildon-de \
  --main-context wildon-main \
  --name "Wildon Germany" \
  --country "Germany" \
  --country-code "DE" \
  --flag "🇩🇪" \
  --currency "EUR" \
  --currency-symbol "€" \
  --timezone "Europe/Berlin" \
  --api-host api.wildon.de
```

## Troubleshooting

### `control-service` rejects the host

Symptom:

- requests to `https://<region-host>/v1/system/*` fail with host validation errors

Check:

- `CONTROL_ALLOWED_HOSTS` on the regional `control-service`

Fix:

- rerun `bootstrap-region-system-access.sh`

### `regional-api-surface` ingress exists, but `/v1/system/*` still does not work

Check:

1. the ingress class is valid for that cluster
2. DNS points at the cluster ingress
3. TLS is configured correctly
4. `control-service` is healthy in the region

### Registration succeeded, but the region does not show in the control app

Check:

1. the control app is talking to the correct main control backend
2. the logged-in user has admin or superadmin access
3. the control app was restarted/rebuilt if you are serving an older build

### You want to make this the default region

Add `--default` when running:

- `register-region.sh`
- `provision-region.sh`

## Important Notes

- The secret key is stored in the main region registry and used server-side only.
- The browser should never receive the regional secret key.
- The current UI still uses shell scripts for bring-up; the “Add Region” form is not yet fully wired to create regions end to end.
- This runbook assumes the regional API host serves:
  - `/v1/system/*` from `control-service`
  - all other public API routes from `gateway-service`
