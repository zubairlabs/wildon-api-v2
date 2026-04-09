# Regional Bring-Up

These scripts let you bring a new region online for control-dashboard access without hand-writing SQL.

## What They Do

`bootstrap-region-system-access.sh`
- applies a regional ingress so `https://<region-host>/v1/system/*` routes to `control-service`
- keeps the rest of the API host on `gateway-service`
- patches `CONTROL_ALLOWED_HOSTS` on the regional `control-service`
- generates a regional system API client in `control_app.system_api_clients`

`register-region.sh`
- registers that regional API and its keys into the main control registry in `control_app.regions`

`provision-region.sh`
- runs both steps end-to-end

## Typical Flow

1. Deploy the API stack into the new region cluster using the existing deploy flow:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/deploy-k3s.sh --kube-context wildon-ca --tag <tag>
```

2. Bootstrap `/v1/system/*` on that region and generate the system API client:

```bash
cd /home/ubuntu/wildon-api
scripts/ops/regions/bootstrap-region-system-access.sh \
  --kube-context wildon-ca \
  --api-host api.wildon.com.au
```

3. Register the region in the main control registry:

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
  --api-base-url "https://api.wildon.com.au" \
  --public-key "<SYSTEM_API_PUBLIC_KEY>" \
  --secret-key "<SYSTEM_API_SECRET_KEY>"
```

4. Or do both with one command:

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
  --api-host api.wildon.com.au
```

## Prerequisites

- DNS for the region API host points at the regional ingress
- TLS is handled already, or you pass `--tls-secret`
- the region cluster has the standard `wildon` services deployed
- the region cluster and the main cluster both have `wildon-runtime-secrets` with `DATABASE_URL`
- your kube contexts have permission to create configmaps/jobs and patch deployments

## Scope Set

The generated regional client currently gets the device phase-one scopes:

- `system.devices.read`
- `system.devices.write`
- `system.device_categories.read`
- `system.device_categories.write`
- `system.device_models.read`
- `system.device_models.write`

That matches the current server-side control dashboard implementation for devices.
