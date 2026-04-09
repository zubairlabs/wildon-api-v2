Ingress manifests for host-based surface routing.

`surfaces.yaml` routes each host directly to its owning service:
- `api.wildon.com.au` -> `gateway-service:8080`
- `platform-api.wildon.com.au` -> `platform-service:8083`
- `control-api.wildon.internal` -> `control-service:8084` (VPN/private CIDR only)

This keeps platform/control surfaces off the gateway proxy path.
