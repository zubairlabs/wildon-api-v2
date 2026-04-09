Sealed secrets or secret templates go here.

## Runtime Secrets

- Template: `runtime-secrets-template.yaml`
- Secret name: `wildon-runtime-secrets`
- Required keys:
  - `DATABASE_URL` (used by `auth-service`, `control-service`)
  - `NATS_URL` (used by `api-clients-service` invalidation publish; required if strict mode enabled)
  - `SENDGRID_API_KEY` (used by `auth-service`)
  - `SENDGRID_EMAIL_FROM` (used by `auth-service`)

## Internal gRPC mTLS

- Template: `internal-grpc-tls-template.yaml`
- Create one `<service>-grpc-tls` secret per service.
- Required keys:
  - `ca.crt`
  - `tls.crt`
  - `tls.key`
- SAN URI format:
  - `spiffe://wildon.internal/service/<service-name>`

### Bootstrap Script

Use `scripts/ops/security/bootstrap-internal-grpc-tls-secrets.sh` to generate and apply all internal gRPC TLS secrets from an existing internal CA.

Example (run on k3s control-plane):

```bash
scripts/ops/security/bootstrap-internal-grpc-tls-secrets.sh \
  --namespace wildon \
  --ca-cert /etc/ssl/wildon-internal/ca.crt \
  --ca-key /etc/ssl/wildon-internal/ca.key
```

Dry-run preview:

```bash
scripts/ops/security/bootstrap-internal-grpc-tls-secrets.sh \
  --namespace wildon \
  --ca-cert /etc/ssl/wildon-internal/ca.crt \
  --ca-key /etc/ssl/wildon-internal/ca.key \
  --dry-run
```
