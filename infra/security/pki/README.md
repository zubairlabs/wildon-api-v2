# Internal mTLS PKI

This directory owns internal service mTLS lifecycle artifacts and procedures.

## Layout
- `root-ca/`: root/intermediate CA materials (never commit private keys).
- `service-certs/`: issued service certificate manifests/templates.
- `rotation/`: certificate rotation runbooks and automation scripts.

## Rules
- Internal gRPC traffic must use mTLS.
- Service identity is derived from certificate SAN URI (`spiffe://wildon.internal/service/<service-name>`).
- Certificates are short-lived and rotated automatically.

## Runbooks
- Rotation drill: `docs/runbooks/INTERNAL_MTLS_ROTATION_DRILL.md`
- K8s secret template: `infra/k3s/secrets/internal-grpc-tls-template.yaml`
