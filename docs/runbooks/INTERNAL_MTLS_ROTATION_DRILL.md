# Internal mTLS Rotation Drill

This runbook validates internal gRPC mTLS identity enforcement and certificate rollover.

## Scope

- Services: `gateway-service`, `auth-service`, `public-service`, `core-service`, `users-service`, `api-clients-service`, `billing-service`, `logs-service`, `storage-service`, `export-service`, `platform-service`, `control-service`.
- Trust model: caller identity from certificate SAN URI.
- Required SAN format: `spiffe://wildon.internal/service/<service-name>`.

## Prerequisites

1. Internal TLS secrets exist per service (`<service>-grpc-tls`) with `ca.crt`, `tls.crt`, `tls.key`.
2. Service deployments mount `/var/run/wildon/pki`.
3. Environment flags are enabled:
   - `INTERNAL_AUTH_REQUIRE_MTLS=true`
   - `INTERNAL_TLS_REQUIRE_SERVER_TLS=true`
   - `INTERNAL_TLS_REQUIRE_CLIENT_AUTH=true`
   - `INTERNAL_TLS_CA_CERT_PATH=/var/run/wildon/pki/ca.crt`

## Drill A: Positive identity path

1. Rotate one service cert (start with `public-service`) with unchanged SAN:
   - old: `spiffe://wildon.internal/service/public-service`
   - new: same SAN, new keypair, same trusted CA chain.
2. Apply updated `public-service-grpc-tls` secret.
3. Restart `public-service` pods.
4. Verify:
   - gRPC health remains serving.
   - `gateway-service -> public-service` calls succeed.
   - No spike in `UNAUTHENTICATED`/`PERMISSION_DENIED` for internal gRPC.

## Drill B: Unauthorized caller identity

1. Issue a cert for a test pod with SAN `spiffe://wildon.internal/service/unknown-service`.
2. Attempt internal RPC to `users-service`.
3. Expected result:
   - Request denied (`PERMISSION_DENIED` or `UNAUTHENTICATED`).
   - Denial logs include caller identity and target service.

## Drill C: Trust bundle rollover

1. Add next CA to trust bundle while keeping current CA.
2. Reissue one caller cert from next CA.
3. Verify cross-service calls succeed during overlap.
4. Reissue remaining service certs.
5. Remove old CA only after all services trust and serve with new chain.

## Success Criteria

- Internal unauthenticated calls are denied.
- SAN identity mismatch is denied.
- Healthy traffic survives cert rotation without outage.
- Alerts and logs confirm expected auth behavior.

## Rollback

1. Restore previous secret versions for impacted services.
2. Restart impacted deployments.
3. Verify health and internal traffic recovery.
