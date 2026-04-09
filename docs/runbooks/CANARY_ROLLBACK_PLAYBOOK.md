# Canary Rollback Playbook

## Purpose
- Run production-safe canary for gateway/auth/users/api-clients/billing releases.

## Canary Plan
1. Deploy canary with 5% traffic.
2. Observe 15 minutes:
   - `http_errors_total`
   - `grpc_errors_total`
   - `security_events_total`
   - `rate_limit_blocks_total`
3. Increase to 25% for 30 minutes.
4. If stable, promote to 100%.

## Abort Conditions
- p95 latency regression > 20%.
- 5xx increase > 2x baseline.
- auth failure or refresh failure anomaly > 1.5x baseline.
- repeated `refresh_reuse_detected` or `token_sv_mismatch` spikes.

## Rollback Steps
1. Shift traffic to previous ReplicaSet.
2. Disable new feature flags.
3. Verify health endpoints and key auth flows:
   - `/health`
   - `/v1/auth/login`
   - `/v1/auth/refresh`
4. Capture incident notes and metrics snapshot.

## Post-Rollback Actions
- Open hotfix ticket.
- Attach release SHA, failed checks, and rollback timestamp.
- Schedule re-run after fix and staging proof.
