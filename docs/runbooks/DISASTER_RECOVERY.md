# Disaster Recovery Runbook

## Targets
- `RTO`: 60 minutes for API tier and critical data path.
- `RPO`: 15 minutes for transactional databases.

## Scope
This runbook covers:
- YugabyteDB YSQL backup/restore.
- Redis rebuild strategy.
- NATS stream recovery checks.
- k3s service failover and rollback.

## Preconditions
- GHCR images are published for the release tag being restored.
- k3s cluster credentials are available to the operator.
- Database access for backup/restore operations is available.
- Latest manifests in `infra/k3s` are in git.

## Backup Procedure (daily)
1. Run database backup:
   - `scripts/ops/backup-restore-drill.sh backup`
2. Store generated SQL dump in durable storage.
3. Verify backup artifact checksum and retention policy.

## Restore Drill Procedure (weekly)
1. Run full drill locally or in staging:
   - `scripts/ops/backup-restore-drill.sh drill`
2. Verify restored DB is queryable.
3. Start services against restored DB and run smoke tests.
4. Record drill result, duration, and blockers.

## Production Incident Recovery
1. Freeze deployments and announce incident status.
2. Determine blast radius:
   - API tier only.
   - Data tier corruption.
   - Messaging backlog.
3. Roll back API tier to last known good GHCR tag:
   - `scripts/ops/deploy-k3s.sh --tag <previous_tag> --namespace wildon`
4. Restore YugabyteDB from latest valid backup if data corruption is confirmed.
5. Rehydrate Redis caches by replaying read traffic and consumer jobs.
6. Validate NATS consumer lag and replay pending messages where required.
7. Run post-recovery verification:
   - health endpoints
   - auth login flow
   - profile read/write flow
   - export job create/status
8. Close incident only after SLOs return to baseline.

## Post-Incident Checklist
1. Publish timeline, root cause, and corrective actions.
2. Add a regression test/load scenario for the failure mode.
3. Update this runbook with observed gaps.
