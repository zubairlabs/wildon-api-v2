# Wildon Backend Implementation Roadmap

## Progress Snapshot (February 14, 2026)

- Phase 0: Complete.
- Phase 1: Complete.
- Phase 2: Complete.
- Phase 3: Complete (initial implementation delivered with gRPC contracts, storage/export services, SDK retry+deadline policies, and local smoke validation).
- Phase 4: Complete (core business modules, provider adapters, platform/control surfaces, proto governance checks, and migration rollback smoke checks).
- Phase 5: Complete (gateway realm/app/user/device rate limiting, entitlement cache + invalidation consumer, autoscaling/PDB manifests, load/soak assets, DR runbook + drill script, GHCR -> k3s rollout automation with rollback).
- Remaining phases: none in current roadmap.

## Phase 0: Workspace Foundation (Week 1)

Deliverables:
- Rust workspace root (`Cargo.toml`) with all crates/services members.
- Global linting/format config (`rustfmt.toml`, `clippy.toml`).
- `.env.example` and app overlay (`app/wildon`).
- `crates/contracts` created with base proto files:
  - `auth.proto`
  - `public.proto`
  - `core.proto`
  - `storage.proto`
  - `export.proto`
  - `logs.proto`
- `crates/contracts/build.rs` wired for `tonic-build` code generation.
- Service skeletons include `migrations/`, `seeds/`, and `Dockerfile` for each stateful service.
- Storage config contract defined (`S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`) with Wasabi defaults in examples.
- Basic CI pipeline: `fmt`, `clippy`, `test`, `build`.
- Local infra via `infra/docker/docker-compose.yml` (`YugabyteDB` YSQL, `Redis`, `NATS` only).
- Local environment excludes nginx, MinIO, Kubernetes, and Helm.

Exit criteria:
- `cargo check --workspace` passes.
- `cargo test --workspace` passes.
- Generated protobuf code builds successfully in CI.
- Service migration and seed commands can run locally for at least `auth-service`, `public-service`, and `core-service`.
- Local `storage-service` can boot using Wasabi-compatible S3 config values.
- Core services can run with `cargo run` against local Docker Compose infra.
- Local stack boots with one command.

## Phase 1: Shared Crates + Gateway/Auth Skeleton (Week 2)

Deliverables:
- `crates/common`, `config`, `errors`, `types`, `auth`, `middleware`, `observability`, `contracts`.
- `gateway-service` skeleton with host routing + health endpoints.
- `auth-service` skeleton with token issue/refresh/introspect APIs.
- gRPC server skeletons for `auth-service`, `public-service`, and `core-service`.
- JWT claims/audience/realm enforcement integrated in gateway middleware.
- gRPC client bootstrap in gateway for downstream calls.
- Service-scoped migration/seed runner scripts in `scripts/dev` and `scripts/ci`.
- CI workflow builds container images and publishes versioned tags to GHCR.

Exit criteria:
- Request with invalid `aud`/`realm` is rejected at gateway.
- Valid token can reach downstream dummy route through gRPC path.
- Trace IDs propagate across gateway -> auth-service.
- CI enforces migration-before-seed ordering for affected services.
- k3s manifests/deploy specs reference GHCR image coordinates and tags.

## Phase 2: Core Vertical Slice (Weeks 3-4)

Deliverables:
- `public-service` modules: `users`, `devices` minimal CRUD.
- `core-service` modules: `plans`, `entitlements`, `usage` minimal implementation.
- `logs-service` ingestion + append-only audit for auth/admin actions.
- `event-bus` crate + outbox pattern in one write flow.
- Protobuf contracts for implemented RPCs promoted to stable `v1` packages.
- Baseline seed sets for required lookup/config tables in `public-service` and `core-service`.

Exit criteria:
- User signup/login/profile read/update works end-to-end.
- Entitlement check is enforced on one feature-gated endpoint.
- Domain event emitted and consumed exactly-once effect (idempotent consumer behavior).
- Public/core/logs cross-service calls operate through generated gRPC clients only.
- Fresh environment bootstrap works via: migrate -> seed -> start.

## Phase 3: Storage + Export Capabilities (Weeks 5-6)

Deliverables:
- `storage-service` signed URL upload/download + metadata.
- `export-service` async job APIs (`create/status/download`) + CSV generator.
- `storage-sdk` and `export-sdk` integrated from `public-service`/`core-service`.
- `storage.proto` and `export.proto` expanded with async job and metadata contracts.
- Production-safe seed policy documented and enforced (baseline only in prod).
- Wasabi integration implemented through S3-compatible client with endpoint-based configuration (no Wasabi-only code path).

Exit criteria:
- Large file upload flow works without proxying file bytes through gateway.
- Export job runs async and writes result to storage service.
- Retry on export worker restart does not create duplicate artifacts.
- gRPC deadlines/retry policies verified for storage/export calls.
- Switching from Wasabi endpoint to another S3-compatible endpoint requires config change only and passes storage integration smoke tests.

## Phase 4: Business Modules and Provider Integrations (Weeks 7-9)

Deliverables:
- `core-service` modules: `billing_webhooks`, `notifications`, `ai`, `jobs`.
- `provider-clients` adapters for SendGrid/Twilio/FCM/Stripe/OpenAI (minimum paths).
- `platform-service` basic support/ticketing endpoints.
- `control-service` basic users/roles/feature-flags endpoints.
- Contract compatibility checks (proto lint + breaking-change checks) in CI.
- Migration rollback smoke tests for each stateful service in CI.

Exit criteria:
- Billing webhook ingestion is idempotent.
- Notification fan-out works with provider failover behavior.
- Feature flags configurable by control-service and enforced by public-service/core-service.
- No unversioned/breaking proto changes can merge without explicit version bump.

## Phase 5: Hardening for 1M Concurrent Readiness (Weeks 10-12)

Deliverables:
- Rate-limit strategy by realm/app/user/device.
- Caching strategy + `cache_invalidator` consumers.
- k8s autoscaling policies (HPA/KEDA) and PDBs.
- Load test scenarios and SLO dashboards.
- Disaster recovery runbooks and backup restore drills.
- GitHub-based release flow finalized: merge/push -> GHCR publish -> k3s rollout.

Exit criteria:
- Soak/load tests meet SLO targets at planned RPS envelope.
- No critical single point of failure in API tier.
- Recovery drill proves RTO/RPO targets.
- Deployment pipeline can promote tested GHCR tags to k3s with rollback support.

## Scaling Gates

Gate A: <= 10k concurrent
- Single region, single-node YugabyteDB YSQL, Redis, NATS cluster.
- Basic HPA and queue workers.

Gate B: ~100k concurrent
- Yugabyte scale-out/read strategy, cache-heavy read paths, partition selected high-volume tables.
- Introduce aggressive backpressure and queue prioritization.

Gate C: ~1M concurrent
- Multi-AZ production setup, dedicated ingress tier, tuned autoscaling.
- Tight SLO/error-budget operations and progressive delivery.

Gate D: 5M-10M concurrent (re-architecture checkpoint)
- Evaluate regional partitioning/sharding, active-active strategies, further domain decomposition.

## Local-First Delivery Flow

1. Develop and validate locally (`cargo check`, `cargo test`, service smoke tests).
2. Run services locally with `cargo run` and infra from Docker Compose (`YugabyteDB`, `Redis`, `NATS`).
3. Push branch to git remote (`origin`, currently `git@github.com:zyrobytehq/wildon-api.git`) after local validation.
4. GitHub Actions builds and publishes service images to GHCR.
5. k3s pulls GHCR images and rolls out manifests/deployments.
6. Promote only tested image tags; keep rollback path to previous known-good tag.

Pre-rollout plan reference:
- `docs/LOCAL_TO_K3S_VALIDATION_PLAN.md` (local test gate, GHCR promotion, secure k3s access and monitoring model).
- `infra/k3s/security/rbac-access.yaml` (least-privilege deployer/observer RBAC baseline).

## API and Data Contract Governance

Required in every phase:
- OpenAPI spec versioned per service.
- Protobuf packages versioned per service (`wildon.<service>.vN`).
- DB migrations per service (forward + rollback notes).
- Service-local seeds versioned and idempotent where possible.
- Event schema versioning (compatibility rules documented).
- Consumer-driven contract tests for SDK crates.
- Proto lint and breaking-change checks enforced in CI.
- Object storage implementation remains S3-compatible and vendor-neutral at code level.
- Deployment artifacts are image-tag driven from GHCR into k3s (no local-only build artifacts in cluster).

## First Execution Sprint (Suggested Next Build Tasks)

1. Create workspace root + all service/crate skeletons from the agreed folder tree.
2. Create `crates/contracts` with initial proto files and `build.rs` generation.
3. Add `migrations/` and `seeds/` folders to each stateful service and wire service-specific run scripts.
4. Implement storage config keys with Wasabi defaults in `.env.example` and app overlays (S3-compatible abstraction).
5. Add local Docker Compose infra (`YugabyteDB`, `Redis`, `NATS`) and local run scripts (`cargo run` services).
6. Implement `config` crate that loads base env + `app/wildon/app.toml` overlay.
7. Implement `auth` crate claims/audience model and shared JWT middleware.
8. Bring up `gateway-service` with host-router, strict auth gates, and downstream gRPC clients.
9. Add GitHub Actions workflow to publish images to GHCR and deploy tested tags to k3s.
