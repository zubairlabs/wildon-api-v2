# Wildon Backend Architecture Blueprint

## 1. Scope and Success Criteria

This plan targets a backend that:
- Runs one codebase with a single app overlay (`app/wildon`).
- Scales from 10 users to ~1,000,000 concurrent users on the same architecture.
- Keeps app logic decoupled from infrastructure and provider choices.
- Defers major architectural change until ~5,000,000 to 10,000,000 concurrent users.

Success criteria:
- Stateless API tier with horizontal scaling.
- Strong auth/audience separation across `public`, `platform`, and `control` surfaces.
- Async/event-driven internals for heavy and non-critical paths.
- Internal service-to-service communication standardized on gRPC/protobuf contracts.
- Clear SLOs and load-shedding behavior.
- Monorepo portability: copy services/crates with minimal environment-specific edits.

## 2. Architecture Constraints

- API protocol:
  - North-south (client -> gateway): HTTP/JSON.
  - East-west (service -> service): gRPC (protobuf), required for internal RPC.
- Rust stack: `tokio` + `axum` + `tower` + `tracing` + `tonic` + `prost`.
- Deploy target: k3s/k8s for shared infra environments; local development is non-k8s.
- Default persistence:
  - YugabyteDB YSQL (Postgres-compatible) for transactional data.
  - Redis for cache, rate limiting, short-lived session state.
  - S3-compatible object storage for files and exports (Wasabi by default, provider configurable).
  - NATS JetStream for event bus (durable, replayable events).
- Every service owns its schema and data tables (no cross-service direct DB access).
- No ad-hoc internal JSON APIs between services; internal calls must use generated gRPC clients.
- Local development runs services with `cargo run` and infra with Docker Compose only (no local nginx, no local MinIO, no local Kubernetes, no local Helm).

## 3. Monorepo Contract

Root layout (as proposed) is correct and should be enforced with workspace linting.

Key portability rules:
- `app/wildon/app.toml` is the source of app-specific runtime behavior.
- No hard-coded app IDs/domains/audiences in service code.
- Service code imports `config` + app overlay at boot.
- App-specific differences use feature flags only when runtime config is insufficient.
- Internal RPC contracts are defined in `crates/contracts/proto/*.proto` and code-generated for all services.
- Internal service communication uses SDK crates (`storage-sdk`, `export-sdk`, `logs-sdk`) wrapping generated gRPC clients.
- Every stateful service owns its own `migrations/` and `seeds/` directories colocated with service code.
- Storage provider settings (endpoint, region, bucket, credentials path) are environment/config driven and never hard-coded to a single vendor.

## 4. Runtime Topology

Ingress path:
1. External LB/Ingress -> `gateway-service`.
2. `gateway-service` validates JWT, realm, audience, rate limits.
3. Gateway routes by host and path to downstream services via internal gRPC clients.

Control planes:
- `auth-service` is token issuer and session authority.
- `core-service` is business authority for plans/entitlements/usage/AI orchestration/billing webhooks.
- `storage-service`, `export-service`, `logs-service` are internal capability services.

API surface roles:
- `public-service`: end-user app endpoints.
- `platform-service`: partner/support operations.
- `control-service`: governance/admin endpoints.

Local development topology:
1. Run Rust services locally using `cargo run`.
2. Run infra locally using Docker Compose (`YugabyteDB`, `Redis`, `NATS` only).
3. Use Wasabi as the object storage endpoint.
4. Keep local environment minimal (no local ingress/controller stack).

Stateful service structure requirement:

```text
services/<service-name>/
├── src/
├── migrations/
├── seeds/
└── Dockerfile
```

## 5. Crate Boundaries and Rules

`crates/common`
- HTTP response envelopes, pagination, shared IDs/time utils.

`crates/auth`
- Claims, JWT verification/signing primitives, audience policies, auth context.
- No DB access. Pure auth logic.

`crates/middleware`
- Shared `tower`/`axum` middleware.

`crates/event-bus`
- Event envelope definitions + producer/consumer abstraction.
- Enforce idempotency headers and tracing propagation.

`crates/provider-clients`
- External vendor adapters only.
- Must expose trait-based ports so services can mock providers.

`crates/observability`
- Standard tracing config, metrics naming conventions, request correlation IDs.

`crates/contracts`
- Owns protobuf contracts for internal RPC and generated Rust code.
- Proposed layout:

```text
crates/contracts/
├── proto/
│   ├── auth.proto
│   ├── public.proto
│   ├── core.proto
│   ├── storage.proto
│   ├── export.proto
│   └── logs.proto
├── build.rs
└── Cargo.toml
```

SDK crates (`storage-sdk`, `export-sdk`, `logs-sdk`)
- Typed internal clients + retry/circuit-breaker defaults over gRPC.

## 6. Data and Consistency Model

Pattern:
- Synchronous path for user-critical reads/writes.
- Event-driven async path for side effects (notifications, analytics, cache invalidation, export generation).

Recommended approach:
- YSQL transaction (Postgres-compatible) + outbox record in same commit.
- Outbox publisher forwards to NATS JetStream.
- Consumers process events idempotently using `(event_id, consumer_name)` dedupe table.

Consistency expectations:
- User-facing writes: strong consistency at service boundary.
- Cross-service projections and analytics: eventual consistency.

## 6.5. Migration and Seed Strategy

- Database ownership is per service; migrations are never shared across services.
- Each stateful service keeps SQL or migration files under `services/<service>/migrations/`.
- Each stateful service keeps deterministic seed scripts under `services/<service>/seeds/`.
- Standard run order:
  1. Apply migrations for that service.
  2. Run baseline seeds for that service.
  3. Start service process.
- Seeds are split by environment profile:
  - `baseline` for required lookup/bootstrap data.
  - `dev` and `test` optional fixtures.
  - No demo/test fixture seeds in production.
- Migration/seeding execution should be automated by service-specific entrypoint/jobs and exposed via scripts under `scripts/dev`, `scripts/ci`, and `scripts/ops`.

## 6.6. gRPC Contract Strategy

- Package naming: `wildon.<service>.v1` (for example `wildon.com.aure.v1`).
- `v1` contracts are backward compatible; breaking changes require `v2`.
- `crates/contracts/build.rs` compiles protobufs with `tonic-build`.
- Each service:
  - Implements its own gRPC server interface.
  - Calls downstream services via generated clients or SDK wrappers.
- Every gRPC call sets deadline/timeout and propagates trace metadata.

## 6.7. Object Storage Portability Strategy

- `storage-service` is the only service that talks directly to object storage.
- Storage integration is S3 API-compatible with configurable endpoint/region/credentials.
- Initial deployment target is Wasabi (S3-compatible endpoint), configured via environment/app config.
- Migration to another S3-compatible provider must be possible without code changes in feature modules (`public-service`, `core-service`, `export-service`).
- `storage-sdk` contracts must remain provider-agnostic (object key, metadata, signed URL, TTL semantics).

## 7. Security Model

- JWT includes `sub`, `aud`, `iss`, `realm`, `roles`, `tenant/app_id`, `exp`, `jti`.
- `gateway-service` enforces signature/issuer/audience/realm before proxy.
- Services still perform defense-in-depth authorization checks.
- Internal gRPC traffic uses mTLS in production clusters.
- Secrets from k8s secrets manager; no plaintext secrets in repo.
- PII encryption at rest and in transit.
- Audit events for all control/admin operations in `logs-service`.

## 8. Scale Targets and SLOs

Primary SLO targets (start):
- Availability: 99.95% for gateway/public read APIs.
- p95 latency: < 150 ms for cached/standard reads, < 300 ms for standard writes.
- Auth/token endpoints p95: < 200 ms.
- Error budget: 0.05% monthly.

Capacity assumptions for 1M concurrent users:
- Effective active request rate target: 20k sustained RPS, 80k burst.
- Gateway and public-service must be horizontally autoscaled.
- Redis and Yugabyte YSQL scaled with read replicas/partitioning strategy from early phase.

Load-shedding policy:
- Prioritize auth, core user writes, and critical reads.
- Degrade non-critical modules (analytics, exports, secondary enrichments).
- Queue heavy jobs instead of sync execution.

## 9. Service-by-Service Build Priority

Priority order:
1. `gateway-service`
2. `auth-service`
3. `public-service`
4. `core-service`
5. `storage-service`
6. `logs-service`
7. `export-service`
8. `platform-service`
9. `control-service`

Reasoning:
- Establish security/routing/identity first.
- Deliver end-user vertical slices early.
- Add governance surfaces after core business and operational systems are stable.

## 10. Non-Negotiable Engineering Practices

- Contract-first APIs (OpenAPI per service, versioned).
- Protobuf-first internal APIs (versioned proto packages in `crates/contracts`).
- Migrations per service with rollback strategy.
- Mandatory startup/deploy ordering: migration job completes before service rollout.
- Provider portability by configuration for object storage (Wasabi now, other S3-compatible providers later).
- Local-first release discipline: validate locally first, then push to git remote, then build/publish images to GHCR, then deploy on k3s.
- Idempotency keys for external callbacks and job creation.
- Distributed tracing for every request hop.
- Structured logs only (JSON in production).
- Mandatory timeouts/retries/circuit breakers for all network calls.
- Backpressure on queue consumers.
- Canary deploy + automated rollback on SLO regressions.

## 11. Re-Architecture Triggers (5M to 10M Concurrent)

Revisit design when one or more occurs:
- Sustained >150k RPS with p95/p99 instability.
- Yugabyte YSQL write hot spots despite partitioning and read separation.
- Event bus lag exceeds SLOs despite consumer scaling.
- Cross-region latency requires active-active writes.

Likely next-step changes at that stage:
- Regional sharding by tenant/app/user geography.
- Dedicated streaming/log analytics platform.
- Partial split of `core-service` domain modules into separate services by bounded context.
