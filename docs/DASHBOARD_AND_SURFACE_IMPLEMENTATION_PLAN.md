# Wildon Dashboard and Surface Implementation Plan

## 1. Purpose

This document defines how dashboard functionality is implemented across Wildon services.

Primary rule:
- Do not create a generic `dashboard-service`.
- Each surface service owns its own dashboard module and response contracts.

This keeps boundaries aligned with the existing architecture:
- `public-service` owns user-facing dashboard.
- `platform-service` owns support dashboard.
- `control-service` owns admin dashboard.

## 2. Non-Negotiable Structural Decision

Dashboard ownership is surface-local:

1. `public-service/modules/dashboard`
2. `platform-service/modules/dashboard`
3. `control-service/modules/dashboard`

No cross-service DB reads are allowed.
All cross-domain data must be fetched through gRPC/NATS contracts.

## 3. Dashboard Ownership Model

## 3.1 Public Dashboard (User)

Owner:
- `public-service`

Module:
- `services/public-service/src/modules/dashboard/`

Aggregates:
- devices overview
- media stats
- subscription snapshot (via `billing-service`)
- AI usage snapshot
- trip summary

Audience/realm:
- `aud=public`
- `realm=public`

## 3.2 Platform Dashboard (Support)

Owner:
- `platform-service`

Module:
- `services/platform-service/src/modules/dashboard/`

Aggregates:
- moderation queue counts
- flagged content counts
- partner metrics summary
- support ticket status summary

Audience/realm:
- `aud=platform`
- `realm=platform`

## 3.3 Control Dashboard (Admin)

Owner:
- `control-service`

Module:
- `services/control-service/src/modules/dashboard/`

Aggregates:
- system health snapshot
- revenue/subscription metrics (via `billing-service`)
- plan metrics
- user growth
- AI usage totals
- exports summary

Audience/realm:
- `aud=control`
- `realm=control`

## 4. HTTP Endpoint Plan (Gateway-Exposed)

Gateway exposes surface-specific endpoints only:

Public:
- `GET /v1/dashboard/summary`
- `GET /v1/dashboard/widgets/:widget`

Platform:
- `GET /v1/platform/dashboard/summary`
- `GET /v1/platform/dashboard/widgets/:widget`

Control:
- `GET /v1/control/dashboard/summary`
- `GET /v1/control/dashboard/widgets/:widget`

Rules:
- no cross-surface endpoint reuse.
- all dashboard endpoints require authenticated user + `X-Client-Id`.
- route policy and audience checks remain enforced in gateway middleware.

## 5. Internal Contracts (gRPC / NATS)

## 5.1 gRPC Read Dependencies

`public-service` dashboard may call:
- `billing-service`: subscription status, entitlement/usage snapshot
- `storage-service`: optional media/storage summary

`platform-service` dashboard may call:
- `logs-service`: moderation/security event aggregates
- `core-service` or platform-owned modules for partner/support summary

`control-service` dashboard may call:
- `billing-service`: revenue, subscription, plan metrics
- `logs-service`: system/security aggregate counters
- `export-service`: export status aggregates
- `core-service`: orchestration-level aggregate KPIs

## 5.2 NATS Event Usage

Dashboards should use pre-aggregated counters where available.
Event subjects must follow versioning policy (for example `domain.event.v1`).

## 6. Data and Read Model Strategy

Do not compute expensive aggregates on every request.

Each owner service should maintain a lightweight read model:
- in-memory cache + Redis-backed cache for short TTL dashboard cards
- optional pre-aggregation table/materialized read model per surface

Recommended TTL:
- public dashboard cards: 15-60 seconds
- platform dashboard cards: 15-60 seconds
- control dashboard cards: 10-30 seconds for operational cards, 60-300 seconds for financial rollups

## 7. Security and Authorization Rules

1. Gateway checks:
- client validation
- local JWT validation
- audience/realm enforcement

2. Service checks:
- role/scope checks in service middleware
- resource-level authorization in handlers

3. Dashboard scopes:
- public: `public:read`
- platform: `platform:read`
- control: `control:read`

4. Control dashboard sensitive widgets:
- optional step-up (`amr` contains `mfa`) for widgets exposing high-risk financial/security detail.

## 8. API Contract and Swagger Requirements

All dashboard endpoints must be added to:
- `docs/openapi/gateway-v1.json`

Each endpoint must include:
- request params/query schema
- response schema
- error schema (`ErrorEnvelope`)
- security requirements (`bearerAuth` + `clientIdHeader`)

## 9. Service Implementation Tasks

## 9.1 `public-service`

- add `modules/dashboard/mod.rs`
- add dashboard DTOs and handlers
- wire routes in `services/public-service/src/routes.rs`
- connect optional billing/storage aggregates

## 9.2 `platform-service`

- add `modules/dashboard/mod.rs`
- implement support/moderation/partner aggregate handlers
- wire routes in `services/platform-service/src/routes.rs`

## 9.3 `control-service`

- add `modules/dashboard/mod.rs`
- implement admin KPI/revenue/exports/system-health handlers
- wire routes in `services/control-service/src/routes.rs`

## 9.4 `gateway-service`

- map new dashboard routes to owning surface services
- enforce existing auth/client middleware chain unchanged
- add route docs in OpenAPI

## 10. Phased Delivery Plan

## Phase D1: Contracts and Route Skeletons

Deliverables:
- dashboard route definitions per surface
- response DTO contracts
- gateway route wiring placeholders

Validation gate:
- `cargo check --workspace` passes
- routes reachable with stub responses

## Phase D2: Public Dashboard Implementation

Deliverables:
- `public-service` dashboard module with user-centric widgets
- billing snapshot integration

Validation gate:
- `/v1/dashboard/summary` returns user-scoped data
- ownership checks verified

## Phase D3: Platform Dashboard Implementation

Deliverables:
- `platform-service` dashboard module with support/moderation widgets

Validation gate:
- `/v1/platform/dashboard/summary` returns support-scoped aggregates
- unauthorized role access denied

## Phase D4: Control Dashboard Implementation

Deliverables:
- `control-service` dashboard module with financial/operational widgets

Validation gate:
- `/v1/control/dashboard/summary` returns control-scoped metrics
- audience/role/scope enforcement validated

## Phase D5: Performance and Caching Hardening

Deliverables:
- cache policy and pre-aggregation for expensive cards
- latency budget instrumentation for dashboard endpoints

Validation gate:
- p95 latency target is met under smoke load

## Phase D6: OpenAPI + Frontend Handoff

Deliverables:
- dashboard endpoints and schemas documented in OpenAPI
- frontend integration notes updated

Validation gate:
- Swagger shows all dashboard endpoints
- frontend can generate/use typed clients from `gateway-v1.json`

## 11. Acceptance Checklist

- [ ] No generic `dashboard-service` introduced.
- [ ] `public-service`, `platform-service`, `control-service` each own a dashboard module.
- [ ] Dashboard routes are surface-specific and audience-safe.
- [ ] Cross-service data access is gRPC/NATS only (no cross-DB writes/reads).
- [ ] Role/scope/resource authorization enforced in service handlers.
- [ ] Dashboard endpoints are fully documented in OpenAPI.
- [ ] Dashboard cards have cache strategy and measurable latency.
