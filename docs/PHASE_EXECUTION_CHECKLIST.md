# Wildon Phase Execution Checklist

This file tracks implementation status against `COMPLETE_STRUCTURAL_PLAN.md`.

Status legend:
- `[x]` complete
- `[-]` partial/in-progress
- `[ ]` remaining

## Phase 1: Structural Foundation

- [x] Scaffold `users-service`, `api-clients-service`, `billing-service`
- [x] Scaffold `crates/rate-limit`
- [x] Scaffold `infra/security/pki`
- [x] Add required proto set and build wiring
- [x] Implement standard gRPC health protocol (`grpc.health.v1.Health`) on all internal gRPC services
- [x] Remove duplicate authoritative AuthContext model outside protobuf contracts
- [x] Core billing modules moved out of `core-service`
- [x] Workspace compiles and proto generation succeeds

## Phase 2: Data Model + Contracts Baseline

- [x] Auth/users/api-clients/billing contracts exist and compile
- [x] Auth/users/api-clients/billing migrations and seeds exist
- [x] `sv` + `perm_rev` freshness model wired in gateway/auth
- [x] Enforce users-service as strict identity source-of-truth (remove auth fallback paths)
- [x] Ensure signup/identity lifecycle writes go through `users-service`
- [x] Ensure rate-limit profile/override ownership is fully policy-driven from `api-clients-service`

## Phase 3: Core Email Auth

- [x] Gateway client validation + `X-Client-Id == token.cid` enforcement
- [x] Endpoint-level rate limiter dimensions (`user x endpoint`, `client x endpoint`)
- [x] Register + email verification OTP + login implemented (gateway + auth gRPC + migrations)
- [-] End-to-end gate requires live environment execution script evidence

## Phase 4: Password Recovery + Session Revocation

- [x] Forgot-password request/verify/reset + session revocation implemented
- [-] End-to-end gate requires live environment execution script evidence

## Phase 5: OAuth/OIDC Provider

- [-] OAuth/OIDC RPC + gateway endpoint surface implemented (`/.well-known`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/jwks.json`, `/oauth2/revoke`, `/oauth2/introspect`)
- [-] Correctness baseline wired (`state`, `nonce`, exact `redirect_uri`, PKCE `S256`, confidential client credential checks)
- [x] OIDC/JWKS drill scripts + runbook added
- [-] Live interoperability + rotation drill execution pending environment run

## Phase 6: Social Login

- [-] Google + Apple social login flow endpoints implemented (provider-account linking + token issuance path)
- [x] Staging validation runbook + script added
- [-] Provider-specific staging execution with real credentials pending

## Phase 7: RBAC + Scope + Resource Ownership

- [-] Audience/realm enforcement baseline
- [-] Gateway authorization policy middleware added (surface RBAC, third-party scope mandatory rule, high-risk MFA step-up checks)
- [-] Permission resolution model wired via Redis `(user_id, perm_rev)` permission-set lookup with scope fallback
- [x] Service-local ownership enforcement added in `public-service` via `x-auth-sub` checks
- [-] Full multi-service escalation matrix execution pending

## Phase 8: Security Hardening

- [x] Gateway endpoint limiter moved to Redis fixed-window counters with fail-open control
- [-] CORS/CSRF gateway enforcement implemented (double-submit + origin check) and pending validation tests
- [x] JSON request hardening middleware added (content-type enforcement + request body limit)
- [x] Auth abuse controls added in auth-service (login lockout + OTP request/verify limits)
- [x] Billing webhook hardening added (Stripe signature verification + replay payload mismatch rejection)
- [x] Billing subscription mutation idempotency added (`idempotency-key` metadata + hash dedupe/conflict behavior)
- [-] Final abuse simulation evidence pending

## Phase 9: Reliability and Platform Hardening

- [-] mTLS wiring + deployment rollout scaffolding implemented (service env flags, cert mounts, per-service secret naming, PKI runbook/template); live cluster drill execution pending
- [x] Backpressure/timeouts/retry policy baseline + explicit open/half-open circuit-breaker behavior on critical upstream clients
- [x] Canonical error mapping foundation + gateway translator + async event envelope trace context fields (`request_id`, `traceparent`, `producer`, `schema_version`)
- [x] Key rotation + JWKS drill runbook/script artifacts added

## Phase 10: Production Readiness

- [x] Runbooks added (canary/rollback, key rotation, social staging validation)
- [x] Observability dashboard artifacts added for auth/security + canary
- [x] Canary drill script added
- [x] Gateway Swagger docs endpoint added (`/docs`) with OpenAPI spec (`/openapi/gateway-v1.json`)
- [-] Production/staging drill execution evidence pending

## Next Focus (Current Sprint)

1. Close remaining Phase 8 validation gates:
   - Run abuse simulation against new auth lockout + OTP counters and capture evidence.
   - Add limiter/security metrics dashboards and alerts.
2. Close remaining Phase 9 gates:
   - execute SAN/cert-rotation drills in cluster and record evidence.
   - verify unauthorized mTLS caller rejection across critical RPCs in staging.
3. Close Phase 5/6/7 validation gates:
   - Run OIDC interoperability and JWKS rollover drills.
   - Validate social login with real Google/Apple provider credentials in staging.
   - Complete service-local ownership checks and privilege-escalation matrix tests.
4. Resume Phase 3 closeout:
   - Complete register + email verification OTP flows.
   - Finish end-to-end login path validation with new users-service authoritative identity flow.
