# Wildon Endpoint Ownership and Communication Plan (Phases 3 and 4)

This document defines where endpoints live, which service owns business logic, and how services communicate while implementing:
- Phase 3: Core Email Auth
- Phase 4: Password Recovery + Session Revocation

It is aligned with `COMPLETE_STRUCTURAL_PLAN.md` and current workspace structure.

## 1. Endpoint Residency Rules

1. External client-facing APIs live at the edge in `gateway-service` HTTP routes.
2. Business capabilities live in service-owned gRPC APIs (`crates/contracts/proto/*.proto`).
3. Cross-service synchronous calls are gRPC only.
4. Service HTTP routes are not public contracts; keep them for health/internal operations only.
5. Gateway must remain the single public ingress for auth, user, platform, and control surfaces.

## 2. Service Responsibilities (Auth-Critical)

- `gateway-service`
  - Owns HTTP endpoint contract exposed to apps/web clients.
  - Enforces client identity, JWT checks, audience/realm checks, rate limits, and CSRF/CORS policy.
  - Translates HTTP requests to gRPC requests.

- `auth-service`
  - Owns credentials, OTP, sessions, refresh tokens, password reset, token issuance.
  - Calls `users-service` for authoritative identity/role/perm state.
  - Emits security/audit events.

- `users-service`
  - Owns user identity state (`status`, `roles`, `perm_rev`).
  - No password/session/token logic.

- `api-clients-service`
  - Owns `client_id` policy, status, audience constraints, rate-limit profiles.
  - Validated by gateway before auth/user logic.

- `logs-service`
  - Receives structured security and audit events.

## 3. External HTTP Endpoint Map (Gateway)

## 3.1 Already implemented

- `GET /health` -> gateway local health.
- `GET /v1/public/ping` -> gateway local ping.
- `POST /v1/auth/login` -> `auth-service.IssueToken`.
- `POST /v1/users/signup` -> `public-service.Signup`.
- `GET /v1/users/me` -> `public-service.GetProfile`.
- `PATCH /v1/users/me` -> `public-service.UpdateProfile`.
- `POST /v1/devices` -> `public-service.CreateDevice`.
- `GET /v1/devices` -> `public-service.ListDevices`.
- `POST /v1/media/upload-ticket` -> `public-service.CreateMediaUploadTicket`.
- `POST /v1/exports` -> `public-service.CreateExportJob`.
- `GET /v1/exports/:job_id` -> `public-service.GetExportJob`.

## 3.2 Phase 3 endpoints to add

- `POST /v1/auth/register`
- `POST /v1/auth/verify-email/request`
- `POST /v1/auth/verify-email/confirm`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`

## 3.3 Phase 4 endpoints to add

- `POST /v1/auth/password/forgot/request`
- `POST /v1/auth/password/forgot/verify`
- `POST /v1/auth/password/reset`

## 4. Internal gRPC Contract Map

## 4.1 Existing gRPC ownership

- `auth.proto`
  - `Health`
  - `IssueToken`
  - `ValidateAccessToken`

- `users.proto`
  - `CreateUser`
  - `GetUserAuthState`
  - `UpdateUserRoles`
  - `DisableUser`
  - `BumpPermRevision`

- `api_clients.proto`
  - `ValidateClient`
  - `GetClientPolicy`
  - `UpsertClient`
  - `SetClientStatus`

- `public.proto`
  - profile/device/media/export user-facing RPCs

- `billing.proto`
  - entitlement/usage/subscription/webhook RPCs

## 4.2 Auth gRPC expansions required for Phases 3 and 4

Add to `auth.proto` (service-owned by `auth-service`):

- Phase 3
  - `RegisterUser`
  - `RequestEmailVerificationOtp`
  - `ConfirmEmailVerificationOtp`
  - `RefreshToken`
  - `LogoutSession`

- Phase 4
  - `RequestPasswordResetOtp`
  - `VerifyPasswordResetOtp`
  - `ResetPassword`

Gateway calls these RPCs directly and maps request/response to HTTP.

## 5. Communication Sequences

## 5.1 Register flow

1. Client -> Gateway `POST /v1/auth/register` with `X-Client-Id`.
2. Gateway validates client policy and rate-limit dimensions.
3. Gateway calls `auth-service.RegisterUser`.
4. `auth-service` normalizes email, hashes password, stores pending user credential state.
5. `auth-service` calls `users-service.CreateUser` for identity record.
6. `auth-service` issues verification OTP (hashed + TTL) and dispatches email provider adapter.
7. Gateway returns generic anti-enumeration-safe response.

## 5.2 Email verify flow

1. Client -> Gateway `POST /v1/auth/verify-email/request` then `/confirm`.
2. Gateway calls corresponding auth gRPC methods.
3. `auth-service` validates hashed OTP, retries, expiry, one-time semantics.
4. On success, marks email verified and emits lifecycle/audit events.

## 5.3 Login/refresh/logout flow

1. Login stays at gateway `POST /v1/auth/login` -> `auth-service.IssueToken`.
2. Refresh endpoint `POST /v1/auth/refresh` -> new `auth-service.RefreshToken`.
3. Logout endpoint `POST /v1/auth/logout` -> `auth-service.LogoutSession`.
4. Gateway enforces `X-Client-Id == token.cid` for authenticated requests.

## 5.4 Forgot-password flow

1. Client -> Gateway forgot request/verify/reset endpoints.
2. Gateway calls auth gRPC methods for forgot/reset lifecycle.
3. `auth-service` validates OTP policy and resets password hash.
4. `auth-service` revokes session family + refresh chain, increments `session_version`.
5. Subsequent old tokens fail on freshness checks (`sv` mismatch).

## 6. Gateway Middleware Policy for New Endpoints

When adding auth endpoints, update bypass/auth behavior in gateway middleware:

- Unauthenticated endpoints:
  - `/v1/auth/register`
  - `/v1/auth/verify-email/request`
  - `/v1/auth/verify-email/confirm`
  - `/v1/auth/login`
  - `/v1/auth/refresh`
  - `/v1/auth/password/forgot/request`
  - `/v1/auth/password/forgot/verify`
  - `/v1/auth/password/reset`

- Authenticated endpoint:
  - `/v1/auth/logout`

`client_identity` and rate limiting still apply to all non-bypass paths.

## 7. File-Level Implementation Plan

## 7.1 Contracts

- `crates/contracts/proto/auth.proto`
  - add Phase 3 and Phase 4 RPCs/messages.

- `crates/contracts/build.rs`
  - ensure proto generation includes updated auth proto definitions.

## 7.2 Gateway

- `services/gateway-service/src/routes.rs`
  - add new HTTP handlers for Phase 3 and 4 endpoints.
  - map handlers to new auth gRPC methods.

- `services/gateway-service/src/middleware/jwt_validate.rs`
  - extend public-path allowlist for unauthenticated auth flows.

- `services/gateway-service/src/middleware/realm_enforce.rs`
  - align bypass list with unauthenticated auth flows.

- `services/gateway-service/src/middleware/rate_limit.rs`
  - ensure route template keys exist for all new endpoints.

## 7.3 Auth service

- `services/auth-service/src/main.rs`
  - implement new auth gRPC methods.

- `services/auth-service/src/modules/`
  - add/extend modules for registration, email verification OTP, forgot-password, reset, logout/refresh semantics.

- `services/auth-service/src/state.rs`
  - add repositories/config for OTP, password reset, session revocation, audit emission.

## 7.4 Users and logs integration

- `services/users-service`
  - keep `CreateUser` + `GetUserAuthState` as required dependencies for auth lifecycle.

- `services/logs-service`
  - consume security/auth lifecycle events with request and trace context.

## 8. Execution Order Before Coding Phase 3/4

1. Freeze external HTTP contract in gateway for Phase 3 and 4 routes.
2. Freeze auth gRPC contract additions in `auth.proto`.
3. Regenerate contracts and compile workspace.
4. Implement gateway handlers and middleware path policy updates.
5. Implement auth-service gRPC handlers and module logic.
6. Add integration tests for each auth flow.
7. Validate with phase gate:
  - register/verify/login pass
  - forgot/reset/revocation pass
  - old tokens rejected on `sv` mismatch
  - client identity and rate-limit behavior intact.

## 9. Decision Summary

- Public endpoint ownership: `gateway-service` only.
- Domain ownership: service-local gRPC contracts and implementations.
- For Phases 3 and 4 specifically:
  - external auth endpoints live in gateway;
  - auth logic lives in `auth-service`;
  - identity source remains `users-service`;
  - policy source remains `api-clients-service`.
