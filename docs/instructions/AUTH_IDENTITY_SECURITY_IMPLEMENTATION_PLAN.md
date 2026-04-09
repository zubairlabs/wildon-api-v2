# Auth + Identity + Security Implementation Plan

## 1. Scope

This plan covers:
1. Login and registration with OAuth 2.1 + OIDC foundations.
2. Email registration, OTP verification, forgot-password flow, reset password.
3. Third-party login (Google, Apple).
4. Acting as OAuth/OIDC provider for third-party clients.
5. RBAC + scope model across Wildon services.
6. JSON payload abuse protections (size + depth + schema hardening).
7. Security rate limiting and auth abuse protection using Redis.
8. Application identity with registered `api_clients` (separate from user identity).

This plan is implementation-first and production-oriented.

## 2. Role and Surface Model

Roles (current):
- `superadmin`
- `admin`
- `manager`
- `support`
- `user`

Surface ownership:
- `control-service`: `superadmin`, `admin`, `manager`
- `platform-service`: `support`
- `public-service` + other user-facing service paths: `user`

Strict token audience segmentation:
- `aud = "public" | "platform" | "control"` only.
- `aud=public` can only access `public-service` routes.
- `aud=platform` can only access `platform-service` routes.
- `aud=control` can access `control-service` routes and only explicitly allowlisted non-control routes.
- `aud=public` and `aud=platform` must never access control endpoints.

Enforcement layers:
- Gateway (`core-api`/`gateway-service`): strict audience + realm gate before routing.
- Service middleware: scope/role enforcement (defense in depth).
- Domain handlers: final authorization checks for critical actions.

## 2.1 Request Identity Model (User + Application)

Every authenticated request carries two identities:
- User identity: who is logged in (`sub`, roles, scopes, session state).
- Application identity: which app/client is calling (`client_id`).

Rules:
- `api_clients` are mandatory for first-party and third-party apps.
- `api_clients` do not replace user auth. They are control-plane identity.
- Gateway validates `X-Client-Id` before user-token authorization.
- Mobile/public clients use `client_id` only (no client secret in app binaries).
- Confidential clients (server-side dashboards/integrations) use `client_id + client_secret`.

## 2.2 Service Ownership for Application Identity

`api-clients-service` is the source of truth for application identity:
- Owns client registry, client status, client audience policy, version policy, and client secret metadata.
- Exposes gRPC validation API for gateway (`ValidateClient`, `GetClientPolicy`).
- `auth-service` consumes client policy for token issuance constraints and `cid` claim consistency.

`auth-service` remains source of truth for:
- user auth, sessions, refresh tokens, JWT/OIDC, RBAC/scope issuance.

## 3. Token and Claims Model

Access token (JWT) claims:
- `sub`, `iss`, `aud`, `realm`, `exp`, `iat`, `jti`
- `cid` (registered `client_id` that requested token)
- `roles` (role list)
- `scopes` (space-delimited or array)
- `sid` (session id)
- `amr` (auth method, e.g. pwd/otp/oauth)
- `sv` (user session_version for mass revocation)
- `device_id` (optional, mobile/app sessions)

OIDC ID token claims:
- Standard: `sub`, `iss`, `aud`, `exp`, `iat`
- OIDC: `nonce`, `email`, `email_verified`, `name` (as available)

Session model:
- Short-lived access token.
- Rotating refresh tokens with server-side session tracking and revocation.
- `session_version` integer on `users` for instant global session invalidation.
- Session is bound to `client_id` and optionally `device_id`.

Access token TTL by audience:
- `public`: 10-15 minutes
- `platform`: 10 minutes
- `control`: 5 minutes

## 4. OAuth 2.1 + OIDC Baseline

Implement in `auth-service`:
- Authorization Code + PKCE (required for all public clients).
- Refresh token grant (rotation + replay detection with session kill on reuse).
- Client Credentials grant (for trusted machine-to-machine internal clients only).
- First-party apps are also registered OAuth clients (`wildon-android`, `wildon-ios`, `wildon-web-public`, etc.).
- Public clients: `client_id` only, PKCE required.
- Confidential clients: `client_id + client_secret`.
- OIDC endpoints:
  - `/.well-known/openid-configuration`
  - `/oauth2/authorize`
  - `/oauth2/token`
  - `/oauth2/userinfo`
  - `/oauth2/jwks.json`
  - `/oauth2/revoke`
  - `/oauth2/introspect` (for internal/admin usage)

Not allowed:
- Implicit grant.
- Password grant as OAuth grant type (keep username/password under first-party auth endpoints).
- `code_challenge_method=plain` for SPA/mobile/public clients (S256 only).
- Client secrets embedded in mobile or browser-distributed apps.

## 4.1 OAuth/OIDC Correctness Requirements

Must enforce:
- `state` required for authorization endpoint requests (CSRF protection).
- `nonce` required for OIDC ID token flows.
- Exact redirect URI matching (no wildcard redirect URIs).
- PKCE `S256` required for public clients.
- Confidential token endpoint auth methods explicitly allowlisted:
  - `client_secret_basic`
  - `client_secret_post`
  - optional future: `private_key_jwt`

## 5. Auth Flows to Implement

## 5.1 Email Registration + Verification
- `POST /v1/auth/register` (email + password + profile basics)
- `POST /v1/auth/verify-email/request` (send OTP via SendGrid)
- `POST /v1/auth/verify-email/confirm` (verify OTP)

Rules:
- Store OTP hashed, TTL-limited, one-time use.
- Generic responses to reduce account enumeration.
- Email normalized and uniqueness enforced.

## 5.2 Login
- `POST /v1/auth/login`
- `POST /v1/auth/step-up/challenge`
- `POST /v1/auth/step-up/verify`

## 5.3 Forgot Password
- `POST /v1/auth/password/forgot/request`
- `POST /v1/auth/password/forgot/verify`
- `POST /v1/auth/password/reset`

Rules:
- OTP hashed with expiry and retry limits.
- Reset invalidates prior sessions and refresh tokens.
- Generic response for unknown accounts.
- Reset increments `users.session_version`.

## 5.4 Third-Party Login
- Google login via authorization code exchange.
- Apple login via authorization code + ID token validation.

Rules:
- Validate provider token signature, issuer, audience, nonce.
- Link provider account by stable provider subject.
- Handle account-link conflict safely.

## 5.5 OAuth Provider for Other Apps
- Client registry (managed via `control-service` -> `api-clients-service` admin APIs).
- Client metadata: redirect URIs, grant types, scopes, PKCE requirement, status.
- Consent records (if required by product policy).

## 5.6 Step-Up Authentication (Mandatory)
High-risk operations must require `amr` to include `mfa`:
- `control-service`: refunds, user deletion, system settings update, OAuth client creation/update.
- Any additional endpoint marked as `requires_step_up=true`.

Behavior:
- If token lacks `mfa` in `amr`, return `403` with a step-up-required error code.
- Step-up completion returns a new short-lived access token with elevated `amr` including `mfa`.

## 5.7 Device Binding Strategy (Mobile/App Clients)
For app sessions, support:
- `device_id` (stable UUID per app install)
- `device_public_key` (optional, for proof-of-possession evolution)
- `device_fingerprint_hash` (privacy-safe hash)

Rules:
- Store binding fields in `sessions`.
- Include `device_id` in access/refresh token claims for bound sessions.
- Validate `device_id` match on refresh.
- On mismatch, reject refresh and emit security event.

## 5.8 API Client Validation Flow
App/client sends:
- `X-Client-Id: <client_id>` on every request.
- Optional `X-App-Version` for policy/version enforcement.

Gateway checks:
- `client_id` exists.
- `client_id` is active and not kill-switched.
- client is allowed for requested audience/surface.
- client environment matches deployment boundary (dev/staging/prod).
- client-level rate-limit policy and feature flags.

Then gateway proceeds to user JWT checks.

Consistency rule:
- For authenticated requests, `X-Client-Id` must equal token `cid`.
- If mismatch, reject request (`401` or `403` by policy) and emit security event.

## 6. RBAC + Scope Strategy

Role-to-surface constraints:
- `superadmin|admin|manager` -> `control` realm
- `support` -> `platform` realm
- `user` -> `public` realm

Audience-to-surface constraints (hard deny):
- `aud=public` -> only public routes
- `aud=platform` -> only platform routes
- `aud=control` -> control routes + explicit allowlist only

Scope namespaces:
- `auth:*` (identity actions)
- `control:*` (admin operations)
- `platform:*` (support operations)
- `public:*` (user operations)
- `logs:*`, `storage:*`, `export:*`, `core:*` (service-specific)

Implementation:
- Validate `client_id` at gateway before user token enforcement.
- Issue scopes at auth time based on role + policy.
- Validate `aud` + `realm` in gateway routing.
- Re-validate `aud` + `realm` + scope in each service middleware.
- `control-service` can manage role assignments and policy via admin RPCs.

## 7. Security Controls

## 7.1 JSON Abuse Protection
Apply at gateway + auth-service:
- Request body size limits (auth routes stricter, e.g. <= 32 KB).
- Max JSON nesting depth check (e.g. <= 12).
- `Content-Type: application/json` enforcement.
- `serde` hardening:
  - `deny_unknown_fields` on request DTOs.
  - strict field length constraints.
- Request timeout + early rejection on malformed payloads.

## 7.2 Security Rate Limiting (applies to all users/plans)
Backed by Redis atomic counters / Lua scripts.

Global protections:
- Login brute force
- Credential stuffing
- OTP spam
- Password reset abuse
- Email verification spam
- OAuth endpoint abuse

Required policies:
- Per-IP login limit: `10 attempts / 5 min / IP`
- Per-account failed login limit: `5 failures / 15 min / account`
- Lock account: `30 min` after threshold
- Per-device fingerprint limit (optional advanced path)

Recommended endpoint defaults:
- Register: 5 / 15 min / IP
- Verify email request: 3 / 10 min / account + IP cap
- Forgot request: 3 / 15 min / account + IP cap
- OTP verify: 10 / 15 min / account + IP cap
- OAuth authorize/token: separate stricter limits by client + IP

## 7.3 Session Version and Mass Revocation
Add `users.session_version INT NOT NULL DEFAULT 1`.

Increment `session_version` on:
- password reset
- role change / permission change
- security incident response
- manual admin revoke-all sessions

Validation:
- Include `sv` in JWT.
- On authenticated requests, reject if `token.sv != current user.session_version`.
- Implement with cache-backed lookup (Redis) to avoid direct DB hit on every request.

## 7.4 Refresh Replay Detection
When refresh token rotation is enabled:
- If an already-rotated refresh token is presented again, treat as replay.
- Immediately invalidate full session family.
- Emit `refresh_reuse_detected` security event.
- Optional: temporary account lock for repeated replay incidents.

## 7.5 Step-Up Enforcement
For high-risk endpoints, enforce:
- `amr` contains `mfa`.
- Otherwise return `403` and require step-up flow.

## 7.6 Structured Security Events
Emit structured events to `logs-service`:
- `login_failed`
- `account_locked`
- `refresh_reuse_detected`
- `oauth_client_created`
- `api_client_disabled`
- `api_client_rate_limited`
- `role_changed`
- `permission_changed`
- `password_reset`

## 7.7 Application-Level Protection via `api_clients`
Required controls:
- Per-client rate limits (`client_id` dimension in gateway limiter).
- Client kill switch (disable compromised app build quickly).
- Allowed audience restrictions per client.
- Optional minimum app version policy by client.
- Environment isolation (distinct clients for dev/staging/prod).

Important:
- `api_clients` are for control/visibility and must not be treated as user authentication.

## 7.8 CORS and CSRF (Browser-Specific)
Policy:
- CORS enabled only for browser-facing surfaces/origins (web dashboards, web app).
- Explicit origin allowlist (no wildcard origins in production).
- Non-browser surfaces can disable CORS entirely.

If cookie-based auth is enabled for browser clients:
- `HttpOnly`, `Secure`, and `SameSite` cookie settings are mandatory.
- CSRF protection required (double-submit token or strict origin check strategy).

If Authorization bearer tokens are used from browser JS:
- CSRF risk is reduced, but strict CORS and origin validation still required.

## 7.9 End-to-End Tracing and Correlation
Required observability:
- OpenTelemetry tracing with logs correlation IDs.
- Propagate `traceparent` and `x-request-id` across all boundaries.

Propagation paths:
- gateway -> services (HTTP/gRPC)
- service -> service (gRPC metadata)
- workers/events via NATS/Redis headers/metadata

## 7.10 Internal Service-to-Service Authentication
Internal calls must be authenticated/authorized, even in-cluster.

Allowed patterns:
- mTLS between services, or
- short-lived internal service JWT in gRPC metadata (`x-internal-auth`).

Requirements:
- identity of caller service must be verifiable.
- authorization policy by service identity and operation.

## 7.11 Key Management and JWKS Rotation
Required policy:
- Signing algorithm explicitly configured (recommended: EdDSA/Ed25519 or RS256).
- JWT header includes `kid`.
- JWKS publishes active and previous verification keys during rollout.
- Old keys remain published until all tokens signed with them are expired.

Secret handling:
- store signing keys via Kubernetes secrets (sealed/external secret manager roadmap).
- key rotation runbook and validation drill required.

## 7.12 Session/OTP Cleanup and Retention
Background cleanup worker (`auth-worker`) must enforce retention:
- expired refresh tokens: cleanup cadence + retention window
- expired/revoked sessions: cleanup cadence + retention window
- expired OTP rows: cleanup cadence + retention window
- failed auth/security events: retention policy for audit and forensics

Retention should balance:
- security/audit needs
- data minimization and storage cost

## 7.13 Edge/Ingress Protections
Before traffic reaches Rust services, enforce:
- ingress max body size limits
- connection and request timeout limits
- optional WAF layer (future: Cloudflare/ModSecurity)

## 7.14 Password Policy and Credential Hygiene
Required baseline:
- Argon2id password hashing with explicit parameters and upgrade policy.
- password length/complexity minimums and banned password list.
- deterministic email normalization rules.
- optional breached-password checks (future hardening).

## 8. Data Model and Storage Plan

`auth-service` tables (primary owner):
- `users`
- `credentials_password`
- `emails`
- `email_verification_otps`
- `password_reset_otps`
- `sessions`
- `refresh_tokens`
- `oauth_provider_accounts` (google/apple)
- `oauth_clients`
- `oauth_client_secrets` (hashed)
- `oauth_consents` (if enabled)
- `role_assignments`
- `scope_policies`
- `account_lockouts`
- `failed_auth_events`

`api-clients-service` tables (primary owner):
- `api_clients`
- `api_client_secrets` (hashed, confidential clients only)
- `api_client_audiences`
- `api_client_versions` (optional min/max or allowlist policy)
- `api_client_audit_events`

Required schema details:
- `users.session_version INT NOT NULL DEFAULT 1`
- `sessions.device_id UUID NULL`
- `sessions.device_public_key TEXT NULL`
- `sessions.device_fingerprint_hash TEXT NULL`
- `refresh_tokens.replaced_by_token_id` for rotation chain tracking
- `refresh_tokens.revoked_reason` to persist replay/security revocations
- `oauth_clients.require_pkce_s256 BOOLEAN NOT NULL DEFAULT true` for public clients
- `oauth_clients.client_type TEXT NOT NULL` (`public` or `confidential`)
- `api_clients.client_id TEXT UNIQUE NOT NULL`
- `api_clients.client_type TEXT NOT NULL` (`public` or `confidential`)
- `api_clients.status TEXT NOT NULL` (`active`, `disabled`, `deprecated`)
- `api_clients.environment TEXT NOT NULL` (`dev`, `staging`, `prod`)
- `api_clients.allowed_audiences TEXT[] NOT NULL`
- `api_clients.rate_limit_profile TEXT NOT NULL`

Redis keys:
- `rl:ip:login:<ip>`
- `rl:acct:login:<account>`
- `rl:device:login:<fingerprint>`
- `rl:client:<client_id>`
- `rl:otp:<type>:<account>`
- `lock:acct:<account>`
- `client:policy:<client_id>` (cached active/status/audience/rate profile/version policy)
- `sv:user:<user_id>` (session_version cache)
- `refresh:replay:<token_id>`

Audit events -> `logs-service`:
- `login_failed`
- `account_locked`
- `refresh_reuse_detected`
- `oauth_client_created`
- `role_changed`
- `permission_changed`
- `password_reset`
- registration and email verification lifecycle events

## 9. Service-by-Service Implementation Plan

`api_clients` phase ownership:
- Phase A: `api-clients-service` scaffold + schema/contracts/seeds and gateway contract.
- Phase B: request-path enforcement and per-client rate limiting baseline.
- Phase C: OAuth alignment (first-party apps as public OAuth clients) + OIDC correctness (`state`, `nonce`, exact redirect URI).
- Phase F: kill-switch/version hardening.
- Phase 8: production operations runbook and dashboards.

`api-clients-service` responsibilities:
- Authoritative registry for `client_id`, client status, environment, and audience policy.
- Public/confidential client classification and secret metadata lifecycle.
- Version policy and kill-switch controls.
- Validation RPC consumed by gateway and auth-service.

## Phase A: Foundations
Deliverables:
- Final auth API/proto contracts for above flows.
- `api-clients-service` microservice skeleton + gRPC contract (`ValidateClient`, `GetClientPolicy`, admin management APIs).
- Migrations/seeds for auth tables.
- Migrations/seeds for `api-clients-service` tables.
- Role/scope seed data.
- Redis key strategy document.
- Audience segmentation contract (`aud` enum: `public|platform|control`) and route policy matrix.
- `users.session_version` schema and revocation policy.
- `api_clients` schema + seed set for first-party apps per environment.
- Gateway/client-validation contract (`X-Client-Id` requirements and error model).
- OpenTelemetry baseline for gateway + auth + api-clients services with trace propagation.
- Internal service auth baseline design (mTLS or internal JWT) documented and approved.

Exit criteria:
- `cargo check/test` green.
- Migrations and seeds run clean in local bootstrap.
- Gateway and service middleware reject cross-audience token misuse.
- Unknown/disabled `client_id` requests are rejected at gateway.
- Trace/span context visible across gateway -> auth-service -> api-clients-service.

## Phase B: Core Email Auth
Deliverables:
- Register + verify email OTP.
- Login + session + refresh.
- Forgot password request/verify/reset.
- SendGrid adapter integration for OTP emails.
- Access token TTL split by audience (`public` 10-15m, `platform` 10m, `control` 5m).
- Device binding fields supported for app sessions (`device_id` required for app clients).
- Gateway enforces `client_id` active-status and allowed-audience before login/auth flows.
- Per-client rate-limit baseline enabled.
- Enforce `X-Client-Id == token.cid` on authenticated requests.
- Password policy + Argon2id parameter baseline implemented.
- CORS allowlist and CSRF strategy implemented for browser-facing routes.

Exit criteria:
- End-to-end email auth flows pass integration tests.
- Session revocation works on password reset.
- Password reset increments `session_version` and invalidates old access path via `sv` mismatch.
- Per-client metrics are visible for login and token flows.
- Browser route CORS/CSRF tests pass.

## Phase C: OAuth 2.1 + OIDC Provider
Deliverables:
- OAuth/OIDC endpoints + JWKS + metadata.
- PKCE validation (S256 strict for SPA/mobile/public clients) and refresh rotation.
- Introspection/revocation endpoints.
- Refresh replay detection with session family invalidation.
- First-party app clients managed as OAuth clients (public, PKCE required, no client secret).
- Require `state` and `nonce` where applicable; enforce exact redirect URI matching.
- Token endpoint client auth methods explicitly restricted by client type.
- JWKS key management and rotation policy implemented (with `kid` rollover behavior).

Exit criteria:
- OIDC discovery + token/userinfo interoperability tests pass.
- Refresh replay test triggers session invalidation and event emission.
- Public clients cannot use confidential-only flows.
- JWKS key rotation drill passes without token verification regressions.

## Phase D: Social Login (Google + Apple)
Deliverables:
- Provider adapters and callback flows.
- Account-linking rules and conflict handling.

Exit criteria:
- Login with Google and Apple works in staging with real provider configs.

## Phase E: RBAC + Scope Enforcement
Deliverables:
- Role assignment admin APIs (`control-service` integration).
- Scope checks across gateway/services.
- Surface-based role restrictions enforced.
- Mandatory step-up policy wiring for high-risk control actions.

Exit criteria:
- Unauthorized role/scope attempts consistently blocked.
- High-risk control operations reject non-MFA tokens with step-up required response.

## Phase F: Security Hardening
Deliverables:
- JSON limits and schema hardening in gateway/auth paths.
- Full auth abuse rate limiting with Redis.
- Lockout and anti-enumeration behavior.
- Structured security events emitted to `logs-service`.
- App kill-switch and version policy enforcement (`api_clients` + optional `X-App-Version`).
- Session/refresh/OTP/event cleanup worker + retention windows enforced.
- Ingress-level protections configured (body size, timeouts, connection limits).

Exit criteria:
- Pen-test style abuse test suite passes.
- No regressions in normal auth latency/SLO.
- Security event taxonomy is queryable end-to-end in `logs-service`.
- Compromised client simulation can be blocked by disabling one `client_id`.
- Cleanup/retention jobs run on schedule and preserve required audit windows.

## 10. Testing Strategy

Required test layers:
- Unit tests: validators, token claims, OTP logic, lockout logic.
- Integration tests: full auth flows with test DB + Redis.
- Contract tests: proto/OpenAPI compatibility.
- Security tests:
  - payload depth/size rejects
  - brute-force simulation
  - OTP spam simulation
  - lockout and unlock lifecycle
  - CORS allowlist behavior for browser origins
  - CSRF protection checks for cookie-based auth flows
  - `X-Client-Id == token.cid` mismatch rejection
  - unregistered/disabled `client_id` rejection
  - client-to-audience mismatch rejection
  - audience segmentation deny matrix (`public/platform/control`)
  - session version mismatch rejection (`sv` mismatch)
  - refresh replay detection and session-family kill
  - OAuth correctness (`state`, `nonce`, exact redirect URI match)
  - JWKS key rotation and `kid` rollover verification
  - internal service auth rejection for missing/invalid service identity
  - trace propagation verification across gateway/services/workers
  - step-up required on high-risk control routes
  - device-bound refresh mismatch rejection

## 11. Rollout Strategy

1. Deploy schema and read-path-safe changes first.
2. Enable features behind flags where possible.
3. Roll out per flow: register -> verify -> login -> password reset -> social -> oauth provider.
4. Monitor auth failure rate, lockouts, OTP send rate, SendGrid errors, replay events, cross-audience denies, client-level denies (`client_id`), trace error hotspots, and key-rotation health.
5. Keep rollback scripts for token/session schema changes.

## 12. Open Decisions (to finalize before coding)

1. OTP format and validity window (`6 digits`, `10 min` suggested).
2. Refresh token lifetime and absolute session lifetime.
3. Consent screen behavior for third-party OAuth clients.
4. Control-token allowlist for non-control endpoints (exact routes).
5. Device fingerprint input strategy and privacy constraints.
6. MFA factor policy for step-up (TOTP only vs TOTP + WebAuthn).
7. Replay incident escalation threshold (lock account or session-only).
8. `X-Client-Id` enforcement mode for local/dev (strict vs warning mode).
9. App version policy model (`X-App-Version` minimum/denylist strategy).
10. Internal service auth mechanism selection (mTLS vs internal JWT first rollout).
11. Signing algorithm default (EdDSA vs RS256) and key rotation cadence.
12. Cleanup retention windows for sessions, refresh tokens, OTP rows, and security events.
13. Browser auth mode decision per surface (cookie+CSRF vs bearer-only).

## 13. Phase-by-Phase Execution Checklist

Use this as the implementation order. Stop after each phase and run validation gates before continuing.

## Phase 1: Contracts + Data Model Baseline
- Create/expand `crates/contracts/proto/auth.proto` for:
  - registration + email verification RPCs
  - login + refresh + logout RPCs
  - forgot password request/verify/reset RPCs
  - oauth authorize/token/revoke/introspect/userinfo/jwks metadata RPCs
  - role/scope admin RPCs
- Create `crates/contracts/proto/api_clients.proto` for:
  - `ValidateClient`
  - `GetClientPolicy`
  - admin management RPCs (create/disable/rotate/update audiences/version policy)
- Add token audience enum contract (`public|platform|control`) and audience policy matrix.
- Add `api_clients` contracts and gateway validation error contract (unknown/disabled/client-audience-mismatch).
- Regenerate contracts via `tonic-build`.
- Add auth-service migrations for all listed auth tables.
- Add `users.session_version` and session device-binding columns in migrations.
- Add `api-clients-service` migrations for `api_clients`, `api_client_secrets`, `api_client_audiences`, `api_client_versions`.
- Add seeds for roles (`superadmin`, `admin`, `manager`, `support`, `user`) and initial scope policies.
- Add seeds for first-party clients (`wildon-android`, `wildon-ios`, `wildon-web-public`, `wildon-control-web`) per environment.
- Scaffold `services/api-clients-service` with `src/`, `migrations/`, `seeds/`, and `Dockerfile`.
- Implement OpenTelemetry context propagation baseline and internal service auth baseline (mTLS or internal JWT).

Validation gate:
- Protobuf generation succeeds.
- `auth-service` and `api-clients-service` migrations + seeds run locally with clean bootstrap.
- Cross-audience route attempts are denied in gateway and service middleware.
- Unknown/disabled `client_id` is denied before token validation.
- Trace context and service identity propagate across gateway -> auth-service -> api-clients-service.

## Phase 2: Email Registration + Verification + Login
- Implement register endpoint + password hashing.
- Implement SendGrid email OTP request + confirm flows.
- Implement login with JWT access + rotating refresh tokens + `sv` claim.
- Apply access TTL split by audience (`public` 10-15m, `platform` 10m, `control` 5m).
- Add optional app client device binding (`device_id`) into session and token claims.
- Require and validate `X-Client-Id` in gateway for auth and API routes.
- Enforce `X-Client-Id == token.cid` on authenticated requests.
- Implement CORS allowlist policy for browser origins and CSRF policy for cookie-mode routes.
- Implement Argon2id hashing + password baseline policy and email normalization rules.
- Implement anti-enumeration response behavior.

Validation gate:
- End-to-end happy path: register -> verify -> login.
- Failed verification/login behavior is consistent and auditable.
- Token claims include expected `aud`, `realm`, and `sv`.
- Per-client rate-limit counters are active and visible.
- Browser CORS/CSRF tests pass for configured web routes.

## Phase 3: Forgot Password + Session Revocation
- Implement forgot-password request/verify/reset APIs.
- Invalidate active sessions/refresh tokens on successful reset.
- Increment `users.session_version` on reset.
- Emit audit events to `logs-service`.

Validation gate:
- End-to-end flow: forgot request -> verify OTP -> reset password -> old refresh token rejected.
- Existing tokens fail after reset because `sv` mismatch is enforced.

## Phase 4: OAuth 2.1 + OIDC Provider Mode
- Implement Authorization Code + PKCE, refresh, client credentials (internal only).
- Implement OIDC discovery, JWKS, userinfo, revoke, introspect.
- Add oauth client registry management API path (`control-service` -> `api-clients-service` and `auth-service` where applicable).
- Link first-party app registrations to OAuth public clients (no secret).
- Enforce PKCE `S256` for SPA/mobile/public clients (deny `plain`).
- Enforce required `state`, required `nonce` (ID token flows), and exact redirect URI matching.
- Restrict token endpoint client authentication methods by client type.
- Implement JWKS key rotation with `kid` rollover policy.
- Add refresh replay detection that revokes full session family.

Validation gate:
- Discovery and JWKS interoperable.
- PKCE negative tests (missing/invalid verifier) are rejected.
- Refresh token reuse triggers `refresh_reuse_detected` and session invalidation.
- Public app clients cannot authenticate with confidential-client methods.
- JWKS rotation drill passes while previously issued tokens remain verifiable until expiry.

## Phase 5: Social Login (Google + Apple)
- Implement Google and Apple login adapters in `provider-clients`.
- Validate provider token signature + issuer + audience + nonce.
- Add account linking rules and conflict handling.

Validation gate:
- Real provider staging login works for both Google and Apple.
- Duplicate/link conflict behavior is deterministic and safe.

## Phase 6: RBAC + Scope Enforcement
- Enforce realm/surface constraints:
  - `control-service`: `superadmin`, `admin`, `manager`
  - `platform-service`: `support`
  - `public-service` and user-facing paths: `user`
- Enforce strict audience segmentation:
  - `aud=public` and `aud=platform` never reach control endpoints.
  - `aud=control` only reaches explicitly allowlisted non-control endpoints.
- Enforce scope checks in middleware + sensitive handler paths.
- Add role/scope management APIs in `control-service`.
- Add mandatory step-up (`amr` includes `mfa`) for high-risk control actions.

Validation gate:
- Unauthorized role/scope requests blocked at gateway and service layers.
- Privilege escalation attempts covered by tests.
- High-risk control actions return step-up-required when `mfa` is absent.

## Phase 7: Security Hardening and Abuse Controls
- Apply JSON body size/depth limits and strict DTO validation.
- Add Redis-backed auth abuse controls:
  - per-IP login attempts
  - per-account failed attempts + lockout window
  - per-device fingerprint limits (optional advanced)
  - OTP/password reset/oauth anti-spam limits
- Add per-client rate limits and client kill-switch enforcement.
- Add cleanup worker cadence + retention enforcement for sessions, refresh tokens, OTP rows, and security events.
- Apply ingress-level protections (body limits, connection/request timeouts).
- Add structured security metrics, alerts, and event taxonomy to `logs-service`.

Validation gate:
- Brute-force and OTP spam simulations hit limits as expected.
- No material regression in p95 auth latency under normal traffic.
- Security events (`login_failed`, `account_locked`, `refresh_reuse_detected`, `role_changed`, `permission_changed`, `password_reset`) are visible end-to-end.
- Disabled `client_id` blocks traffic immediately across all routes.
- Cleanup and retention jobs execute on schedule and keep required audit windows.

## Phase 8: Production Readiness
- Add feature flags per flow (register, social login, provider mode).
- Add migration rollback notes and runbooks.
- Add dashboards for auth success/failure, lockouts, OTP send failures, provider callback errors.
- Add client lifecycle runbook (rotate secret, disable client, sunset app version).
- Add runbooks for key rotation and internal service-auth rotation.

Validation gate:
- Canaries pass with rollback path proven.
- On-call runbook and alert thresholds reviewed.
