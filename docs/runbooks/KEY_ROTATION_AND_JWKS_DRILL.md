# Key Rotation And JWKS Drill

## Purpose
- Validate OAuth/OIDC key rollover without breaking token verification.

## Preconditions
- `auth-service` and `gateway-service` deployed.
- Current signing key (`kid=current`) active.
- Previous key still available in JWKS.

## Procedure
1. Generate new signing key material and assign new `kid`.
2. Deploy `auth-service` with both keys published in JWKS:
   - old key: verify-only
   - new key: sign+verify
3. Confirm `/.well-known/openid-configuration` and `/oauth2/jwks.json` show both keys.
4. Issue new token and confirm header uses new `kid`.
5. Validate both:
   - token signed before rotation (old `kid`)
   - token signed after rotation (new `kid`)
6. Wait until old-token TTL window expires.
7. Remove old key from JWKS and redeploy.
8. Re-run verification checks for new tokens.

## Success Criteria
- No 5xx spike on token validation paths.
- Old tokens remain valid until expiry.
- New tokens always validate with new `kid`.

## Rollback
1. Re-enable previous key as signer.
2. Republish both keys.
3. Redeploy auth-service.
4. Re-run discovery + token verification checks.
