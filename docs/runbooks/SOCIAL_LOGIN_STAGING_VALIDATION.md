# Social Login Staging Validation

## Scope
- Validate Google and Apple login flows in staging with real provider configs.

## Required Inputs
- `GOOGLE_*` staging credentials.
- `APPLE_*` staging credentials.
- Staging redirect URIs registered at providers.

## Validation Steps
1. Google:
   - obtain provider ID token in staging flow.
   - call `/v1/auth/social/google`.
   - verify access+refresh issuance and stable account linking.
2. Apple:
   - obtain provider ID token in staging flow.
   - call `/v1/auth/social/apple`.
   - verify access+refresh issuance and stable account linking.
3. Repeat login with same provider subject:
   - ensure same local user identity is returned.
4. Cross-link conflict checks:
   - verify deterministic error on conflicting linkage.

## Success Criteria
- Both providers can sign in successfully.
- Repeat sign-in is idempotent and deterministic.
- No duplicate-account creation for same provider subject.

## Evidence
- Save request IDs for successful and conflict test cases.
- Attach logs-service events and screenshots from staging.
