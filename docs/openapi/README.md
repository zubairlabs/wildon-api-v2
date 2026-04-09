# OpenAPI Docs

This folder contains HTTP contracts for Wildon API surfaces.

## Files

- `gateway-v1.json`: OpenAPI 3.0 document for all gateway routes.
- `control-v1.json`: OpenAPI 3.0 document for control-service routes.
- `platform-v1.json`: OpenAPI 3.0 document for platform-service routes.

## Runtime URLs

When `gateway-service` is running:

- Swagger UI: `/docs`
- OpenAPI JSON: `/openapi/gateway-v1.json`

When `control-service` is running:

- Swagger UI: `/docs`
- OpenAPI JSON: `/openapi/control-v1.json`

When `platform-service` is running:

- Swagger UI: `/docs`
- OpenAPI JSON: `/openapi/platform-v1.json`

## Frontend Usage

Use these files as canonical API contracts:

- endpoint paths and methods
- request/response schemas
- required auth headers (`Authorization`, `X-Client-Id`)
- optional headers (`X-App-Version`, `X-Device-Id`, `X-Device-Fingerprint`, `X-Idempotency-Key`)
