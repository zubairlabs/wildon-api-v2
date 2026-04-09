# wildon-api

Monorepo scaffold for Wildon Rust microservices.

Current status:
- Workspace and service/crate skeletons created.
- Local infra compose stack included (`YugabyteDB`, `Redis`, `NATS`).
- Wasabi-oriented S3 config keys added to env examples.
- Phase 5 hardening added: gateway rate limiting, core cache invalidation, k3s autoscaling/PDB manifests, load test assets, DR runbook, GHCR->k3s deploy script/workflow.

See:
- `docs/ARCHITECTURE_BLUEPRINT.md`
- `docs/IMPLEMENTATION_ROADMAP.md`
