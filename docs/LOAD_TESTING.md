# Load Testing

## Scripts
- Smoke: `scripts/ops/load/k6-smoke.js`
- Soak: `scripts/ops/load/k6-soak.js`
- Runner: `scripts/ops/load/run-load-tests.sh`

## Local execution
1. Start infra: `scripts/dev/up-local.sh`
2. Start services with `cargo run`.
3. Run: `scripts/ops/load/run-load-tests.sh`

## Baseline SLO gates
- Error rate: `< 1%` smoke, `< 2%` soak.
- Gateway p95 latency: `< 300ms` smoke, `< 400ms` soak.
- Gateway p99 latency: `< 800ms` soak.
- 429 ratio should stay within configured backpressure policy.

## Dashboard
Import `infra/k3s/observability/slo-dashboard.json` into Grafana and map metrics to your Prometheus datasource.
