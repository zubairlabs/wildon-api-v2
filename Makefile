## Wildon API — Local Development
## Usage: make <target> [SVC=service-name]

.DEFAULT_GOAL := help

# All services in the workspace
SERVICES := gateway-service auth-service public-service platform-service \
            control-service core-service users-service api-clients-service \
            billing-service storage-service export-service logs-service chat-service

COMPOSE := docker compose -f infra/docker/docker-compose.yml

.PHONY: help
help:
	@echo "Wildon API — local dev targets"
	@echo ""
	@echo "  make infra          Start infrastructure (YugabyteDB, Redis, NATS)"
	@echo "  make infra-down     Stop infrastructure"
	@echo "  make infra-logs     Tail infra logs"
	@echo ""
	@echo "  make build SVC=<service>   Build a single service (release)"
	@echo "  make run   SVC=<service>   Run a single service (uses .env)"
	@echo "  make build-all             Build all services (release)"
	@echo ""
	@echo "  make check          cargo check --workspace"
	@echo "  make fmt            cargo fmt --all"
	@echo "  make test           cargo test --workspace"
	@echo ""
	@echo "  make dev SVC=<service>     Build + run a service in one step"
	@echo ""
	@echo "Services: $(SERVICES)"

# ── Infrastructure ─────────────────────────────────────────────────────────────

.PHONY: infra
infra:
	$(COMPOSE) up -d
	@echo ""
	@echo "  YugabyteDB UI : http://localhost:7000"
	@echo "  NATS monitor  : http://localhost:8222"
	@echo ""
	@echo "  Database URL  : postgresql://yugabyte@127.0.0.1:5433/wildon"

.PHONY: infra-down
infra-down:
	$(COMPOSE) down

.PHONY: infra-logs
infra-logs:
	$(COMPOSE) logs -f

# ── Building ───────────────────────────────────────────────────────────────────

.PHONY: build
build:
ifndef SVC
	$(error SVC is required — e.g. make build SVC=gateway-service)
endif
	cargo build --release -p $(SVC)
	@echo "  Binary: target/release/$(SVC)"

.PHONY: build-all
build-all:
	cargo build --release $(foreach s,$(SERVICES),-p $(s))

# ── Running ────────────────────────────────────────────────────────────────────

.PHONY: run
run:
ifndef SVC
	$(error SVC is required — e.g. make run SVC=gateway-service)
endif
	@test -f .env || (echo "No .env found — copy .env.example and fill in secrets" && exit 1)
	env $$(grep -v '^#' .env | grep -v '^$$' | xargs) ./target/release/$(SVC)

.PHONY: dev
dev: build run

# ── Code quality ───────────────────────────────────────────────────────────────

.PHONY: check
check:
	cargo check --workspace

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: test
test:
	cargo test --workspace
