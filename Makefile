# 7 Deadly Sins - frequently used commands. Run `make help` for the list.
.DEFAULT_GOAL := help
PY := uv run
COMPOSE := docker compose

.PHONY: help install lint fmt test cov migrate migration api worker tenant report demo prune docker-build docker-up docker-down clean

help: ## List commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	uv sync

lint: ## Ruff check
	$(PY) ruff check src/ tests/ scripts/

fmt: ## Ruff format + autofix
	$(PY) ruff format src/ tests/ scripts/
	$(PY) ruff check --fix src/ tests/ scripts/

test: ## Tests
	$(PY) pytest -q

cov: ## Coverage report
	$(PY) pytest -q --cov=sins --cov-report=term-missing

migrate: ## Apply migrations
	$(PY) alembic upgrade head

migration: ## New migration (m="message")
	$(PY) alembic revision --autogenerate -m "$(m)"

api: ## API (dev, with reload)
	$(PY) sins serve --port 8000 --reload

worker: ## ARQ worker
	$(PY) sins worker

tenant: ## New tenant + API key (n="Demo Bank")
	$(PY) sins create-tenant --name "$(or $(n),Demo Bank)"

report: ## PDF report (json=scan.json)
	$(PY) sins report "$(json)" --out "$(or $(out),report.pdf)"

demo: ## Full flow demo (API and worker must be running)
	$(PY) python scripts/e2e_demo.py $(or $(target),http://localhost:8099)

prune: ## Delete old scans (dry run: make prune ARGS="--dry-run")
	$(PY) sins prune $(ARGS)

docker-build: ## Build the Docker image
	$(COMPOSE) --profile app build

docker-up: ## Postgres + Redis (+ the app profile)
	$(COMPOSE) up -d

docker-down: ## Stop the stack
	$(COMPOSE) down

clean: ## Clear caches
	rm -rf .pytest_cache .ruff_cache out dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
