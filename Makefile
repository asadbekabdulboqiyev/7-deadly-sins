# SINS — tez-tez ishlatiladigan buyruqlar. `make help` bilan ro'yxat.
.DEFAULT_GOAL := help
PY := uv run
COMPOSE := docker compose

.PHONY: help install lint fmt test cov migrate migration api worker tenant report demo prune docker-build docker-up docker-down clean

help: ## Buyruqlar ro'yxati
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Bog'liqliklarni o'rnatish
	uv sync

lint: ## Ruff tekshiruvi
	$(PY) ruff check src/ tests/ scripts/

fmt: ## Ruff format + avtomatik tuzatish
	$(PY) ruff format src/ tests/ scripts/
	$(PY) ruff check --fix src/ tests/ scripts/

test: ## Testlar
	$(PY) pytest -q

cov: ## Qamrov hisoboti
	$(PY) pytest -q --cov=sins --cov-report=term-missing

migrate: ## Migratsiyalarni qo'llash
	$(PY) alembic upgrade head

migration: ## Yangi migratsiya (m="izoh")
	$(PY) alembic revision --autogenerate -m "$(m)"

api: ## API (dev, reload bilan)
	$(PY) sins serve --port 8000 --reload

worker: ## ARQ worker
	$(PY) sins worker

tenant: ## Yangi mijoz + API kalit (n="Demo Bank")
	$(PY) sins create-tenant --name "$(or $(n),Demo Bank)"

report: ## PDF hisobot (json=scan.json)
	$(PY) sins report "$(json)" --out "$(or $(out),report.pdf)"

demo: ## To'liq oqim demosi (API + worker ishlab turishi kerak)
	$(PY) python scripts/e2e_demo.py $(or $(target),http://localhost:8099)

prune: ## Eski skanlarni tozalash (dry-run: make prune ARGS="--dry-run")
	$(PY) sins prune $(ARGS)

docker-build: ## Docker obrazini yig'ish
	$(COMPOSE) --profile app build

docker-up: ## Postgres + Redis (+ app profili)
	$(COMPOSE) up -d

docker-down: ## Stackni to'xtatish
	$(COMPOSE) down

clean: ## Keshlarni tozalash
	rm -rf .pytest_cache .ruff_cache out dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
