# Contributing

## Environment

```bash
uv sync --python 3.13
docker compose up -d
uv run alembic upgrade head
```

macOS: `brew install pango gtk+3` is required for PDF output. The tests run
without `nuclei` and `osv-scanner` installed (the adapters are mocked).

## Day-to-day commands

```bash
make test        # pytest
make lint        # ruff check
make fmt         # ruff format + fix
make cov         # coverage
make migration m="message"   # autogenerate
```

All three checks must be green before a commit:

```bash
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run pytest -q
uv run alembic check
```

## Rules

1. **Business rules live only in `services/scan_service.py`.** Routes, the CLI
   and the worker just call those functions.
2. **A test for every new endpoint** - at least one happy path and one failure.
3. **Tenant isolation** - a `tenant_id` filter on every request. Try to break it
   in a test with a foreign tenant (`test_tenant_cannot_see_foreign_scan`).
4. **New adapter** - implement the protocol in `adapters/base.py`: `name`,
   `sin`, `category`, `available()`, `applies_to()`, `run()`. Add it to
   `REGISTRY` and write a test for its `applies_to`.
5. **Security** - no `shell=True`, user input is never concatenated into argv,
   keys are never logged.
6. **Migrations** - if a model changes, `make migration` and a clean
   `alembic check` are mandatory. The migration message must be short and
   precise.
7. **Language** - code comments, docs, API strings and UI strings are all
   English (product contract).

## Test layout

| File | What it covers |
|---|---|
| `test_api.py` | HTTP flow, auth, ownership, PDF |
| `test_scan_service.py` | Lifecycle, tenant isolation |
| `test_service_extras.py` | Idempotency, cancel, diff, rotate, prune, pagination |
| `test_observability.py` | Log formats, metrics |
| `test_ratelimit.py` | Token-bucket boundaries |
| `test_middleware.py` | Request ID, rate limit, `/metrics` |
| `test_orchestrator.py` | Adapters, `applies_to`, retry |
| `test_security.py` | Key hashing, tokens |
| `test_targets.py` | Target classification, lab restriction |
| `test_report.py` | PDF contents |

The tests run **only** against a database whose name ends in `_test`. Any other
name raises `RuntimeError`, which protects the production database.

## PR

- Small, logical commits (`feat:`, `fix:`, `docs:`, `test:`).
- In the description: what changed, why, and how it was verified.
- A behavior change means `docs/` gets updated.
- Keep the done/remaining list in `PROGRESS.md` current.
