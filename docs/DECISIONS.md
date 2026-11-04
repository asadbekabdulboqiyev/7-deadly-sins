# 7 Deadly Sins - decision record (ADR)

Every architectural decision is recorded here.

## ADR-1: 7 sins to 4 existing tools (Greed, Sloth, Pride, Envy)

**Status:** accepted.

Instead of writing our own scanners (6 months of work), we orchestrate
existing open-source scanners:
- nuclei (Greed - CVEs), osv-scanner (Sloth - dependencies), subfinder+naabu+httpx (Pride - attack surface), sslyze (Envy - SSL/TLS).

**Rationale:** delivery speed, 10,000+ nuclei templates, and a single merged
output through the `FindingContract`.

**Constraint:** Hydra brute force, DDoS and hand-written exploit payloads are
dropped from v1 (legal liability).

## ADR-2: PostgreSQL (instead of MongoDB)

**Status:** accepted.

PostgreSQL for state, findings and JSONB evidence. SQLAlchemy plus Alembic for
schema management.

## ADR-3: `applies_to` adapter filtering (prevents the osv hang)

**Status:** accepted.

Every adapter exposes `applies_to(target) -> bool`. A non-matching engine is
never started and is reported through `EngineReport(skipped=True,
skip_reason=...)` to the progress callback (progress still reaches 100%). In the
PDF a skipped engine shows as `-` / `skipped`.

| Target | nuclei | osv |
|---|---|---|
| domain/url/ip | ✅ | - |
| local directory | - | ✅ |

**Rationale:** `osv-scanner` hangs when it runs against a URL (real incident).

## ADR-4: Alembic is the schema source (`init-db` is dev only)

**Status:** accepted.

`alembic.ini` holds no URL (it is read from `SINS_DATABASE_URL` by
`migrations/env.py`). `prepend_sys_path = %(here)s/src`. `alembic upgrade head`
is the source of truth for the schema. `init-db` exists for local development
only (with `--drop`).

**Verification:** `uv run alembic check` must print "No new upgrade operations
detected" (no model vs migration drift).

## ADR-5: API key security (SHA-256 hash, shown once)

**Status:** accepted.

`Tenant.api_key_hash` holds the SHA-256 hash. `api_key_prefix` exists for
display. The raw key is emitted by `sins create-tenant` exactly once. The API
key never reaches the frontend.

## ADR-6: Queue (ARQ with inline fallback)

**Status:** accepted.

ARQ worker (`max_jobs=2`). Without Redis the API runs the job inline through
`asyncio.create_task`. `GET /healthz` reports `queue: ok|inline`.

## Roadmap

| Phase | Status |
|---|---|
| 0 - foundation | ✅ |
| 1 - DB + API | ✅ |
| 2 - 2nd module + PDF | ✅ |
| 3 - dashboard | ⏳ |
| 4 - pilot | ⏳ |
