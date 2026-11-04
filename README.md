# 7 Deadly Sins

> Internal codename: **SINS**. The commercial name will be chosen later.
> Enterprise sales does not use the sin names - only technical categories.

An attack surface and vulnerability assessment platform. Core principle:

> **We do not write scanners. We orchestrate existing open-source scanners,
> merge their results, and hand back a remediation path.**

## Why it looks like this

| Problem | Solution |
|---|---|
| Writing 7 modules = 6 months | 4 existing tools cover 7 jobs |
| Writing payloads = legal risk | nuclei has 10,000+ ready-made checks |
| Every tool, a different format | One `FindingContract` |
| One CVE in 3 places | `correlate()` - one finding, three pieces of evidence |

## 7 sins to 4 tools

| Sin | Job | Tool | Status |
|---|---|---|---|
| Greed (2) | CVE vulnerabilities | `nuclei` | ✅ ready |
| Sloth (7) | Dependency audit | `osv-scanner` | ✅ ready (local directory only) |
| Pride (1) | Attack surface | `subfinder` + `naabu` + `httpx` | ✅ ready |
| Envy (4) | SSL/TLS | `sslyze` (CLI) | ✅ ready |
| Lust (3) | Auth flaws | nuclei auth templates + `pyjwt` | ⏳ Sprint 4 |
| Gluttony (5) | Resilience | nuclei rate-limit templates (≤50 RPS) | ⏳ Sprint 4 |
| Wrath (6) | Exploit validation | nuclei exploit templates | ⏳ Sprint 4 |

**Dropped from v1:** Hydra brute force, DDoS stress testing, hand-written
exploit payloads. Reason: legal liability. Details in `docs/DECISIONS.md`.

> Another AI also works on this project: the rules, the commands and the
> handed-over tasks are in `AI-HANDOFF.md`.

### Important: engines are filtered by target type

Every adapter exposes `applies_to(target)`. A non-matching engine **is never
started** and appears in the report as skipped.

| Target type | nuclei | pride | envy | osv |
|---|---|---|---|---|
| `example.com`, `https://…`, `10.0.0.1` | ✅ | ✅ | ✅ | - |
| `/path/to/repo`, `./app` | - | - | - | ✅ |

Reason: `osv-scanner` hangs when it runs against a URL (real incident).

## Authorization gate - the first code in the system

Ownership of the target is proven before any scan:

```bash
sins verify example.com
# -> returns a token
# method 1: _sins-verify.example.com TXT "token"
# method 2: https://example.com/.well-known/sins-verify-<token>

sins scan example.com --verify-token <token>
```

The `--lab` flag only accepts `localhost` and private IPs. It never applies to
an external address. In the API, lab targets are verified automatically when
they are created (`verify_method="lab"`); external targets need a DNS TXT
record or a `.well-known` file.

## Quick start

```bash
uv sync --python 3.13
docker compose up -d                # PostgreSQL + Redis
uv run alembic upgrade head         # or (dev only): uv run sins init-db --drop
uv run sins adapters                # which tools are installed
```

`make help` lists every command. The short version:

```bash
make test      # pytest
make lint      # ruff check
make api       # API (reload)
make worker    # ARQ worker
make migrate   # alembic upgrade head
```

macOS + Homebrew: `weasyprint` needs `pango` and `gtk3` -
`brew install pango gtk+3`. The code sets `DYLD_FALLBACK_LIBRARY_PATH` itself,
so no extra environment setup is required.

### Scan with the CLI

```bash
python3 -m http.server 8099 &        # lab target

uv run sins scan http://localhost:8099 --lab -e nuclei \
  --json out/scan.json
uv run sins report out/scan.json --out out/report.pdf --tenant "Demo Bank"
```

### Scan through the API (product flow)

```bash
uv run sins create-tenant --name "Demo Bank"   # the API key is shown once
uv run sins serve --port 8000                  # http://127.0.0.1:8000/docs
uv run sins worker                             # ARQ worker (scan jobs)

export SINS_API_KEY=sins_...
uv run python scripts/e2e_demo.py http://localhost:8099
```

The full flow:

| Step | Request |
|---|---|
| 1. Add a target | `POST /targets` → response carries `verify_token` and instructions |
| 2. Prove ownership | `POST /targets/{id}/verify` (DNS TXT or `.well-known`) |
| 3. Scan | `POST /scans` → `202`, `{"target_id": ..., "engines": [...], "severities": [...]}` |
| 4. Status | `GET /scans/{id}` → `status`, `progress`, `current_engine` |
| 5. Findings | `GET /scans/{id}/findings?severity=critical&limit=50` |
| 6. Difference against the previous scan | `GET /scans/{id}/diff` |
| 7. Cancel | `POST /scans/{id}/cancel` |
| 8. PDF report | `GET /scans/{id}/report.pdf` |

Authentication: the `X-API-Key: sins_...` header. The key is stored in the
database **as a SHA-256 hash only**. Rotate it with
`POST /tenant/rotate-key` (the old key stops working immediately).

`POST /scans` supports the `Idempotency-Key` header: a network retry does not
start a second scan.

### Monitoring and control

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Liveness - `{"status":"ok"}` |
| `GET /readyz` | Readiness - `{"ready":true,"db":"ok","queue":"ok"}` (may return 503) |
| `GET /metrics` | Prometheus text: requests, duration, scans, engines |
| `GET /tenant/me` | Current tenant (key prefix, name) |

When `queue: "inline"` there is no Redis - scans run inside the API process
(dev mode).

### Guardrails and policy

- **Rate limit** - 600 requests/minute (per key or IP), `429` + `Retry-After`.
- **Retry** - an adapter that fails transiently gets 2 attempts (exponential backoff).
- **Retention** - `sins prune --days 180` plus an ARQ cron (03:30).
- **Structured logs** - every record is JSON, traced by `X-Request-ID`.

## Architecture

```
CLI / React UI
   -> FastAPI (request-ID + rate limit middleware, X-API-Key,
                AUTHORIZATION GATE, tenant isolation)
        -> PostgreSQL  (state, findings, jsonb evidence) - Alembic migrations
        -> Redis + ARQ (queue; inline fallback when Redis is absent)
        -> Worker  (orchestration only - it never scans by itself)
             -> nuclei / osv-scanner  (existing tools, safe subprocess)
                  -> parser -> FindingContract -> correlate() -> PostgreSQL
        -> Report: Jinja2 HTML -> WeasyPrint -> PDF
```

## Code layout

```
src/sins/
  schemas.py       # FindingContract - the contract the whole system speaks
  models.py        # SQLAlchemy: Tenant, Target, Scan, Finding
  authz.py         # Authorization gate (DNS TXT / HTTP file)
  targets.py       # target type, normalization, lab restriction
  security.py      # API key generation + SHA-256 hash
  runner.py        # safe subprocess (timeout, killpg, argv)
  dedup.py         # dedup_key + correlate() - the heart of the aggregator
  orchestrator.py  # parallel adapter runs + retry + applies_to
  observability.py # JSON logging, request-ID, Prometheus metrics
  ratelimit.py     # token-bucket limiter
  middleware.py    # request context, access log, 429
  adapters/
    base.py        # Adapter protocol (available / applies_to / run)
    nuclei.py      # Greed
    osv.py         # Sloth
  services/
    scan_service.py  # THE single business logic layer (CLI, API and worker all call it)
  api/
    main.py        # FastAPI app, lifespan, error handlers
    deps.py        # X-API-Key -> Tenant
    routes/        # targets.py, scans.py, tenant.py
  report/          # Jinja2 template + WeasyPrint renderer
  worker.py        # ARQ WorkerSettings + cron (prune, metrics)
  cli.py           # every capability exists here before any UI
migrations/        # Alembic (schema + idempotency index)
docs/              # ARCHITECTURE, API, SECURITY, RUNBOOK, DECISIONS
Dockerfile         # multi-stage, non-root, healthcheck
Makefile           # daily commands
.github/workflows/ # CI: lint, format, alembic check, test
```

## Roadmap

| Phase | Status | Outcome |
|---|---|---|
| **0 - foundation** | ✅ | authz gate, `FindingContract`, nuclei adapter, CLI |
| **1 - DB + API** | ✅ | Alembic, FastAPI, ARQ, tenant/scan flow, 130+ tests |
| **1.5 - operations** | ✅ | metrics, rate limit, idempotency, diff, cancel, retention, Docker, CI |
| **2 - 2nd module + PDF** | ✅ | osv adapter, `applies_to` filter, production-grade PDF |
| **3 - dashboard** | ⏳ | React, SSE progress, tables |
| **4 - pilot** | ⏳ | **1 real customer, a real report** |

The next module lands only after pilot customer feedback.

## Documentation

| File | What it covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, lifecycle, retry, observability |
| [`docs/API.md`](docs/API.md) | Every endpoint, request/response examples |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, ownership gate, subprocess |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Startup, troubleshooting, incidents |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Why each decision was made |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Code rules, tests, PR |
| [`PROGRESS.md`](PROGRESS.md) | Done and remaining work (current state) |

## Tests

```bash
uv run pytest -q                 # 252 tests (against a separate `sins_test` database)
uv run ruff check src/ tests/ scripts/
uv run alembic check             # checks model vs migration drift
```

The test suite **rejects** any database name that does not end in `_test`. That
is what stops an accidental wipe of the production database.

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [`LICENSE`](LICENSE) for the full text.

In plain terms: you may use, study, modify and redistribute this software. If
you run a modified version as a network service, you must offer the corresponding
source to the users of that service. Running the unmodified software does not
require you to publish anything of your own.
