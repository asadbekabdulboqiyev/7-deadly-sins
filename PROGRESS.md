# SINS — Progress

> This file is updated after every session. Goal: keep what was done and what is
> left in one place, briefly.
> Full instructions for the next AI: `AI-HANDOFF.md`.

Last updated: 2026-11-05

## Current state — steady

| Metric | Value |
|---|---|
| Tests | **280 passed** (`uv run pytest -q`) |
| Coverage | ~76% (`pytest --cov=sins`) |
| Lint | `ruff check` + `ruff format --check` clean (63 files) |
| Migrations | head `c3d4e5f6a7b8` — `alembic check` clean |
| API version | 0.2.0 |
| Engines | all 7 enabled by default: `nuclei`, `osv`, `pride`, `envy`, `lust`, `gluttony`, `wrath` |
| Site | `/Users/asadbek/sins-site` — build + desktop/mobile audit done |
| Git | all work committed |

## Done

### Backend core
- Ownership gate (DNS TXT / `.well-known`), lab target check
- `FindingContract` — single contract for all tool output
- `dedup.py` — `dedup_key` + `correlate()`
- `nuclei` and `osv-scanner` adapters, safe subprocess runner
- Orchestrator: `applies_to`, parallel run, retry + exponential backoff
- Typer CLI, PDF report (Jinja2 → WeasyPrint), FastAPI, ARQ worker, Alembic

### Engines (Sprint 3 + additions)
- **Pride** (`subfinder` → `naabu` → `httpx`): subdomains, open ports, live HTTP
  services. Each stage best-effort; port severity matrix; `_resolve_tool()` skips
  venv shadowing.
- **Envy** (`sslyze` CLI): certificate expiry / trust, weak signature, SSLv2/3
  and TLS 1.0/1.1, Heartbleed, TLS compression, HSTS.
- **Lust** (`httpx` CLI): auth posture — Basic over plain HTTP, login form over
  plain HTTP, session cookie Secure/SameSite, JWT hygiene.
- **Gluttony** (`httpx` CLI): resilience posture — Server header disclosure,
  X-Powered-By disclosure, dangerous allowed methods.
- **Wrath** (nuclei templates): exploit confirmation — re-run templates, confirm
  findings that reproduce a prior finding.
- **Sloth** (`osv-scanner`): dependency & misconfiguration audit.
- Greed (`nuclei`): vulnerability scanning.

All engines live-verified against real tools: Pride → `127.0.0.1` (7 findings),
Envy → local TLS `127.0.0.1:8443` (3 findings: self-signed, expiry, HSTS).

### Drift / exposure timeline
- `finding_states` table (migration `b7c2f4e9a1d3`) + regressions column
  (migration `c3d4e5f6a7b8`)
- `src/sins/drift.py` — fingerprint / weight / exposure score / age
- `src/sins/services/drift_service.py` — upsert states, list states, timeline
- Scan wiring: `prior_findings` into `ScanContext`, `ScanDiff.regressed`

### Operations layer
- `observability.py` — JSON/text log, request-ID, Prometheus registry
- `ratelimit.py` — token bucket, key SHA-256, `max_keys` eviction
- `middleware.py` — RequestContext (ID + access log + metrics), RateLimit (429)
- `models.py` — `ScanStatus.cancelled`, `Scan.idempotency_key` (partial unique)
- `scan_service.py` — filters/pagination, `severity_counts`, `cancel_scan`,
  `diff_scan`, `rotate_api_key`, `prune_scans`, `find_scan_by_idempotency_key`
- API: `Idempotency-Key`, pagination, `status`/`target_id` filters,
  `POST /scans/{id}/cancel`, `GET /scans/{id}/diff`,
  `GET /tenant/me`, `POST /tenant/rotate-key`
- `main.py` — `/healthz` (liveness), `/readyz` (db + queue), `/metrics`
- `worker.py` — `max_tries=2`, cron: daily prune (03:30) + 5-min metrics gauge
- CLI — `prune` (`--days`, `--dry-run`) and `rotate-key`

### Infrastructure
- `Dockerfile` — multi-stage, non-root (uid 10001), HEALTHCHECK
- `.dockerignore`, `docker-compose.yml` (`app` profile: api + worker)
- `Makefile` — `help/install/lint/fmt/test/cov/migrate/api/worker/tenant/report/demo/prune/docker-*`
- `.github/workflows/ci.yml` — lint, format check, `alembic check`, pytest + cov

### Docs
- `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/SECURITY.md`,
  `docs/RUNBOOK.md`, `CONTRIBUTING.md`, `docs/DECISIONS.md`
- `README.md` — sin→tool table, endpoints, roadmap
- `AI-HANDOFF.md` — next AI instructions, commands, pitfalls, assigned tasks

### Audit fixes (2026-11-04)
- `tests/test_scan_service.py` — 13 previously-live tests had been replaced with
  `pytest.skip` stubs → restored from HEAD
- `envy.py` — guessed JSON schema and nonexistent CLI flags (`--regular`,
  `--jsonfile`) → rewritten against real sslyze 6.x schema
- `pride.py` — naabu `ports` array expectation → real JSONL format; `-rate-limit`
  → `-rate`; httpx venv shadowing → `_resolve_tool()`
- Time-dependent tests and wrong severity checks removed
- Unrequested changes reverted: `MAX_FINDINGS_PER_SCAN` 1000→5000,
  `testpaths=["tests","src/sins"]`
- Stale `tmp_parent_test`/`tmp_child_test` leftovers removed
  (`alembic check` green)

### Site + localization pass (2026-11-05)
- **Site truth pass** — 7 sin engines over 6 OSS tools (was "4 engines");
  all seven sins marked live; 5-step pipeline including Drift; Lust/Gluttony →
  `httpx`, Wrath → `nuclei` re-run.
- **New `Exposure drift` section** (`sins-site/src/components/Drift.tsx`) —
  interactive SVG exposure timeline, selectable scans, state-change list,
  accurate `GET /scans/:id/diff` payload. Backed by `drift.py` +
  `drift_service.py` (fingerprint, `exposure_score`, regression counter).
- **New proof strip** — 7 engines / 6 tools / 1 schema / 0 custom exploits.
- **Design law** — eyebrow budget cut to 3, hero `min-h-[100dvh]`,
  `section[id]` scroll-margin, skip link, section rhythm `6rem/8rem`.
- **Responsive fixes** — 360–1440 px audited; removed the 12 px overflow at
  360 px (`min-w-0` on drift grid children); chart hit areas now align exactly
  with plotted points; tap targets ≥ 24 px; chart labels and placeholders
  raised to AA contrast.
- **Assets/meta** — `index.html` description/keywords/theme-color aligned to
  `#08090b`; manifest colors fixed; OG + report-cover regenerated with current
  copy and `meridian-bank.com` demo target.
- **Backend localization** — PDF report template and CLI tables were partly
  Uzbek (`Engine natijalari`, `Qanday tekshirildi`, `Manba`, `Sarlavha`,
  `Maxfiy`…) → all English; methodology now lists all seven engines;
  `lang="en"`, "Confidential" footer.
- **Verification** — site `npm run build` + `tsc --noEmit` clean; backend
  **280 tests passed**, ruff check/format clean.

## Remaining work

Mandatory — none. Next-AI priorities (`AI-HANDOFF.md`, section 8):

1. **Run the Docker image** — no Docker daemon on this machine.
2. **Full flow with Redis** — Redis not installed, API runs `queue: inline`.
3. **Real-domain ownership gate** — mock tests only, no real domain yet.
4. **Prometheus/Grafana** — metrics exist, no dashboard yet.
5. **Site ↔ API integration** — site is still static marketing.

## Verification commands

```bash
cd /Users/asadbek/sins
uv run pytest -q                                    # 280 passed
uv run ruff check src/ tests/ scripts/              # clean
uv run ruff format --check src/ tests/ scripts/     # clean
uv run alembic check                                # clean
make help                                           # commands
```

## Important notes

- Tests run against a DB ending with `_test` (`tests/conftest.py`).
- `expire_on_commit=False` → after `session.expire_all()`, reading `obj.id`
  raises `MissingGreenlet` — take the ID first.
- `prune_scans` is global (not per tenant) — call `_purge_leftovers` first in
  prune tests.
- macOS: `sed -i ''`; no `setsid`; free a port: `lsof -ti :8000 | xargs -r kill`.
- `nuclei` with `-rate-limit 50 -concurrency 10` takes ~9–10 minutes; exit 1 =
  findings present.
- Use `_resolve_tool()` for httpx resolution (`SINS_HTTPX_BIN` overrides).
