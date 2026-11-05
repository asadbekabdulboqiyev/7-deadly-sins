# AI Handoff — Instructions for the AI Working on This Project

> **Read this first.** This file is the working instruction set for any AI that
> joins the project later. The current state lives in `PROGRESS.md` (the single
> progress file). Architecture: `docs/ARCHITECTURE.md`.

> Last verified state: 2026-11-05 — **308 tests**, lint clean, format clean,
> `alembic check` clean.

---

## 0. Context in 30 seconds

**Product:** "7 Deadly Sins" — an automated exposure / vulnerability surface
assessment platform. Seven English sin-named modules, each backed by a ready
open-source tool adapter.

**Two folders:**

| Folder | What |
|---|---|
| `/Users/asadbek/sins` | Backend: FastAPI + PostgreSQL + ARQ worker + adapters |
| `/Users/asadbek/sins-site` | Marketing site (static, no API wired yet) |

**Running engines:** `nuclei` (Greed), `osv-scanner` (Sloth),
`subfinder` + `naabu` + `httpx` (Pride), `sslyze` (Envy), `httpx` (Lust),
`httpx` (Gluttony), nuclei templates via `Wrath`.

**First commands (mandatory):**

```bash
cd /Users/asadbek/sins
git status --short          # must be clean
uv run pytest -q            # 280 passed
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run alembic check        # "No new upgrade operations detected"
```

If any of these is red — **do not start new work**, first find the cause.

---

## 1. Immutable rules

1. **Product name.** Exactly `7 Deadly Sins`. Module names are English sins
   (`Pride`, `Envy`, ...). Site copy is English.
2. **Finding language.** All user-facing strings are English: finding
   `title`, `remediation.summary`, `steps`, risk grades (`CRITICAL` / `HIGH` /
   `MEDIUM` / `LOW` / `NONE`). ASCII apostrophe `'` (e.g. `o'zgaruvchi`). No
   Cyrillic characters anywhere in text files. No machine-translation style.
3. **No scanner / exploit / brute-force / DDoS logic.** Only orchestrating
   existing OSS tools and converting output into `FindingContract`. This is the
   legal positioning; the decision is recorded in `docs/DECISIONS.md`.
4. **Tests cannot be skipped or weakened.** Replacing a live test with a
   `pytest.skip(...)` stub, removing an assertion, or writing a test that passes
   by failing is rejected. If an old test must change, state the reason in the
   commit message.
5. **Verify schemas against the real tool before trusting them.** Every tool
   output contract was validated once in this project (see section 4).
6. **Secrets.** API keys, `.env`, DB dumps — never in code or git.
7. **`PROGRESS.md`** is updated after each session (date, test count, what was
   done, what is left).
8. **Precision.** If the requirement is vague — ask. Do not add your own
   initiative.
9. **Proof the work.** Before saying "ready", run the command and show the
   output (`sp-verification-before-completion`).

---

## 2. Commands

```bash
# Setup
cd /Users/asadbek/sins
uv sync

# Tests (PostgreSQL `sins_test` database; conftest creates it)
uv run pytest -q
uv run pytest tests/test_pride_engine.py -q          # one file
uv run pytest -q -k "envy and hsts"                  # by name
uv run pytest -q --cov=sins --cov-report=term        # coverage

# Lint / format
uv run ruff check src/ tests/ scripts/
uv run ruff format src/ tests/ scripts/              # write
uv run ruff format --check src/ tests/ scripts/      # check

# Migrations
uv run alembic upgrade head
uv run alembic check
uv run alembic revision --autogenerate -m "note"

# API (local)
uv run sins serve --port 8000
# background:
nohup uv run sins serve --port 8010 > /tmp/sins-api-8010.log 2>&1 &

# Worker (requires Redis)
uv run sins worker

# CLI
uv run sins --help
uv run sins tenant "Client name"       # new tenant + API key
uv run sins demo                      # full pipeline demo
uv run sins prune --days 30 --dry-run

# Direct adapter smoke test (works without extra tooling)
uv run python - <<'PY'
from sins.adapters.envy import EnvyAdapter
from sins.adapters.base import ScanContext
for f in EnvyAdapter().run(ScanContext(target="https://127.0.0.1:8443", timeout=120)):
    print(f.severity, f.location, f.title)
PY
```

**Test database rule:** `tests/conftest.py` only runs against a database name
ending with `_test`. Override with `SINS_TEST_DATABASE_URL`. Tests never touch
the dev database (`sins`).

---

## 3. Code map — where things live

| File / folder | Task | Editable |
|---|---|---|
| `src/sins/schemas.py` | `FindingContract`, `Severity`, `Category` | With care |
| `src/sins/models.py` | SQLAlchemy models | With migration |
| `src/sins/adapters/base.py` | `Adapter` protocol, `ScanContext` | Careful |
| `src/sins/adapters/*.py` | One adapter per sin | **Main work area** |
| `src/sins/drift.py` | Exposure fingerprint / weight / score / age | New |
| `src/sins/services/drift_service.py` | Finding-state upsert + timeline | New |
| `src/sins/runner.py` | Safe subprocess (`run_tool`, `which`) | Careful |
| `src/sins/dedup.py` | `dedup_key`, `correlate` | Tests only |
| `src/sins/orchestrator.py` | Parallel run, retry | Careful |
| `src/sins/services/scan_service.py` | All business logic | Tests |
| `src/sins/api/` | FastAPI routes | OK |
| `src/sins/config.py` | Settings (`SINS_*`) | OK |
| `src/sins/targets.py` | Target classification | Careful |
| `tests/` | Tests | OK |
| `docs/` | Docs | OK |
| `migrations/versions/` | Alembic migrations | With migration |

**Adding an adapter, in order:**

1. `src/sins/adapters/<sin>.py` — `available()`, `applies_to()`, `run()`.
2. Register in `src/sins/adapters/__init__.py` `REGISTRY`.
3. Add to `SINS_ALLOWED_ENGINES` in `src/sins/config.py` and `.env.example`.
4. Add `tests/test_<sin>_engine.py` — tests with real-output fixtures.
5. Update `README.md` (sin→tool table), `docs/ARCHITECTURE.md` (module map).
6. Update `PROGRESS.md`.

---

## 4. Real tool output — verified facts

This section covers the places where a previous AI made mistakes.

### `naabu` (v2.16)

```bash
naabu -list hosts.txt -json -silent -rate 100
```

One JSON line **per port** (JSONL), no `ports` array:

```json
{"ip":"93.184.216.34","port":443,"protocol":"tcp","tls":true}
```

- Rate flag is `-rate` (the old `-rate-limit` does not exist, exits 2).
- `-list` accepts a file.

### `httpx` (v1.10, ProjectDiscovery)

```bash
httpx -list hosts.txt -json -silent -ports 80,443,8080
```

JSONL: `{"url": "...", "status_code": 200, "title": "...", "webserver": "...", "tech": [...], "failed": false}`.

**Critical trap:** the Python `httpx` package is a dev dependency of this
project (FastAPI test client), so `.venv/bin/httpx` **always** exists and wins
over the PATH inside `uv run`. That is why `pride.py` has `_resolve_tool()`:
`SINS_HTTPX_BIN` → PATH → `~/go/bin` and others; the binary must report
`projectdiscovery` on `-version`.

### `subfinder` (v2.16)

```bash
subfinder -d example.com -json -silent
```

JSONL: `{"host": "www.example.com", "input": "example.com", "source": "crtsh"}`.
Only for domain inputs (no value for IP/URL).

### `sslyze` (6.x, CLI)

```bash
sslyze --certinfo --compression --http_headers \
       --sslv2 --sslv3 --tlsv1 --tlsv1_1 --heartbleed \
       --json_out - host:port
```

- `--regular` was removed (6.x); `--jsonfile` does not exist — use `--json_out -`.
- Structure: `server_scan_results[] → scan_result.<plugin> → {status, result}`.
- `status` must be `COMPLETED`; `NOT_SCHEDULED` / `ERROR` → skip.
- Certificate: `certificate_info.result.certificate_deployments[0]`
  (`received_certificate_chain[0].not_valid_after` ISO-8601, ...).
- Sample: `/tmp/envy-lab/out.json`.

### `nuclei` (v3.11)

`-jsonl -silent`; exit `1` means findings present (not an error). The
`runner.RunResult.ok` property only checks `returncode == 0` — the nuclei
adapter handles this separately.

### Lust (auth posture) — added 2026-11-04

- Probe: `httpx -list <hosts> -json -silent -irr -x GET` (httpx binary, JSONL).
- Response payload keys: `failed`, `scheme`, `url`, `host`, `body`,
  `content_type`, `raw_header`.
- `raw_header` is a full raw HTTP response string; header names are lowercased
  **with hyphen** (`www-authenticate`, `set-cookie`).
- Checks: Basic over plain HTTP, login form over plain HTTP, cookie Secure /
  HttpOnly / SameSite, JWT structural hygiene (alg=none, missing exp, long-lived).
- Deliberately excludes brute force / credential guessing.

### Gluttony (resilience posture) — added 2026-11-04

- Two probes: GET (server header, X-Powered-By) and OPTIONS (Allow header).
- Dangerous methods: `PUT`, `DELETE`, `PATCH`, `TRACE` intersect with allowed set.
- Deliberately excludes load/stress testing.

### Wrath (exploit confirmation) — added 2026-11-04

- Re-runs nuclei with `-t <templates>` from `ScanContext.templates`.
- Confirms a nuclei finding when a prior finding matches: same `dedup_key` or
  CVE intersection.
- Confirmed finding: title prefix `Confirmed exploit: `, evidence
  `confirmed: true`, source `wrath`, `source_tools: ["nuclei", "wrath"]`,
  `dedup_key: f"wrath|{finding.dedup_key}"`.

---

## 5. Test writing rules

1. **Fixtures from real output.** Keep JSON inside the test file; no network
   / tooling needed.
2. **Time-dependent tests.** Compute certificate expiry via
   `datetime.now(UTC) + timedelta(days=...)`. Never hardcode dates like
   `2025-01-01`.
3. **No `pytest.skip`.** Use fakes / monkeypatch.
4. **Severity checks:** use `{f.title: f}` or filter by list — not
   `{f.location: f.severity}` when several findings share a location.
5. **Monkeypatch module level:** the adapter does
   `from ..runner import run_tool`, so patch
   `monkeypatch.setattr("sins.adapters.<sin>.run_tool", ...)`.
6. **Hermetic:** no real network, no real tool, no time-sensitive file.
7. **Per finding:** `title.isascii()` and `remediation is not None`.
8. **Coverage:** do not drop below current level; add tests for a new module.

---

## 6. Known errors (audit results) — fixed in this session

| # | Error | Cause | Fix |
|---|---|---|---|
| 1 | Lust basic auth test found nothing | Header key normalized to lowercase + hyphen (`www-authenticate`) but read with underscore (`www_authenticate`) | Adapter fixed |
| 2 | Lust cookie tests expected findings on Secure cookies | Test passed cookie with `Secure` while expecting a finding | Tests fixed |
| 3 | Gluttony fake crashed on OPTIONS-only payloads | Default fallback `responses["GET"]` | Fake fixed |
| 4 | Wrath confirm test failed | Payload lacked `info.classification.*`; dedup key mismatch | Tests fixed |
| 5 | Drift score expectation wrong | Score is `56.67` for critical+high+medium | Test fixed |
| 6 | `risk_grade` returned Uzbek labels | Now returns `CRITICAL/HIGH/MEDIUM/LOW/NONE` | Fixed + tests updated |
| 7 | `conftest.py` had unterminated triple-quoted string | Broken docstring | Fixed |

**Rule:** do not accept "it works on my machine" — verify via commands listed in
section 2.

---

## 7. Current state

| Metric | Value |
|---|---|
| Tests | **280 passed** |
| Coverage | ~76% (`--cov=sins`) |
| Lint | `ruff check` + `ruff format --check` clean (63 files) |
| Migrations | head `c3d4e5f6a7b8` — `alembic check` clean |
| Engines | all 7 enabled by default: `nuclei,osv,pride,envy,lust,gluttony,wrath` |
| Drift | `finding_states` + regressions + exposure timeline implemented |
| Docker | image/compose exist, **daemon unavailable on this machine — unverified** |
| Redis | not installed — API runs `queue: inline` |

**Completed (recent):** Lust, Gluttony, Wrath adapters + tests; drift module,
drift service, `FindingState`, `regressions` column, scan wiring, `ScanDiff`
regressed flag, `ScanContext.prior_findings`, `risk_grade` English.

**Blocked:** Docker build/compose (no daemon), Redis-backed worker flow,
real ownership-gate verification.

---

## 8. Assigned work — priorities

1. **P0.** Real-domain ownership gate — needs a domain the owner controls.
2. **P1.** Engine binaries in the image (`nuclei`, `osv-scanner`, `subfinder`,
   `naabu`, `httpx`) — without them a container scan finds nothing.
3. **P2.** A live `Run scan` that returns findings (binaries above, or a
   clearly labelled `simulated: true` fixture mode). Today it honestly returns
   **0 findings**; the demo leans on `scripts/seed_demo.py`.
4. **P3.** KEV/EPSS on `GET /scans/{id}/findings` — enrichment is report-only.
5. **P4.** Drift section on the site is still "illustrative" — needs
   `GET /public/demo/drift` or a read-only real timeline.

Done already: Docker compose stack, Redis/ARQ flow, and API ↔ site integration
(SSE + diff + PDF).

---

## 9. Completion protocol

Before finishing:

```bash
uv run pytest -q
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run alembic check
```

**Commit format:**

```
feat(pride): add subdomain and port surface engine
fix(envy): parse real sslyze 6.x JSON schema
test(envy): cover certificate expiry and HSTS cases
docs: refresh engine table and handoff guide
```

Title in English, short. Body may contain Uzbek reasoning. One commit —
one logical change.

**Update `PROGRESS.md`:** date, test count, coverage, done work, left work.

**Report to the user:** 3–5 points. Be honest: what was not verified (Docker,
Redis, real domain) — write it separately. Before writing "done", show the
command output.

---

## 10. Do not touch without asking

- `MAX_FINDINGS_PER_SCAN` (5000) and `MAX_EVIDENCE_BYTES` — DB protection.
- `dedup.correlate()` semantics — tied to report correlation.
- Authz gate and API key hash logic (`security.py`, `authz.py`).
- `runner.run_tool` — argv / shell=False / killpg / timeout guards.
- Migration history — only add new revisions.
- `tests/conftest.py` `_test` DB rule.

**Asking is required:** new Python dependency, new external service,
data-model change, breaking API change, redesign of site design.

---

## 11. Useful facts

- Tools: `/Users/asadbek/go/bin/{subfinder,naabu,httpx,nuclei}`,
  `sslyze` inside venv (`.venv/bin/sslyze`, added via `uv add sslyze`).
- Env vars: `SINS_DATABASE_URL`, `SINS_REDIS_URL`, `SINS_ALLOWED_ENGINES`,
  `SINS_MAX_RPS`, `SINS_TOOL_TIMEOUT_SECONDS`, `SINS_SUBFINDER_BIN`,
  `SINS_NAABU_BIN`, `SINS_HTTPX_BIN`.
- macOS: `sed -i ''`; no `setsid`; free a port:
  `lsof -ti :8000 | xargs -r kill`.
- `expire_on_commit=False` → after `session.expire_all()` reading `obj.id` raises
  `MissingGreenlet` — take the ID first.
- `prune_scans` is global (not per-tenant) — call `_purge_leftovers` first in
  prune tests.
- Local probes for adapter-level testing:
  `python3 -m http.server 8080 --bind 127.0.0.1` (Pride),
  `/tmp/envy-lab/serve.py` + `cert.pem` (Envy, TLS 8443).
- Never scan a domain you do not own.
