# Architecture

## In one sentence

7 Deadly Sins is a service that orchestrates existing open-source scanners,
normalizes their output into a single contract, and returns a remediation path.
We do not write scanners; we run them safely, observably, and multi-tenant.

## Layers

```
+--------------------------------------------------------------+
| Entry: CLI (Typer) - HTTP API (FastAPI) - ARQ worker         |
+---------------------------+----------------------------------+
                            |  every entry calls one place
+---------------------------v----------------------------------+
| services/scan_service.py - the ONLY business logic layer     |
|  ownership checks - tenant isolation - limits -              |
|  scan lifecycle - diff - pruning - key rotation              |
+---------------------------+----------------------------------+
        +-------------------+--------------------+
        v                   v                    v
   PostgreSQL          Redis + ARQ          Orchestrator
  (SQLAlchemy 2.0)     (queue, cron)     (adapters, retry)
                                                 |
                                     nuclei - osv-scanner
                                     (subprocess, argv, timeout)
```

The rule: **an HTTP route, a CLI command and a worker job never reimplement
business logic.** They only call `scan_service` functions. That is why
inconsistencies such as "validated in the API, not in the CLI" cannot appear.

## Module map

| File | Responsibility |
|---|---|
| `schemas.py` | `FindingContract` - the contract shared by the whole system (Pydantic) |
| `models.py` | SQLAlchemy: `Tenant`, `Target`, `Scan`, `Finding` |
| `targets.py` | Target type detection, normalization, lab restriction |
| `authz.py` | Ownership gate: token, DNS TXT, `.well-known` check |
| `security.py` | API key generation, SHA-256 hash, displayable prefix |
| `runner.py` | Safe subprocess: argv list, timeout, killpg, output cap |
| `adapters/base.py` | `Adapter` protocol: `available()`, `applies_to()`, `run()` |
| `adapters/nuclei.py` | Greed - CVEs and misconfigurations |
| `adapters/pride.py` | Pride - subdomains, ports, live services (subfinder, naabu, httpx) |
| `adapters/envy.py` | Envy - TLS certificate and protocols (sslyze CLI) |
| `adapters/osv.py` | Sloth - dependency audit (local directory only) |
| `dedup.py` | `dedup_key` and `correlate()` - one finding, several pieces of evidence |
| `orchestrator.py` | Parallel adapter runs, retry/backoff, `applies_to` |
| `services/scan_service.py` | The whole lifecycle and every control operation |
| `api/` | FastAPI: routes, dependencies, error handlers |
| `middleware.py` | Request ID, access log, metrics, rate limit |
| `observability.py` | JSON logging, Prometheus registry |
| `ratelimit.py` | Token-bucket limiter |
| `report/` | Jinja2 -> WeasyPrint -> PDF |
| `worker.py` | ARQ `WorkerSettings`, cron jobs |
| `cli.py` | Every capability exists here before any UI |

## Scan lifecycle

```
pending --> running --> done
   |           |  '--> failed
   |           '-----> cancelled   (the user cancelled it)
   '---------> cancelled
   '---------> blocked             (ownership gate did not pass)
```

- `pending` -> `running`: a worker takes the job and writes `started_at`.
- `running` -> `done`: findings are written by `dedup_key`, `progress=100`.
- `cancelled`: no result is written - the worker re-reads the status at the end.
- `blocked`: ownership is re-checked after 30 days; if it fails, no scan starts.
- One target runs at most one active scan at a time (`ScanBusy`).

## Idempotency

`POST /scans` accepts the `Idempotency-Key` header:

- The route looks the key up first; if it exists, the existing scan is returned
  and nothing is added to the queue.
- The database has a **partial unique index** on `(tenant_id, idempotency_key)`,
  so rows without a key (NULL) never collide.
- A network retry, or a user clicking twice, does not duplicate the scan.

## Retry policy

An adapter failure never stops the whole scan. `orchestrator._is_retryable()`:

| Error | Retried |
|---|---|
| `TimeoutError`, `ConnectionError`, `OSError`, `RuntimeError`, `subprocess.TimeoutExpired` | ✅ |
| `FileNotFoundError`, `PermissionError`, `ValueError`, `TypeError`, `ToolNotFound` | ❌ |

The attempt count comes from `SINS_ADAPTER_MAX_ATTEMPTS` (default 2), the wait
from `SINS_ADAPTER_RETRY_BACKOFF_SECONDS × 2^(n-1)`.

## Observability

| Signal | Where |
|---|---|
| Structured log (JSON) | stdout, `SINS_LOG_JSON=1` (default) |
| Request ID | `X-Request-ID` in and out, on every log record |
| Metrics | `GET /metrics` (Prometheus text) |
| Liveness | `GET /healthz` - is the process alive |
| Readiness | `GET /readyz` - are DB and queue ready |

Metrics: `sins_http_requests_total`, `sins_http_request_duration_ms`,
`sins_scans_started_total`, `sins_scans_finished_total`, `sins_scan_duration_ms`,
`sins_findings_total`, `sins_engine_runs_total`, `sins_engine_duration_ms`,
`sins_rate_limited_total`, `sins_scans{status}`.

Metrics live in process memory. With several instances Prometheus scrapes each
one separately - that is a deliberate choice (no external dependency).

## Data model (short)

```
Tenant 1 --- * Target 1 --- * Scan 1 --- * Finding
```

- `Finding.evidence` - `jsonb`; the raw tool output is capped at 4 KB.
- `Finding.dedup_key` - unique with `scan_id`: no duplicates inside one scan.
- `Scan.severities` - the levels that were requested; `info` is off by default.
- Every query is bounded by the tenant: `WHERE tenant_id = :tenant`.

## Why these decisions

Details in [`DECISIONS.md`](DECISIONS.md). The important ones:

1. **No scanner of our own** - legal risk and 6 months of work replaced by
   4 existing tools.
2. **`FindingContract`** - output from 7 different tools collapses into one shape.
3. **One service layer** - eliminates CLI/API/worker drift.
4. **Ownership gate as the first code** - scanning happens only with permission.
5. **Left out** - brute force, DDoS, hand-written exploits (liability).
