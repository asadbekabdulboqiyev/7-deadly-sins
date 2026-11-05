# Runbook (operations)

## Daily check (2 minutes)

```bash
curl -s localhost:8000/healthz          # {"status":"ok"}
curl -s localhost:8000/readyz           # ready:true, db:ok, queue:ok
curl -s localhost:8000/metrics | grep -E "sins_scans|sins_engine_runs_total"
```

If `readyz` returns 503, read on.

## Startup

### Local

```bash
uv sync --python 3.13
docker compose up -d                    # Postgres + Redis
uv run alembic upgrade head
uv run sins serve --port 8000 --reload  # terminal 1
uv run sins worker                      # terminal 2
```

Without Redis the API runs with `queue: inline` (scans execute inside the API
process). That is dev only - in production the worker is mandatory.

### Docker

```bash
make docker-build
docker compose --profile app up -d
docker compose logs -f api worker
```

### Production checklist

- [ ] `SINS_DATABASE_URL`, `SINS_REDIS_URL` - managed services
- [ ] `SINS_LOG_JSON=1`, logs shipped to the aggregator (Loki/CloudWatch)
- [ ] `SINS_RATE_LIMIT_PER_MINUTE` - matching the customer contract
- [ ] `SINS_RETENTION_DAYS` - agreed with the DPA and the contract
- [ ] `/metrics` scraped by Prometheus (not exposed to the internet)
- [ ] Alembic `upgrade head` runs as a deploy step
- [ ] `nuclei` and `osv-scanner` versions pinned and on `PATH`

## Demo day (offline-safe)

The demo is designed to survive a venue with no internet: lab targets make
**zero** outbound calls, and every piece of history already sits in Postgres.

```bash
# 1. database + API (Redis not required: queue runs inline)
SINS_DATABASE_URL=postgresql+asyncpg://asadbek@localhost:5432/sins \
  uv run alembic upgrade head
SINS_DATABASE_URL=postgresql+asyncpg://asadbek@localhost:5432/sins \
  uv run python scripts/seed_demo.py --reset --json      # 5 scans / 8 findings
SINS_DATABASE_URL=postgresql+asyncpg://asadbek@localhost:5432/sins \
  SINS_RATE_LIMIT_ENABLED=false uv run sins serve --port 8000

# 2. site
cd ../sins-site && npm run build && npx vite preview --port 4173 --host 127.0.0.1
```

On stage: open the site → **Demo** section → press **Demo key** (tenant
`Demo Bank`, key `sins_demo_stage_key_do_not_use_in_production`) → history
fills with 5 scans → press **Run scan** → the terminal streams
`wrath/envy/lust/nuclei · %` → **Download PDF** (≈47 KB).

Known and honest:

- A **fresh** scan of the seeded lab target returns **0 findings** — no engine
  binaries on the laptop and no fixture mode. The narrative is the seeded
  drift story (new `.env`, resolved `citrix`), not "we just found something".
- `Run scan` takes ~20–25 s on the inline queue; do not click twice.
- Docker was unavailable on the last machine, so the image path is only
  verified from an earlier session.

Re-seed between rehearsals: `scripts/seed_demo.py --reset` (idempotent without
`--reset`; it will not duplicate the tenant).

## Troubleshooting

### `readyz` returns `db: down`

```bash
docker compose ps postgres
pg_isready -h localhost -p 5432
uv run alembic current
```

### `queue: inline` (must not happen in production)

```bash
redis-cli -u "$SINS_REDIS_URL" ping
docker compose logs redis
uv run sins worker        # separate process
```

### A scan is stuck in `running`

1. Check whether the worker log contains `run_scan`.
2. `job_timeout=1800` (30 min) - after that ARQ aborts the job.
3. By hand: `POST /scans/{id}/cancel`, then scan again.
4. If a tool is hung: `ps aux | grep -E "nuclei|osv"`. `killpg` may have failed;
   kill the process and check the timeout in `runner.py`.

### A scan is `failed`

`GET /scans/{id}` → the `error` field. The most common ones:

| Error | Cause | Fix |
|---|---|---|
| `ToolNotFound: nuclei` | binary missing | add it to `PATH` or mount it |
| `TimeoutExpired` | slow network / large target | raise `--rate-limit`, raise the timeout |
| `PermissionError` | template path | check permissions on `--templates` |

Retry applies to transient errors only (`ARCHITECTURE.md` → Retry policy).

### Too many findings / slow report

- The `info` level is off by default - control it through `severities`.
- PDF rendering is CPU-bound in WeasyPrint; queue requests if several run at once.
- `MAX_FINDINGS_PER_SCAN=5000` - anything above that is truncated (visible in the log).

### The database keeps growing

```bash
uv run sins prune --days 180 --dry-run   # inspect first
uv run sins prune --days 180             # delete
```

The cron job runs daily at 03:30 with `SINS_RETENTION_DAYS`.

## Incident

### An API key leaked

```bash
uv run sins rotate-key --api-key "$OLD_KEY"
# send the new key to the customer over a secure channel
```

The old key stops working **immediately**. Then check how it was used:

```bash
# the whole chain for one request_id
grep '"request_id": "<rid>"' api.log
```

### Suspicious tenant

```bash
uv run sins prune --days 0            # refuses: less than 1 day is not allowed
psql "$DB" -c "UPDATE tenants SET api_key_hash = 'revoked' WHERE id = '…'"
```

Replacing `api_key_hash` kills the key at once (same effect as rotation).

### Emergency shutdown

```bash
docker compose stop api worker   # no new work is accepted
docker compose logs --tail=200 api worker > incident.log
```

## Suggested metric alerts

| Condition | Meaning |
|---|---|
| `rate(sins_http_requests_total{status=~"5.."}[5m]) > 0.1` | server errors |
| `rate(sins_rate_limited_total[5m]) > 1` | limit too low, or abuse |
| `sins_scans{status="running"} > 4` | not enough workers |
| `rate(sins_engine_runs_total{ok="false"}[15m]) > 0` | tool failure |
| `sins_scans{status="pending"} > 10` (10 minutes) | queue is stuck |

## Backup

```bash
pg_dump "$SINS_DATABASE_URL" -Fc -f "sins-$(date +%F).dump"
pg_restore -d "$SINS_DATABASE_URL" --clean --if-exists sins-2026-11-03.dump
```

Scan results can be regenerated; **tenants and key hashes** cannot. Back up at
least daily.
