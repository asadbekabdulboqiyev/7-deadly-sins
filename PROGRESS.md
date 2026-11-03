# SINS — Ish jarayoni (progress)

> Bu fayl har qadamdan keyin yangilanadi. Maqsad: bajarilgan va qolgan ishlarni
> bir joyda, qisqa ko'rinishda saqlash.

Oxirgi yangilanish: 2026-11-03

## Holat bir qarashda

| Ko'rsatkich | Qiymat |
|---|---|
| Testlar | **197 passed** (`uv run pytest -q`) |
| Lint | `ruff check` + `ruff format --check` — toza |
| Migratsiya | `9a1f4c7d2b30` — `alembic check` toza |
| API versiya | 0.2.0 |
| Test fayllari | 14 |
| Sayt | `/Users/asadbek/sins-site` — build + desktop/mobil audit o'tgan |
| Git | barcha ishlar commit qilingan |

## Bajarildi

### Backend yadro
- Egalik darvozasi (DNS TXT / `.well-known`), lab-cheklov
- `FindingContract` — barcha tool chiqishi uchun yagona shartnoma
- `dedup.py` — `dedup_key` + `correlate()`
- `nuclei` va `osv-scanner` adapterlari, xavfsiz subprocess runner
- Orkestrator: `applies_to`, parallel bajarish, retry + eksponensial backoff
- Typer CLI, PDF hisobot (Jinja2 → WeasyPrint), FastAPI, ARQ worker, Alembic

### Operatsiya qatlami (kuchaytirish)
- `observability.py` — JSON/text log, request-ID, Prometheus registri
- `ratelimit.py` — token-bucket, kalit SHA-256 bo'yicha, `max_keys` eviction
- `middleware.py` — RequestContext (ID + access log + metrika), RateLimit (429)
- `models.py` — `ScanStatus.cancelled`, `Scan.idempotency_key` (qisman unique)
- `scan_service.py` — filtr/sahifalash, `severity_counts`, `cancel_scan`,
  `diff_scan`, `rotate_api_key`, `prune_scans`, `find_scan_by_idempotency_key`
- API: `Idempotency-Key`, sahifalash, `status`/`target_id` filtri,
  `POST /scans/{id}/cancel`, `GET /scans/{id}/diff`,
  `GET /tenant/me`, `POST /tenant/rotate-key`
- `main.py` — `/healthz` (liveness), `/readyz` (db + queue), `/metrics`
- `worker.py` — `max_tries=2`, cron: tunlik prune (03:30) + 5 daqiqalik gauge
- CLI — `prune` (`--days`, `--dry-run`) va `rotate-key`

### Infratuzilma
- `Dockerfile` — multi-stage, non-root (uid 10001), HEALTHCHECK
- `.dockerignore`, `docker-compose.yml` (`app` profili: api + worker)
- `Makefile` — `help/install/lint/fmt/test/cov/migrate/api/worker/tenant/report/demo/prune/docker-*`
- `.github/workflows/ci.yml` — lint, format check, `alembic check`, pytest + cov

### Hujjatlar
- `docs/ARCHITECTURE.md` (135), `docs/API.md` (197), `docs/SECURITY.md` (82),
  `docs/RUNBOOK.md` (149), `CONTRIBUTING.md` (73), `docs/DECISIONS.md` (63)
- `README.md` — yangi endpoint'lar, kuzatuv, hujjatlar jadvali, roadmap

### Testlar (197)
| Fayl | Soni | Nima |
|---|---|---|
| `test_service_extras.py` | 34 | idempotentlik, cancel, diff, rotate, prune, sahifalash |
| `test_targets.py` | 27 | nishon klassifikatsiyasi, lab cheklovi |
| `test_observability.py` | 23 | log formatlari, metrikalar |
| `test_api_extras.py` | 16 | idempotency, pagination, diff, tenant, /metrics |
| `test_orchestrator_retry.py` | 14 | retry siyosati |
| `test_scan_service.py` | 13 | hayotiy sikl, tenant izolyatsiyasi |
| `test_middleware.py` | 13 | request ID, rate limit, metrika |
| `test_orchestrator.py` | 11 | adapterlar, `applies_to` |
| `test_api.py` | 11 | HTTP oqimi, auth, PDF |
| `test_ratelimit.py` | 10 | token-bucket |
| qolgan 4 fayl | 25 | report, dedup, security, nuclei parse |

## Qolgan ishlar

Majburiy — yo'q. Quyidagilar ixtiyoriy/kelajak:

1. **Docker obrazini sinash** — daemon bu mashinada ishlamaydi
   (`docker build -t sins .` boshqa muhitda).
2. **Redis bilan to'liq oqim** — Redis o'rnatilmagan, API `queue: inline`.
   `docker compose up -d redis && uv run sins worker` bilan tekshirish.
3. **Haqiqiy tarmoqda egalik darvozasi** — DNS TXT/`.well-known` testi mock;
   real domenda bir marta qo'lda sinalmagan.
4. **Sprint 3–4 engine'lar** — Pride (subfinder/naabu/httpx),
   Envy (sslyze), Lust, Gluttony, Wrath.
5. **Prometheus/Grafana dashbord** — metrikalar bor, vizualizatsiya yo'q.
6. **Sayt ↔ API integratsiyasi** — sayt hozir statik marketing; live demo yo'q.

## Tekshiruv buyruqlari

```bash
cd /Users/asadbek/sins
uv run pytest -q                                    # 197 passed
uv run ruff check src/ tests/ scripts/              # toza
uv run ruff format --check src/ tests/ scripts/     # toza
uv run alembic check                                # "No new upgrade operations"
make help                                           # buyruqlar
```

## Muhim eslatmalar

- Testlar faqat `_test` bilan tugaydigan bazada ishlaydi (`tests/conftest.py`).
- `expire_on_commit=False` → `session.expire_all()`dan keyin `obj.id`ga tegish
  `MissingGreenlet` beradi: ID'ni avval oling.
- `prune_scans` global (tenant bo'yicha emas) — prune testlarida avval
  `_purge_leftovers` chaqiriladi.
- macOS: `sed -i ''`; `write` tool ishonchsiz → fayllar `cat << 'EOF'` bilan.
- `nuclei` `-rate-limit 50 -concurrency 10` bilan ~9–10 daqiqa; exit 1 = topilma bor.
