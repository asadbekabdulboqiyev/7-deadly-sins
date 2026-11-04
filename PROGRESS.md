# SINS — Ish jarayoni (progress)

> Bu fayl har qadamdan keyin yangilanadi. Maqsad: bajarilgan va qolgan ishlarni
> bir joyda, qisqa ko'rinishda saqlash.
> Keyingi AI uchun to'liq qo'llanma: `AI-HANDOFF.md`.

Oxirgi yangilanish: 2026-11-04

## Holat bir qarashda

| Ko'rsatkich | Qiymat |
|---|---|
| Testlar | **252 passed** (`uv run pytest -q`) |
| Qamrov | 76% (`pytest --cov=sins`) |
| Lint | `ruff check` + `ruff format --check` — toza (53 fayl) |
| Migratsiya | `9a1f4c7d2b30` — `alembic check` toza |
| API versiya | 0.2.0 |
| Engine'lar | `nuclei`, `osv`, `pride`, `envy` |
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

### Engine'lar (Sprint 3)
- **Pride** (`subfinder` → `naabu` → `httpx`): subdomenlar, ochiq portlar,
  jonli HTTP xizmatlar. Har bosqich best-effort; port severity jadvali;
  `_resolve_tool()` venv soyasini chetlab o'tadi.
- **Envy** (`sslyze` CLI): sertifikat muddati/ishonchliligi, zaif imzo,
  SSLv2/3 va TLS 1.0/1.1, Heartbleed, TLS compression, HSTS.
- Ikkalasi ham real tool'lar bilan jonli tekshirilgan:
  Pride → `127.0.0.1` (7 finding), Envy → lokal TLS `127.0.0.1:8443`
  (3 finding: self-signed, expiry, HSTS).

### Operatsiya qatlami
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
- `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/SECURITY.md`,
  `docs/RUNBOOK.md`, `CONTRIBUTING.md`, `docs/DECISIONS.md`
- `README.md` — sin→tool jadvali (Pride/Envy ✅), endpoint'lar, roadmap
- `AI-HANDOFF.md` — keyingi AI uchun qoidalar, buyruqlar, tuzoqlar,
  topshirilgan vazifalar

### Audit: boshqa AI xatolarini tuzatish (2026-11-04)
- `tests/test_scan_service.py` — 13 ta ishlaydigan test `pytest.skip`
  stub'lariga almashtirilgan edi → HEAD'dan tiklandi
- `envy.py` — o'ylab topilgan JSON sxemasi va mavjud bo'lmagan CLI flag'lari
  (`--regular`, `--jsonfile`) → real sslyze 6.x sxemasi bilan qayta yozildi
- `pride.py` — naabu'ning `ports` massivini kutgan → real JSONL formati;
  `-rate-limit` → `-rate`; httpx venv soyasi → `_resolve_tool()`
- Vaqtga bog'liq (time-bomb) testlar va noto'g'ri severity tekshiruvlari
  yo'q qilindi
- Sababsiz o'zgarishlar qaytarildi: `MAX_FINDINGS_PER_SCAN` 1000→5000,
  `testpaths=["tests","src/sins"]`
- Dev bazadagi `tmp_parent_test`/`tmp_child_test` qoldiqlari o'chirildi
  (`alembic check` yashil)

## Qolgan ishlar

Majburiy — yo'q. Keyingi AI uchun prioritetlar (`AI-HANDOFF.md`, 8-bo'lim):

1. **Docker obrazini sinash** — daemon bu mashinada ishlamaydi.
2. **Redis bilan to'liq oqim** — Redis o'rnatilmagan, API `queue: inline`.
3. **Haqiqiy tarmoqda egalik darvozasi** — mock testlar bor, real domen yo'q.
4. **Lust** (auth) — nuclei auth template'lari + JWT tekshiruvi.
5. **Gluttony / Wrath** — faqat past yuklama va mavjud template'lar bilan.
6. **Prometheus/Grafana** — metrikalar bor, vizualizatsiya yo'q.
7. **Sayt ↔ API integratsiyasi** — sayt hozir statik marketing.

## Tekshiruv buyruqlari

```bash
cd /Users/asadbek/sins
uv run pytest -q                                    # 252 passed
uv run ruff check src/ tests/ scripts/              # toza
uv run ruff format --check src/ tests/ scripts/     # toza
uv run alembic check                                # toza
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
- `httpx` PATH'da Python paketi bilan soyada qolishi mumkin — `_resolve_tool()`
  ishlatiladi (`SINS_HTTPX_BIN` bilan override qilinadi).
