# SINS

> Ichki kod nomi: **7 DeaDly SinS**. Tijoriy nom keyin tanlanadi.
> Enterprise sotuvda "gunoh" nomlari ishlatilmaydi — faqat texnik kategoriyalar.

Attack surface va zaiflik baholash platformasi. Yadro tamoyili:

> **Biz skaner yozmaymiz. Biz tayyor open-source skanerlarni orkestrlaymiz,
> natijalarni birlashtiramiz va tuzatish yo'lini beramiz.**

## Nega bunday

| Muammo | Yechim |
|---|---|
| 7 ta modul yozish = 6 oy | 4 ta tayyor tool 7 ta vazifani bajaradi |
| Payload yozish = huquqiy risk | nuclei template'lari 10 000+ tayyor tekshiruv |
| Har xil tool = har xil format | Bitta `FindingContract` shartnomasi |
| Bir CVE 3 joyda | `correlate()` — bitta finding, uchta dalil |

## 7 sin → 4 tool

| Sin | Vazifa | Tool | Holat |
|---|---|---|---|
| Greed (2) | CVE zaifliklar | `nuclei` | ✅ tayyor |
| Sloth (7) | Dependency audit | `osv-scanner` | ✅ tayyor (faqat lokal papka) |
| Pride (1) | Attack surface | `subfinder` + `naabu` + `httpx` | ⏳ Sprint 3 |
| Envy (4) | SSL/TLS | `sslyze` (Python lib) | ⏳ Sprint 3 |
| Lust (3) | Auth flaws | nuclei auth templates + `pyjwt` | ⏳ Sprint 4 |
| Gluttony (5) | Resilience | nuclei rate-limit templates (≤50 RPS) | ⏳ Sprint 4 |
| Wrath (6) | Exploit validation | nuclei exploit templates | ⏳ Sprint 4 |

**v1 dan chiqarilgan:** Hydra brute-force, DDoS stress-test, qo'lda exploit payload.
Sabab: huquqiy javobgarlik. Batafsil — `docs/DECISIONS.md`.

### Muhim: engine'lar nishon turiga qarab filtrlanadi

Har bir adapter `applies_to(target)` beradi. Mos kelmagan engine **umuman
ishga tushirilmaydi** va hisobotda "o'tkazib yuborildi" deb ko'rsatiladi.

| Nishon turi | nuclei | osv |
|---|---|---|
| `example.com`, `https://…`, `10.0.0.1` | ✅ | — (faqat lokal papka) |
| `/path/to/repo`, `./app` | — | ✅ |

Sabab: `osv-scanner` URL'ga qarshi ishga tushirilsa osilib qoladi (real hodisa).

## Authorization gate — birinchi kod

Skandan oldin nishon egaligi isbotlanadi:

```bash
sins verify example.com
# -> token beradi
# 1-usul: _sins-verify.example.com TXT "token"
# 2-usul: https://example.com/.well-known/sins-verify-<token>

sins scan example.com --verify-token <token>
```

`--lab` bayrog'i faqat `localhost` / private IP uchun ishlaydi. Tashqi manzilga
o'tmaydi. API'da lab nishonlari yaratilishida avtomatik tasdiqlanadi
(`verify_method="lab"`), tashqi nishonlar esa DNS TXT yoki `.well-known` faylini
talab qiladi.

## Tez boshlash

```bash
uv sync --python 3.13
docker compose up -d                # PostgreSQL + Redis
uv run alembic upgrade head         # yoki (faqat dev): uv run sins init-db --drop
uv run sins adapters                # qaysi tool o'rnatilgan
```

`make help` — barcha buyruqlar. Qisqasi:

```bash
make test      # pytest
make lint      # ruff check
make api       # API (reload)
make worker    # ARQ worker
make migrate   # alembic upgrade head
```

macOS + Homebrew: `weasyprint` uchun `pango`/`gtk3` kerak —
`brew install pango gtk+3`. Kod `DYLD_FALLBACK_LIBRARY_PATH` ni o'zi qo'yadi,
qo'shimcha env sozlash shart emas.

### CLI bilan skan

```bash
python3 -m http.server 8099 &        # lab nishon

uv run sins scan http://localhost:8099 --lab -e nuclei \
  --json out/scan.json
uv run sins report out/scan.json --out out/report.pdf --tenant "Demo Bank"
```

### API bilan skan (mahsulot oqimi)

```bash
uv run sins create-tenant --name "Demo Bank"   # API kalit faqat bir marta chiqadi
uv run sins serve --port 8000                  # http://127.0.0.1:8000/docs
uv run sins worker                             # ARQ worker (skan job'lari)

export SINS_API_KEY=sins_...
uv run python scripts/e2e_demo.py http://localhost:8099
```

To'liq oqim:

| Qadam | So'rov |
|---|---|
| 1. Nishon qo'shish | `POST /targets` → javobda `verify_token` + ko'rsatmalar |
| 2. Egalikni tasdiqlash | `POST /targets/{id}/verify` (DNS TXT yoki `.well-known`) |
| 3. Skan | `POST /scans` → `202`, `{"target_id": ..., "engines": [...], "severities": [...]}` |
| 4. Holat | `GET /scans/{id}` → `status`, `progress`, `current_engine` |
| 5. Topilmalar | `GET /scans/{id}/findings?severity=critical&limit=50` |
| 6. Oldingi skan bilan farq | `GET /scans/{id}/diff` |
| 7. Bekor qilish | `POST /scans/{id}/cancel` |
| 8. PDF hisobot | `GET /scans/{id}/report.pdf` |

Autentifikatsiya: `X-API-Key: sins_...` sarlavhasi. Kalit bazada **faqat
SHA-256 hash** sifatida saqlanadi. Almashtirish: `POST /tenant/rotate-key`
(eski kalit darhol ishlamaydi).

`POST /scans` `Idempotency-Key` sarlavhasini qo'llab-quvvatlaydi: tarmoq qayta
urinishi yangi skan boshlamaydi.

### Kuzatuv va boshqaruv

| Endpoint | Ma'no |
|---|---|
| `GET /healthz` | Liveness — `{"status":"ok"}` |
| `GET /readyz` | Readiness — `{"ready":true,"db":"ok","queue":"ok"}` (503 bo'lishi mumkin) |
| `GET /metrics` | Prometheus text: so'rovlar, davomiylik, skanlar, engine'lar |
| `GET /tenant/me` | Joriy tenant (kalit prefiksi, nomi) |

`queue: "inline"` bo'lsa Redis yo'q — skanlar API jarayonida bajariladi (dev rejimi).

### Himoya va siyosat

- **Rate limit** — 600 so'rov/daqiqa (kalit/IP bo'yicha), `429` + `Retry-After`.
- **Retry** — adapter vaqtinchalik yiqilsa 2 marta urinadi (eksponensial kutish).
- **Saqlash siyosati** — `sins prune --days 180` + ARQ cron (03:30).
- **Strukturali log** — har yozuv JSON, `X-Request-ID` bilan kuzatiladi.

## Arxitektura

```
CLI / React UI
   └→ FastAPI (request-ID + rate limit middleware, X-API-Key,
                AUTHORIZATION GATE, tenant izolyatsiyasi)
        ├→ PostgreSQL  (state, findings, jsonb evidence) — Alembic migratsiyalari
        ├→ Redis + ARQ (navbat; Redis yo'q bo'lsa inline fallback)
        └→ Worker  (faqat orkestratsiya — o'zi skan qilmaydi)
             └→ nuclei / osv-scanner  (tayyor tool'lar, xavfsiz subprocess)
                  → parser → FindingContract → correlate() → PostgreSQL
        → Hisobot: Jinja2 HTML → WeasyPrint → PDF
```

## Kod tuzilishi

```
src/sins/
  schemas.py       # FindingContract — butun tizimning shartnomasi
  models.py        # SQLAlchemy: Tenant, Target, Scan, Finding
  authz.py         # Authorization gate (DNS TXT / HTTP fayl)
  targets.py       # nishon turi, normalizatsiya, lab-cheklovi
  security.py      # API kalit generatsiyasi + SHA-256 hash
  runner.py        # Xavfsiz subprocess (timeout, killpg, argv)
  dedup.py         # dedup_key + correlate() — aggregatorning yuragi
  orchestrator.py  # adapterlarni parallel ishga tushirish + retry + applies_to
  observability.py # JSON logging, request-ID, Prometheus metrikalar
  ratelimit.py     # token-bucket limitter
  middleware.py    # request konteksti, access log, 429
  adapters/
    base.py        # Adapter protokoli (available / applies_to / run)
    nuclei.py      # Greed
    osv.py         # Sloth
  services/
    scan_service.py  # YAGONA biznes-logika (CLI, API, worker shu yerni chaqiradi)
  api/
    main.py        # FastAPI app, lifespan, xato handler'lari
    deps.py        # X-API-Key → Tenant
    routes/        # targets.py, scans.py, tenant.py
  report/          # Jinja2 shablon + WeasyPrint renderer
  worker.py        # ARQ WorkerSettings + cron (prune, metrikalar)
  cli.py           # barcha funksiyalar UI dan oldin shu yerda
migrations/        # Alembic (sxema + idempotency indeksi)
docs/              # ARCHITECTURE, API, SECURITY, RUNBOOK, DECISIONS
Dockerfile         # multi-stage, non-root, healthcheck
Makefile           # kunlik buyruqlar
.github/workflows/ # CI: lint, format, alembic check, test
```

## Yo'l xaritasi

| Bosqich | Holat | Natija |
|---|---|---|
| **0 — poydevor** | ✅ | authz gate, `FindingContract`, nuclei adapter, CLI |
| **1 — DB + API** | ✅ | Alembic, FastAPI, ARQ, tenant/scan oqimi, 130+ test |
| **1.5 — operatsiya** | ✅ | metrikalar, rate limit, idempotentlik, diff, cancel, retention, Docker, CI |
| **2 — 2-modul + PDF** | ✅ | osv adapter, `applies_to` filtri, professional PDF |
| **3 — dashboard** | ⏳ | React, SSE progress, jadvallar |
| **4 — pilot** | ⏳ | **1 ta real mijoz, real hisobot** |

Keyingi modul faqat pilot mijoz feedback'idan keyin.

## Hujjatlar

| Fayl | Nima |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Qatlamlar, hayotiy sikl, retry, kuzatuv |
| [`docs/API.md`](docs/API.md) | Barcha endpoint'lar, so'rov/javob namunalari |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Tahdid modeli, egalik darvozasi, subprocess |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Ishga tushirish, muammolar, incident |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Nega shunday qarorlar qabul qilingan |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Kod qoidalari, testlar, PR |
| [`PROGRESS.md`](PROGRESS.md) | Bajarilgan va qolgan ishlar (joriy holat) |

## Testlar

```bash
uv run pytest -q                 # 130+ test (alohida `sins_test` bazasida)
uv run ruff check src/ tests/ scripts/
uv run alembic check             # model ↔ migratsiya driftini tekshiradi
```

Testlar `_test` bilan tugamaydigan baza nomini **rad etadi** — tasodifan prod
bazani o'chirib yuborishning oldini oladi.
