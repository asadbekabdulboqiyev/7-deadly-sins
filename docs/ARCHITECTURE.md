# Arxitektura

## Bir jumlada

SINS — tayyor open-source skanerlarni orkestrlaydigan, natijalarni yagona
shartnomaga keltiradigan va tuzatish yo'lini beradigan xizmat. Biz skaner
yozmaymiz; biz ularni xavfsiz, kuzatiladigan va ko'p mijozli qilib ishlatamiz.

## Qatlamlar

```
┌──────────────────────────────────────────────────────────────┐
│ Kirish: CLI (Typer) · HTTP API (FastAPI) · ARQ worker        │
└───────────────────────────┬──────────────────────────────────┘
                            │  barchasi bitta joyni chaqiradi
┌───────────────────────────▼──────────────────────────────────┐
│ services/scan_service.py — YAGONA biznes-logika qatlami      │
│  egalik tekshiruvi · tenant izolyatsiyasi · limitlar ·       │
│  skan hayotiy sikli · diff · tozalash · kalit rotatsiyasi    │
└───────────────────────────┬──────────────────────────────────┘
        ┌───────────────────┼────────────────────┐
        ▼                   ▼                    ▼
   PostgreSQL          Redis + ARQ          Orkestrator
  (SQLAlchemy 2.0)     (navbat, cron)     (adapterlar, retry)
                                                 │
                                     nuclei · osv-scanner
                                     (subprocess, argv, timeout)
```

Qoida: **HTTP route, CLI buyrug'i va worker job'i hech qachon biznes-qoidani
takrorlamaydi**. Ular faqat `scan_service` funksiyalarini chaqiradi. Shu tufayli
"API'da tekshiriladi, CLI'da yo'q" kabi nomuvofiqlik paydo bo'lmaydi.

## Modul xaritasi

| Fayl | Vazifa |
|---|---|
| `schemas.py` | `FindingContract` — butun tizim orasidagi shartnoma (Pydantic) |
| `models.py` | SQLAlchemy: `Tenant`, `Target`, `Scan`, `Finding` |
| `targets.py` | Nishon turini aniqlash, normalizatsiya, lab-cheklovi |
| `authz.py` | Egalik darvozasi: token, DNS TXT, `.well-known` tekshiruvi |
| `security.py` | API kalit generatsiyasi, SHA-256 hash, ko'rsatiladigan prefiks |
| `runner.py` | Xavfsiz subprocess: argv ro'yxati, timeout, killpg, chiqish chegarasi |
| `adapters/base.py` | `Adapter` protokoli: `available()`, `applies_to()`, `run()` |
| `adapters/nuclei.py` | Greed — CVE va noto'g'ri sozlashlar |
| `adapters/pride.py` | Pride — subdomen/port/jonli xizmatlar (subfinder, naabu, httpx) |
| `adapters/envy.py` | Envy — TLS sertifikati va protokollari (sslyze CLI) |
| `adapters/osv.py` | Sloth — dependency auditi (faqat lokal papka) |
| `dedup.py` | `dedup_key` va `correlate()` — bitta topilma, bir nechta dalil |
| `orchestrator.py` | Adapterlarni parallel ishga tushirish, retry/backoff, `applies_to` |
| `services/scan_service.py` | Butun hayotiy sikl va boshqaruv amallari |
| `api/` | FastAPI: deps, routes, sxemalar, xato handler'lari |
| `middleware.py` | Request ID, access log, metrikalar, rate limit |
| `observability.py` | JSON logging, Prometheus registri |
| `ratelimit.py` | Token-bucket limitter |
| `report/` | Jinja2 → WeasyPrint → PDF |
| `worker.py` | ARQ `WorkerSettings`, cron job'lar |
| `cli.py` | Barcha funksiyalar UI'dan oldin shu yerda |

## Skan hayotiy sikli

```
pending ──► running ──► done
   │           │  └──► failed
   │           └─────► cancelled   (foydalanuvchi bekor qildi)
   └─────────► cancelled
   └─────────► blocked             (egalik darvozasi o'tmadi)
```

- `pending` → `running`: worker job'ni oladi, `started_at` yoziladi.
- `running` → `done`: topilmalar `dedup_key` bo'yicha yoziladi, `progress=100`.
- `cancelled`: natija yozilmaydi — worker yakunda holatni qayta o'qiydi.
- `blocked`: 30 kundan keyin egalik qayta tekshiriladi; o'tmasa skan boshlanmaydi.
- Bitta nishonda bir vaqtda faqat bitta faol skan (`ScanBusy`).

## Idempotentlik

`POST /scans` `Idempotency-Key` sarlavhasini qabul qiladi:

- Route avval kalitni qidiradi; topilsa — mavjud skan qaytariladi, navbatga
  hech narsa qo'shilmaydi.
- Bazada `(tenant_id, idempotency_key)` uchun **qisman unique indeks** —
  kalit berilmagan qatorlar (NULL) to'qnashmaydi.
- Tarmoq qayta urinishi yoki foydalanuvchi ikki marta bosishi skanni
  takrorlamaydi.

## Retry siyosati

Adapter xatosi butun skanni to'xtatmaydi. `orchestrator._is_retryable()`:

| Xato | Qayta urinish |
|---|---|
| `TimeoutError`, `ConnectionError`, `OSError`, `RuntimeError`, `subprocess.TimeoutExpired` | ✅ |
| `FileNotFoundError`, `PermissionError`, `ValueError`, `TypeError`, `ToolNotFound` | ❌ |

Urinishlar soni `SINS_ADAPTER_MAX_ATTEMPTS` (sukut 2), kutish
`SINS_ADAPTER_RETRY_BACKOFF_SECONDS × 2^(n-1)`.

## Kuzatuv (observability)

| Signal | Joy |
|---|---|
| Strukturali log (JSON) | stdout, `SINS_LOG_JSON=1` (sukut) |
| Request ID | `X-Request-ID` kirish/chiqish, barcha log yozuvlarida |
| Metrikalar | `GET /metrics` (Prometheus text) |
| Liveness | `GET /healthz` — jarayon tirikmi |
| Readiness | `GET /readyz` — DB va navbat tayyormi |

Metrikalar: `sins_http_requests_total`, `sins_http_request_duration_ms`,
`sins_scans_started_total`, `sins_scans_finished_total`, `sins_scan_duration_ms`,
`sins_findings_total`, `sins_engine_runs_total`, `sins_engine_duration_ms`,
`sins_rate_limited_total`, `sins_scans{status}`.

Metrikalar jarayon xotirasida. Ko'p instansiya bo'lsa Prometheus har birini
alohida scrape qiladi — bu ongli tanlov (tashqi bog'liqlik yo'q).

## Ma'lumot modeli (qisqa)

```
Tenant 1─┬─< Target 1─┬─< Scan 1─< Finding
         └────────────┘
```

- `Finding.evidence` — `jsonb`, xom tool chiqishi 4 KB bilan cheklanadi.
- `Finding.dedup_key` — `(scan_id, dedup_key)` unique: bir skanda takror yo'q.
- `Scan.severities` — qidirilgan darajalar; `info` sukut bo'yicha o'chiq.
- Har bir so'rov tenant bilan chegaralangan: `WHERE tenant_id = :tenant`.

## Nega shunday qarorlar

Batafsil: [`DECISIONS.md`](DECISIONS.md). Eng muhimlari:

1. **Skaner yozmaslik** — huquqiy risk va 6 oylik ish o'rniga 4 ta tayyor tool.
2. **`FindingContract`** — 7 xil tool chiqishi bitta shaklga tushadi.
3. **Bitta servis qatlami** — CLI/API/worker nomuvofiqligini yo'q qiladi.
4. **Egalik darvozasi birinchi kod** — skanerlash faqat ruxsat bilan.
5. **Chiqarilganlar** — brute-force, DDoS, qo'lda exploit (javobgarlik).
