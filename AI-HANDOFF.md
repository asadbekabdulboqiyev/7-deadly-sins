# AI-HANDOFF — bu loyihada ishlaydigan AI uchun qo'llanma

> **Avval shuni o'qi.** Bu fayl — loyihaga keyin qo'shilgan AI uchun ish
> qoidalari, buyruqlar, tuzoqlar va topshirilgan vazifalar ro'yxati.
> Holat uchun: `PROGRESS.md` (yagona progress fayli). Arxitektura uchun:
> `docs/ARCHITECTURE.md`.
>
> Oxirgi tekshirilgan holat: 2026-11-04 — 252 test, 76% qamrov, lint toza,
> `alembic check` toza.

---

## 0. 30 sekundda kontekst

**Mahsulot:** "7 Deadly Sins" — avtomatlashtirilgan zaiflik/tashqi yuzani
baholash platformasi. 7 ta inglizcha gunoh nomli modul; har biri tayyor OSS
tool'ning yupqa adapteri.

**Ikki papka:**

| Papka | Nima |
|---|---|
| `/Users/asadbek/sins` | Backend: FastAPI + PostgreSQL + ARQ worker + adapterlar |
| `/Users/asadbek/sins-site` | Marketing sayt (statik, hozircha API'siz) |

**Ishlaydigan engine'lar:** `nuclei` (Greed), `osv-scanner` (Sloth),
`subfinder`+`naabu`+`httpx` (Pride), `sslyze` (Envy).
**Preview:** Lust, Gluttony, Wrath.

**Birinchi buyruqlar (majburiy):**

```bash
cd /Users/asadbek/sins
git status --short          # toza bo'lishi kerak
uv run pytest -q            # 252 passed
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run alembic check        # "No new upgrade operations detected"
```

Agar shu to'rttasi yashil bo'lmasa — **yangi ish boshlamang**, avval sababini
toping.

---

## 1. Buzilmaydigan qoidalar

1. **Nom va til.** Mahsulot nomi aynan `7 Deadly Sins`. Modullar inglizcha
   gunoh nomlari bilan (`Pride`, `Envy`, ...). Sayt matni inglizcha.
2. **Finding tili.** `title` — **inglizcha** (texnik fakt), `remediation`
   matni — **o'zbekcha**. Har bir finding'da `Remediation` bo'lishi shart.
   `tests/test_*_engine.py` ichida `title.isascii()` tekshiruvi bor.
3. **Hech qanday skaner/exploit/brute-force/DDoS logikasi yozilmaydi.**
   Faqat mavjud OSS tool'ni chaqirish, chiqishini `FindingContract` ga
   aylantirish. Bu — huquqiy pozitsiya, kelishilgan qaror
   (`docs/DECISIONS.md`).
4. **Testni o'chirish/zaiflashtirish — taqiqlanadi.** `pytest.skip(...)` bilan
   mavjud testni almashtirish, assertion'ni olib tashlash yoki testni
   "o'tadigan" qilib yozish qabul qilinmaydi. Eski testni o'zgartirish kerak
   bo'lsa — sababini commit xabarida yozing.
5. **Sxemani o'ylab topmang.** Har qanday tool chiqishini **real tool** bilan
   tekshiring (`--help`, kichik nishonda bir marta ishga tushirish). Bu
   loyihada aynan shu xato bir marta qilingan (4-bo'limga qarang).
6. **Sirlar.** API kalit, `.env`, DB dump — kodga ham, gitga ham yozilmaydi.
7. **`PROGRESS.md`** har seans oxirida yangilanadi (sana, test soni, nima
   bajarildi, nima qoldi).
8. **Aniqlik.** Talab noaniq bo'lsa — savol bering. O'zboshimchalik bilan
   "yaxshilash" qo'shmang.
9. **O'zbekcha matn.** ASCII apostrof `'` (`o'`, `g'`). Mashina tarjimasi
   uslubida yozmang: "hunarmandchilik qilinadi", "vaqdigan" kabi iboralar
   mumkin emas. Qisqa, aniq, texnik til.
10. **Ishni isbotlang.** "Tayyor" deyishdan oldin buyruqni **haqiqatan**
    ishga tushirib chiqishni ko'rsating (`sp-verification-before-completion`).

---

## 2. Buyruqlar

```bash
# O'rnatish
cd /Users/asadbek/sins
uv sync

# Testlar (PostgreSQL `sins_test` bazasida; conftest o'zi yaratadi)
uv run pytest -q
uv run pytest tests/test_pride_engine.py -q          # bitta fayl
uv run pytest -q -k "envy and hsts"                  # nom bo'yicha
uv run pytest -q --cov=sins --cov-report=term        # qamrov

# Lint / format
uv run ruff check src/ tests/ scripts/
uv run ruff format src/ tests/ scripts/              # yozish
uv run ruff format --check src/ tests/ scripts/      # tekshirish

# Migratsiya
uv run alembic upgrade head
uv run alembic check
uv run alembic revision --autogenerate -m "izoh"

# API (lokal)
uv run sins serve --port 8000
# fon rejimida:
nohup uv run sins serve --port 8010 > /tmp/sins-api-8010.log 2>&1 &

# Worker (Redis kerak)
uv run sins worker

# CLI
uv run sins --help
uv run sins tenant "Mijoz nomi"      # yangi tenant + API kalit
uv run sins demo                     # to'liq demo oqimi
uv run sins prune --days 30 --dry-run

# To'g'ridan-to'g'ri adapterni sinash (tarmoqsiz ham mumkin)
uv run python - <<'PY'
from sins.adapters.envy import EnvyAdapter
from sins.adapters.base import ScanContext
for f in EnvyAdapter().run(ScanContext(target="https://127.0.0.1:8443", timeout=120)):
    print(f.severity, f.location, f.title)
PY
```

**Test bazasi qoidasi:** `tests/conftest.py` faqat nomi `_test` bilan
tugaydigan bazada ishlaydi. `SINS_TEST_DATABASE_URL` bilan almashtiriladi.
Testlar dev bazaga (`sins`) **tegmaydi** — agar `alembic check` kutilmagan
jadval ko'rsatsa, o'sha jadval dev bazada qolgan bo'ladi (bir marta shunday
bo'lgan: `tmp_parent_test`).

---

## 3. Kod xaritasi — qayerga tegish kerak

| Fayl / papka | Vazifa | Tegish mumkinmi |
|---|---|---|
| `src/sins/schemas.py` | `FindingContract`, `Severity`, `Category` | Faqat kelishib |
| `src/sins/models.py` | SQLAlchemy modellari | Migratsiya bilan |
| `src/sins/adapters/base.py` | `Adapter` protokoli, `ScanContext` | Ehtiyotkorlik bilan |
| `src/sins/adapters/*.py` | Har bir gunoh adapteri | ✅ asosiy ish maydoni |
| `src/sins/runner.py` | Xavfsiz subprocess (`run_tool`, `which`) | Ehtiyotkorlik bilan |
| `src/sins/dedup.py` | `dedup_key`, `correlate` | Faqat test bilan |
| `src/sins/orchestrator.py` | Parallel ishga tushirish, retry | Ehtiyotkorlik bilan |
| `src/sins/services/scan_service.py` | Butun biznes-logika | Test bilan |
| `src/sins/api/` | FastAPI route'lar | ✅ |
| `src/sins/config.py` | Sozlamalar (`SINS_*`) | ✅ |
| `src/sins/targets.py` | Nishon klassifikatsiyasi | Ehtiyotkorlik bilan |
| `tests/` | Testlar | ✅ |
| `docs/` | Hujjatlar | ✅ |

**Adapter qo'shish tartibi:**

1. `src/sins/adapters/<sin>.py` — `available()`, `applies_to()`, `run()`.
2. `src/sins/adapters/__init__.py` — `REGISTRY` ga qo'shish.
3. `src/sins/config.py` va `.env.example` — `SINS_ALLOWED_ENGINES` ga qo'shish.
4. `tests/test_<sin>_engine.py` — real chiqish fixture'lari bilan testlar.
5. `README.md` (sin→tool jadvali), `docs/ARCHITECTURE.md` (modul xaritasi).
6. `PROGRESS.md` — holat va test soni.

---

## 4. Real tool chiqishi — tekshirilgan faktlar

Bu bo'lim **aynan shu loyihada** xato qilingan joy. Sxemani taxmin qilmang.

### `naabu` (v2.16)

```bash
naabu -list hosts.txt -json -silent -rate 100
```

Har bir **port** uchun alohida JSON satr (JSONL), `ports` massivi **yo'q**:

```json
{"ip":"93.184.216.34","port":443,"protocol":"tcp","tls":true}
```

- Rate bayrog'i `-rate` (eski `-rate-limit` **mavjud emas**, exit 2 beradi).
- `-list` fayl qabul qiladi.

### `httpx` (v1.10, ProjectDiscovery)

```bash
httpx -list hosts.txt -json -silent -ports 80,443,8080
```

JSONL: `{"url": "...", "status_code": 200, "title": "...", "webserver": "...", "tech": [...], "failed": false}`.

**Muhim tuzoq:** Python `httpx` — loyihaning dev dependency'si (FastAPI test
klienti), shuning uchun `.venv/bin/httpx` **doim** mavjud va `uv run` ichida
PATH'da birinchi turadi. U ProjectDiscovery binary'sini soya qiladi. Shuning uchun
`pride.py` da `_resolve_tool()` bor: `SINS_HTTPX_BIN` → PATH → `~/go/bin` va
h.k.; binary `-version` chiqishida `projectdiscovery` bo'lishi shart.
Yangi tool qo'shsangiz, xuddi shu naqshni ishlating.

### `subfinder` (v2.16)

```bash
subfinder -d example.com -json -silent
```

JSONL: `{"host": "www.example.com", "input": "example.com", "source": "crtsh"}`.
Faqat domen nishonlarida ishlaydi (IP/URL uchun ma'nosiz).

### `sslyze` (6.x, CLI)

```bash
sslyze --certinfo --compression --http_headers \
       --sslv2 --sslv3 --tlsv1 --tlsv1_1 --heartbleed \
       --json_out - host:port
```

- `--regular` **olib tashlangan** (6.x), `--jsonfile` degan flag **yo'q** —
  `--json_out -` stdout'ga JSON beradi.
- Struktura: `server_scan_results[] → scan_result.<plugin> → {status, result}`.
- `status` `COMPLETED` bo'lmasa (`NOT_SCHEDULED`, `ERROR`) — o'tkazib yuboriladi.
- Sertifikat: `certificate_info.result.certificate_deployments[0]`
  (`received_certificate_chain[0].not_valid_after` ISO-8601,
  `path_validation_results[]`, `verified_chain_has_sha1_signature`).
- Namuna: `/tmp/envy-lab/out.json` (lokal TLS serverdan olingan).

### `nuclei` (v3.11)

`-jsonl -silent`; `exit 1` = topilma bor (xato emas). `runner.RunResult.ok`
faqat `returncode == 0` ni "ok" deb biladi — nuclei adapteri buni alohida
hal qiladi.

---

## 5. Test yozish qoidalari

1. **Fixture real chiqishdan** bo'lsin. Internet/tarmoq kerak bo'lmasin:
   JSON'ni test ichida saqlang.
2. **Vaqtga bog'liq test yozmang.** Sertifikat sanasini
   `datetime.now(UTC) + timedelta(days=...)` bilan hisoblang; `2025-01-01`
   kabi qattiq sana — time-bomb.
3. **`pytest.skip` yo'q.** Test muhit talab qilsa, fake/monkeypatch yozing.
4. **Dict kaliti bilan severity tekshirmang**, agar bir nechta finding bir xil
   `location`'da bo'lsa: `{f.location: f.severity}` oxirgi finding'ni qoldirib,
   noto'g'ri natija beradi. `{f.title: f}` yoki ro'yxatdan filtrlang.
5. **Monkeypatch modul darajasida:** adapter `from ..runner import run_tool`
   qiladi, shuning uchun `monkeypatch.setattr("sins.adapters.envy.run_tool", ...)`.
6. **Hermetik:** unit testda haqiqiy tarmoq, haqiqiy tool yoki vaqtinchalik
   fayl qoldig'i bo'lmasin.
7. **Har bir finding uchun:** `title.isascii()` va `remediation is not None`.
8. Qamrov pastga tushmasin (hozir 76%); yangi modulga test yozmasdan
   qo'shmang.

---

## 6. Ma'lum tuzoqlar (audit natijasi)

Bu ro'yxat oldingi AI qilgan xatolardan tuzilgan. Takrorlamang:

| № | Xato | Qanday aniqlanadi |
|---|---|---|
| 1 | `envy.py` o'ylab topilgan JSON sxemasini (`server_info`, `certificate.notAfter`) parse qilgan — real sslyze'da 0 finding | Real tool bilan bir marta ishga tushirish |
| 2 | `sslyze --regular` / `--jsonfile` — mavjud bo'lmagan flag'lar | `sslyze --help` |
| 3 | `pride.py` naabu'ning `ports` massivini kutgan — real chiqish JSONL | `naabu -json` chiqishini ko'rish |
| 4 | `httpx` venv'dagi Python CLI'siga tushib qolgan | `uv run python -c "import shutil; print(shutil.which('httpx'))"` |
| 5 | 13 ta ishlaydigan test `pytest.skip` stub'lariga almashtirilgan | `git diff tests/`, `pytest -rs` |
| 6 | Qattiq sanali testlar (2025-01-01) — vaqt o'tishi bilan yiqiladi | Sanani `now` ga nisbatan hisoblash |
| 7 | `{f.location: f.severity}` — bir xil location'da kolliziya | Bir nechta finding bilan test |
| 8 | `MAX_FINDINGS_PER_SCAN` 5000→1000 sababsiz o'zgartirilgan | `git diff src/sins/services/scan_service.py` |
| 9 | `pyproject.toml` da `testpaths = ["tests", "src/sins"]` — ma'nosiz | `pytest --collect-only` |
| 10 | O'zbekcha matn mashina tarjimasi ("Sertifikat vaqdigan") | O'qib tekshirish |

**Qoida:** boshqa AI yozgan kodni "ishlayapti" deb qabul qilmang — real tool
va test bilan tekshiring.

---

## 7. Hozirgi holat

| Ko'rsatkich | Qiymat |
|---|---|
| Testlar | **252 passed** (2.5 s) |
| Qamrov | 76% (`--cov=sins`) |
| Lint | `ruff check` + `ruff format --check` toza (53 fayl) |
| Migratsiya | `alembic check` toza |
| Engine'lar | nuclei, osv, pride, envy |
| Docker | Dockerfile/compose bor, **daemon bu mashinada yo'q — sinalmagan** |
| Redis | o'rnatilmagan — API `queue: inline` rejimida ishlaydi |

**Bajarilgan (qisqa):** authz gate, `FindingContract`, dedup/correlate,
nuclei/osv/pride/envy adapterlari, orkestrator retry, CLI, PDF hisobot,
FastAPI (idempotency, pagination, cancel, diff, tenant rotate), ARQ worker,
Alembic, Docker/compose, CI, kuzatuv (JSON log + Prometheus + rate limit),
hujjatlar.

---

## 8. Senga topshirilgan ishlar

Quyidagilar **sizga qoldirilgan**. Tartib — tavsiya etilgan prioritet.
Har birida "tayyor" mezoni bor.

### P0. Docker oqimini ishga tushirish

- `docker build -t sins .` va `docker compose up -d` ni **haqiqiy daemon**
  bo'lgan mashinada sinash.
- Tekshirish: konteyner non-root (uid 10001), `HEALTHCHECK` yashil,
  `alembic upgrade head` ishga tushadi, `/healthz` 200.
- Fayllar: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `Makefile`.
- Tayyor mezoni: `docker compose up -d && curl localhost:8000/healthz`
  javob beradi; natijani `docs/RUNBOOK.md` ga yozish.

### P1. Redis + ARQ to'liq oqimi

- `docker compose up -d redis`, `SINS_REDIS_URL` bilan API va worker.
- Tekshirish: `POST /scans` → worker oladi → `status=completed`;
  `GET /metrics` da `sins_queue_depth` o'zgaradi.
- Tayyor mezoni: inline rejimdan tashqari yo'l ham testdan o'tadi
  (`tests/test_worker.py` qo'shish tavsiya etiladi).

### P2. Egalik darvozasini real domenda sinash

- DNS TXT yoki `/.well-known/sins-verify.txt` orqali tasdiqlash.
- Hozir faqat mock testlar bor. O'zingizga tegishli domenda bir marta qo'lda
  o'tkazing.
- Tayyor mezoni: `docs/RUNBOOK.md` da qadam-baqadam natija + skrinshot matni.

### P3. Lust (auth) engine

- G'oya: `nuclei` auth template'lari + JWT tekshiruvi (`pyjwt` allaqachon
  rejada). **Brute-force yozmang.**
- `applies_to`: URL/domain. `category=Category.auth`.
- Tayyor mezoni: adapter + testlar + README jadvali + `PROGRESS.md`.

### P4. Gluttony (resilience) — ehtiyotkorlik bilan

- Faqat **ruxsat etilgan, past yuklamali** tekshiruv (≤50 RPS), foydalanuvchi
  ochiq roziligi bilan.
- DDoS/stress-test logikasi **mutlaqo taqiqlangan** — bu loyihaning huquqiy
  chegarasi.
- Agar shubha bo'lsa — avval foydalanuvchidan so'rang.

### P5. Wrath (exploit validation)

- Faqat `nuclei` ning mavjud `-validate`/exploit template'lari orqali,
  qo'lda payload yozmasdan.
- "Tasdiqlangan ekspluatatsiya" degani — tool natijasini qayta tekshirish,
  yangi exploit yozish emas.

### P6. Prometheus/Grafana

- Metrikalar bor (`/metrics`), vizualizatsiya yo'q. Dashboard JSON qo'shing,
  `docs/RUNBOOK.md` ga ulanish yo'riqnomasi.

### P7. Sayt ↔ API integratsiyasi

- `/Users/asadbek/sins-site` hozir statik marketing. Live demo yoki
  "API kalit olish" oqimini qo'shish — **avval foydalanuvchidan ruxsat**.
- Sayt dizayn qoidalari alohida (`sins-site` ichidagi hujjat/commitlarga
  qarang): qorong'i premium baza, bitta crimson aksent, Geist/Geist Mono,
  `min-h-[100dvh]`, `py-24+`, kamida WCAG AA.

---

## 9. Ishni topshirish protokoli

**Boshlashdan oldin:**

```bash
git status --short          # iflos bo'lsa — avval egasiga ayting
uv run pytest -q
```

**Tugatishdan oldin (majburiy):**

```bash
uv run pytest -q
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run alembic check
```

**Commit formati:**

```
feat(pride): add subdomain and port surface engine
fix(envy): parse real sslyze 6.x JSON schema
test(envy): cover certificate expiry and HSTS cases
docs: refresh engine table and handoff guide
```

Sarlavha inglizcha, qisqa. Body'da o'zbekcha sabab yozish mumkin. Bitta
commit — bitta mantiqiy o'zgarish.

**`PROGRESS.md` ni yangilash:** sana, test soni, qamrov, bajarilgan ish,
qolgan ish. Bu — foydalanuvchi talab qilgan **yagona** progress fayli.

**Foydalanuvchiga hisobot:** 3–5 punkt. Halol bo'ling: nima tekshirilmagan
(Docker, Redis, real domen) — alohida yozing. "Ishlaydi" deb yozishdan oldin
buyruq chiqishini ko'rsating.

---

## 10. Tegmaslik kerak bo'lgan narsalar

Quyidagilarni **savolsiz o'zgartirmang**:

- `MAX_FINDINGS_PER_SCAN` (5000) va `MAX_EVIDENCE_BYTES` — DB himoyasi.
- `dedup.correlate()` semantikasi — hisobotdagi birlashuv shunga bog'liq.
- Authz darvozasi va API kalit hash logikasi (`security.py`, `authz.py`).
- `runner.run_tool` — argv/shell=False/killpg/timeout kafolatlari.
- Migratsiyalar tarixi — faqat yangi revision qo'shiladi.
- `tests/conftest.py` dagi `_test` bazasi qoidasi.
- Boshqa AI yozgan ishlaydigan testlarni "soddalashtirish".

**Ruxsat so'rash kerak:** yangi Python dependency, yangi tashqi servis,
ma'lumotlar modelini o'zgartirish, API'ning breaking o'zgarishi, sayt
dizaynini qayta qurish.

---

## 11. Foydali faktlar

- Tool'lar: `/Users/asadbek/go/bin/{subfinder,naabu,httpx,nuclei}`,
  `sslyze` — venv ichida (`.venv/bin/sslyze`, `uv add sslyze` bilan qo'shilgan).
- Muhit o'zgaruvchilari: `SINS_DATABASE_URL`, `SINS_REDIS_URL`,
  `SINS_ALLOWED_ENGINES`, `SINS_MAX_RPS`, `SINS_TOOL_TIMEOUT_SECONDS`,
  `SINS_SUBFINDER_BIN`, `SINS_NAABU_BIN`, `SINS_HTTPX_BIN`.
- macOS: `sed -i ''`; `setsid` yo'q; portni bo'shatish:
  `lsof -ti :8000 | xargs -r kill`.
- `expire_on_commit=False` → `session.expire_all()` dan keyin `obj.id` ga
  tegish `MissingGreenlet` beradi: ID'ni avval oling.
- `prune_scans` global (tenant bo'yicha emas) — prune testlarida avval
  `_purge_leftovers` chaqiriladi.
- Adapterlarni qo'lda sinash uchun lokal nishonlar:
  `python3 -m http.server 8080 --bind 127.0.0.1` (Pride),
  `/tmp/envy-lab/serve.py` + `cert.pem` (Envy, TLS 8443).
- Hech qachon o'zingizga tegishli bo'lmagan domenga skan yubormang.
