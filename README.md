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
| Sloth (7) | Dependency audit | `osv-scanner` | ⚠️ adapter yozilgan, tool o'rnatilmagan |
| Pride (1) | Attack surface | `subfinder` + `naabu` + `httpx` | ⏳ Sprint 2 |
| Envy (4) | SSL/TLS | `sslyze` (Python lib) | ⏳ Sprint 2 |
| Lust (3) | Auth flaws | nuclei auth templates + `pyjwt` | ⏳ Sprint 3 |
| Gluttony (5) | Resilience | nuclei rate-limit templates (≤50 RPS) | ⏳ Sprint 3 |
| Wrath (6) | Exploit validation | nuclei exploit templates | ⏳ Sprint 3 |

**v1 dan chiqarilgan:** Hydra brute-force, DDoS stress-test, qo'lda exploit payload.
Sabab: huquqiy javobgarlik. Batafsil — `docs/DECISIONS.md`.

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
o'tmaydi.

## Tez boshlash

```bash
uv sync --python 3.13
docker compose up -d redis          # Celery uchun (keyingi sprint)
createdb sins
uv run sins init-db
uv run sins adapters
```

### Birinchi skan (lab)

```bash
# 1. Lokal nishon ko'tarish
python3 -m http.server 8099 &

# 2. Skan
uv run sins scan http://localhost:8099 --lab -e nuclei \
  -t ~/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml \
  -s info --json out/scan.json
```

## Arxitektura

```
CLI / React UI
   └→ FastAPI (auth, quota, AUTHORIZATION GATE)
        ├→ PostgreSQL  (state, findings, jsonb evidence)
        ├→ Redis       (queue + pubsub + rate-limit)
        └→ Celery worker  (faqat orkestratsiya — skan qilmaydi)
             └→ Ephemeral Docker (alohida netns, egress IP pool)
                  └→ nuclei / nmap / trivy / osv-scanner
             → parser → FindingContract → correlate() → PostgreSQL
        → Report worker (Jinja2 HTML → WeasyPrint → PDF)
```

## Kod tuzilishi

```
src/sins/
  schemas.py       # FindingContract — butun tizimning shartnomasi
  models.py        # SQLAlchemy: Tenant, Target, Scan, Finding
  authz.py         # Authorization gate (DNS TXT / HTTP fayl)
  runner.py        # Xavfsiz subprocess (timeout, killpg, argv)
  dedup.py         # dedup_key + correlate() — aggregatorning yuragi
  orchestrator.py  # adapterlarni parallel ishga tushirish
  adapters/
    base.py        # Adapter protokoli
    nuclei.py      # Greed
    osv.py         # Sloth
  cli.py           # barcha funksiyalar UI dan oldin shu yerda
```

## Yo'l xaritasi

| Bosqich | Muddat | Natija |
|---|---|---|
| **0 — poydevor** | ✅ bajarildi | authz gate, Finding sxema, nuclei adapter, CLI, 12 test |
| 1 — DB + API | 1–2 hafta | Alembic, FastAPI, Celery, task status |
| 2 — 2-modul | 3–4 hafta | osv adapter, PDF hisobot (Jinja2 + WeasyPrint) |
| 3 — dashboard | 5–6 hafta | React, SSE progress, jadvallar |
| 4 — pilot | 7–8 hafta | **1 ta real mijoz, real hisobot** |

Keyingi modul faqat pilot mijoz feedback'idan keyin.

## Testlar

```bash
uv run pytest -q
uv run ruff check src/ tests/
```
