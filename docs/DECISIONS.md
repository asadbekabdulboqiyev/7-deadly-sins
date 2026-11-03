# SINS — qarorlar hujjati (ADR)

Barcha arxitekturiy qarorlar shu yerda qayd etiladi.

## ADR-1: 7 sin → 4 tayyor tool (Greed, Sloth, Pride, Envy)

**Holat:** qabul qilindi.

Nechta o'z skaner yozish (6 oy) o'rniga, tayyor open-source skanerlarni orkestrlaymiz:
- nuclei (Greed — CVE), osv-scanner (Sloth — dependency), subfinder+naabu+httpx (Pride — attack surface), sslyze (Envy — SSL/TLS).

**Sabab:** Ishlash tezligi, 10 000+ nuclei template, `FindingContract` shartnomasi orqali birlash.

**Cheklov:** Hydra brute-force, DDoS, qo'lda exploit payload v1 dan chiqarilgan (huquqiy javobgarlik).

## ADR-2: PostgreSQL (MongoDB o'rniga)

**Holat:** qabul qilindi.

State, findings, JSONB evidence uchun PostgreSQL. SQLAlchemy + Alembic sxema boshqaruvi.

## ADR-3: `applies_to` adapter filtering (osv hangini oldini olish)

**Holat:** qabul qilindi.

Har bir adapter `applies_to(target) -> bool` beradi. Mos kelmagan engine ishga tushirilmaydi va `EngineReport(skipped=True, skip_reason=...)` orqali progress callbackga yuboriladi (progress 100% ga yetadi). PDF da skipped engine "—" / "o'tkazib yuborildi" ko'rinadi.

| Nishon | nuclei | osv |
|---|---|---|
| domain/url/ip | ✅ | — |
| lokal papka | — | ✅ |

**Sabab:** `osv-scanner` URL'ga qarshi ishga tushirilganda osilib qoladi (real hodisa).

## ADR-4: Alembic sxema manba (`init-db` faqat dev)

**Holat:** qabul qilindi.

`alembic.ini` da URL yo'q (`SINS_DATABASE_URL` dan `migrations/env.py` oladi). `prepend_sys_path = %(here)s/src`. `alembic upgrade head` — sxema manba. `init-db` — faqat lokal dev (`--drop` bilan).

**Tekshiruv:** `uv run alembic check` — "No new upgrade operations detected" bo'lishi kerak (model ↔ migration drift yo'q).

## ADR-5: API kalit xavfsizligi (SHA-256 hash, bir marta ko'rsatiladi)

**Holat:** qabul qilindi.

`Tenant.api_key_hash` — SHA-256 hash. `api_key_prefix` — ko'rsatish uchun. Raw key `sins create-tenant` da faqat bir marta chiqariladi. Frontend'ga API key tushmaydi.

## ADR-6: Queue (ARQ → inline fallback)

**Holat:** qabul qilindi.

ARQ worker (max_jobs=2). Redis yo'q bo'lda API `asyncio.create_task` orqali inline bajaradi. `GET /healthz` → `queue: ok|inline`.

## Yo'l xaritasi

| Bosqich | Holat |
|---|---|
| 0 — poydevor | ✅ |
| 1 — DB + API | ✅ |
| 2 — 2-modul + PDF | ✅ |
| 3 — dashboard | ⏳ |
| 4 — pilot | ⏳ |
