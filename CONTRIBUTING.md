# Hissa qo'shish

## Muhit

```bash
uv sync --python 3.13
docker compose up -d
uv run alembic upgrade head
```

macOS: PDF uchun `brew install pango gtk+3`. `nuclei` va `osv-scanner`
bo'lmasa ham testlar ishlaydi (adapterlar mock qilinadi).

## Kundalik buyruqlar

```bash
make test        # pytest
make lint        # ruff check
make fmt         # ruff format + fix
make cov         # qamrov
make migration m="izoh"   # autogenerate
```

Commit oldidan **uchalasi** yashil bo'lishi shart:

```bash
uv run ruff check src/ tests/ scripts/
uv run ruff format --check src/ tests/ scripts/
uv run pytest -q
uv run alembic check
```

## Qoidalar

1. **Biznes-qoida faqat `services/scan_service.py`da.** Route, CLI va worker
   faqat shu funksiyalarni chaqiradi.
2. **Har yangi endpoint uchun test** — kamida bitta baxtli yo'l va bitta xato.
3. **Tenant izolyatsiyasi** — har so'rovda `tenant_id` filtri. Testda begona
   tenant bilan urinib ko'ring (`test_tenant_cannot_see_foreign_scan`).
4. **Yangi adapter** — `adapters/base.py` protokolini bajaring:
   `name`, `sin`, `category`, `available()`, `applies_to()`, `run()`.
   `REGISTRY`ga qo'shing va `applies_to` uchun test yozing.
5. **Xavfsizlik** — `shell=True` yo'q, foydalanuvchi kiritmasi argv'ga
   birlashtirilmaydi, kalit logga yozilmaydi.
6. **Migratsiya** — model o'zgarsa `make migration` va `alembic check` toza
   bo'lishi shart. Migratsiya izohi o'zbekcha, aniq.
7. **Matn tili** — kod izohlari va hujjatlar o'zbekcha, API/UI matnlari inglizcha
   (mahsulot shartnomasi).

## Testlar tuzilishi

| Fayl | Nima |
|---|---|
| `test_api.py` | HTTP oqimi, auth, egalik, PDF |
| `test_scan_service.py` | Hayotiy sikl, tenant izolyatsiyasi |
| `test_service_extras.py` | Idempotentlik, cancel, diff, rotate, prune, sahifalash |
| `test_observability.py` | Log formatlari, metrikalar |
| `test_ratelimit.py` | Token-bucket chegaralari |
| `test_middleware.py` | Request ID, rate limit, `/metrics` |
| `test_orchestrator.py` | Adapterlar, `applies_to`, retry |
| `test_security.py` | Kalit hash, token |
| `test_targets.py` | Nishon klassifikatsiyasi, lab cheklovi |
| `test_report.py` | PDF tarkibi |

Testlar **faqat** `_test` bilan tugaydigan bazada ishlaydi. Boshqa nom —
`RuntimeError` (prod bazani himoya qiladi).

## PR

- Kichik, mantiqiy commit'lar (`feat:`, `fix:`, `docs:`, `test:`).
- Tavsifda: nima o'zgardi, nega, qanday tekshirildi.
- Xatti-harakat o'zgarishi bo'lsa — `docs/` yangilanadi.
- `PROGRESS.md` — bajarilgan/qolgan ishlar qisqa yangilanadi.
