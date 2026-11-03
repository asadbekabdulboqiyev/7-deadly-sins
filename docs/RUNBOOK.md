# Runbook (ekspluatatsiya)

## Kunlik tekshiruv (2 daqiqa)

```bash
curl -s localhost:8000/healthz          # {"status":"ok"}
curl -s localhost:8000/readyz           # ready:true, db:ok, queue:ok
curl -s localhost:8000/metrics | grep -E "sins_scans|sins_engine_runs_total"
```

`readyz` 503 bersa — pastga qarang.

## Ishga tushirish

### Lokal

```bash
uv sync --python 3.13
docker compose up -d                    # Postgres + Redis
uv run alembic upgrade head
uv run sins serve --port 8000 --reload  # 1-terminal
uv run sins worker                      # 2-terminal
```

Redis yo'q bo'lsa API `queue: inline` bilan ishlaydi (skan API jarayonida).
Bu faqat dev uchun — prod'da worker majburiy.

### Docker

```bash
make docker-build
docker compose --profile app up -d
docker compose logs -f api worker
```

### Prod checklist

- [ ] `SINS_DATABASE_URL`, `SINS_REDIS_URL` — boshqariladigan xizmatlar
- [ ] `SINS_LOG_JSON=1`, loglar agregatorga (Loki/CloudWatch)
- [ ] `SINS_RATE_LIMIT_PER_MINUTE` — mijoz shartnomasiga mos
- [ ] `SINS_RETENTION_DAYS` — DPА/shartnoma bilan kelishilgan
- [ ] `/metrics` Prometheus scrape (internetga ochiq emas)
- [ ] Alembic `upgrade head` deploy qadamida
- [ ] `nuclei`, `osv-scanner` versiyalari pin qilingan, `PATH`da

## Muammolar

### `readyz` → `db: down`

```bash
docker compose ps postgres
pg_isready -h localhost -p 5432
uv run alembic current
```

### `queue: inline` (prod'da bo'lmasligi kerak)

```bash
redis-cli -u "$SINS_REDIS_URL" ping
docker compose logs redis
uv run sins worker        # alohida jarayon
```

### Skan `running` holatida qotib qoldi

1. Worker logida `run_scan` bor-yo'qligini tekshiring.
2. `job_timeout=1800` (30 daq) — shundan keyin ARQ job'ni to'xtatadi.
3. Qo'lda: `POST /scans/{id}/cancel`, keyin qayta skan.
4. Tool osilib qolsa: `ps aux | grep -E "nuclei|osv"` — `killpg` ishlamagan
   bo'lishi mumkin; jarayonni o'ldiring va `runner.py` timeout'ini tekshiring.

### Skan `failed`

`GET /scans/{id}` → `error` maydoni. Eng ko'p uchraydiganlari:

| Xato | Sabab | Yechim |
|---|---|---|
| `ToolNotFound: nuclei` | binary yo'q | `PATH`ga qo'shing yoki mount qiling |
| `TimeoutExpired` | sekin tarmoq / katta nishon | `--rate-limit` oshiring, timeout oshiring |
| `PermissionError` | template yo'li | `--templates` huquqini tekshiring |

Retry faqat vaqtinchalik xatolarda ishlaydi (`ARCHITECTURE.md` → Retry siyosati).

### Topilmalar juda ko'p / hisobot sekin

- `info` darajasi sukut bo'yicha o'chiq — `severities` bilan boshqaring.
- PDF WeasyPrint'da CPU-bound; bir vaqtda ko'p so'rov bo'lsa navbat qo'ying.
- `MAX_FINDINGS_PER_SCAN=5000` — undan ko'p bo'lsa kesiladi (log'da ko'rinadi).

### Baza o'sib ketdi

```bash
uv run sins prune --days 180 --dry-run   # avval ko'rish
uv run sins prune --days 180             # o'chirish
```

Cron har kuni 03:30 da `SINS_RETENTION_DAYS` bilan avtomatik ishlaydi.

## Incident

### API kalit sizib chiqdi

```bash
uv run sins rotate-key --api-key "$ESKI_KALIT"
# yangi kalitni mijozga xavfsiz kanal orqali yuboring
```

Eski kalit **shu zahoti** ishlamaydi. Keyin loglardan foydalanishni tekshiring:

```bash
# request_id bo'yicha butun zanjir
grep '"request_id": "<rid>"' api.log
```

### Shubhali tenant

```bash
uv run sins prune --days 0            # rad etadi: 1 kundan kichik bo'lmaydi
psql "$DB" -c "UPDATE tenants SET api_key_hash = 'revoked' WHERE id = '…'"
```

`api_key_hash`ni almashtirish kalitni darhol o'chiradi (rotatsiya bilan bir xil).

### Favqulodda to'xtatish

```bash
docker compose stop api worker   # yangi ish qabul qilinmaydi
docker compose logs --tail=200 api worker > incident.log
```

## Metrikalar bo'yicha ogohlantirishlar (tavsiya)

| Shart | Ma'no |
|---|---|
| `rate(sins_http_requests_total{status=~"5.."}[5m]) > 0.1` | server xatolari |
| `rate(sins_rate_limited_total[5m]) > 1` | limit juda past yoki suiiste'mol |
| `sins_scans{status="running"} > 4` | worker yetishmayapti |
| `rate(sins_engine_runs_total{ok="false"}[15m]) > 0` | tool nosozligi |
| `sins_scans{status="pending"} > 10` (10 daqiqa) | navbat to'xtagan |

## Zaxira nusxa

```bash
pg_dump "$SINS_DATABASE_URL" -Fc -f "sins-$(date +%F).dump"
pg_restore -d "$SINS_DATABASE_URL" --clean --if-exists sins-2026-11-03.dump
```

Skan natijalari qayta yaratilishi mumkin; **tenant va kalit hash'lari** —
yo'q. Zaxira kamida kunlik bo'lsin.
