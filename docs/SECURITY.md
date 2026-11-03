# Xavfsizlik

## Model (tahdidlar)

| Tahdid | Nazorat |
|---|---|
| Ruxsatsiz skanerlash | Egalik darvozasi (DNS TXT / `.well-known`), `--lab` faqat private IP |
| Mijozlararo ma'lumot sizishi | Har bir so'rov `tenant_id` bilan chegaralangan; begona ID → 404 |
| API kalit o'g'irlanishi | Bazada faqat SHA-256 hash; rotatsiya endpointi; prefiks log uchun |
| Buyruq in'ektsiyasi | `runner.py` — argv ro'yxati, `shell=False`, oq ro'yxat |
| Resurs ochligi (DoS) | Rate limit, `max_rps`, tool timeout, chiqish hajmi chegarasi |
| Log orqali ma'lumot sizishi | Kalit/parol logga yozilmaydi; `X-Request-ID` sanitizatsiya qilinadi |
| Saqlangan ma'lumot ko'payishi | `sins prune` + ARQ cron (`SINS_RETENTION_DAYS`, sukut 180) |
| Tool noldan katta chiqishi | `MAX_OUTPUT_BYTES`, topilmalar soni `MAX_FINDINGS_PER_SCAN=5000` |

## Egalik darvozasi

Skanerlashdan oldin nishon egaligi isbotlanadi:

1. `sins verify example.com` → token (`sinsv_…`, TTL `SINS_VERIFY_TOKEN_TTL_HOURS`).
2. Tasdiqlash: `_sins-verify.example.com TXT "<token>"` **yoki**
   `https://example.com/.well-known/sins-verify-<token>`.
3. Har `SINS_VERIFY_RECHECK_DAYS` (sukut 30) kunda qayta tekshiriladi;
   o'tmasa skan `blocked` bo'ladi va hech qanday tool ishga tushmaydi.

`--lab` / lab nishon: faqat `localhost`, `127.0.0.0/8`, `10/8`, `172.16/12`,
`192.168/16`, `::1`, `.local`. Tashqi manzil `--lab` bilan **rad etiladi**.

## Sirli ma'lumotlar

- `.env` git'ga tushmaydi (`.gitignore`), `.env.example` — faqat namuna.
- API kalit: 32 bayt `secrets.token_urlsafe` → `sins_` prefiksi.
- Bazada: `sha256(api_key)` + birinchi 12 belgi (log/dashboard uchun).
- Kalit hech qachon log, metrika yoki xato matniga tushmaydi.
- Rate limit kaliti ham hash'ning qismi — ochiq kalit xotirada yo'q.

Commit oldidan:

```bash
git diff --cached | grep -iE "sins_|password|secret|api[_-]?key" || echo "toza"
```

## Subprocess xavfsizligi

`runner.py` qoidalari:

- Faqat **argv ro'yxati** — satr birlashtirish yo'q, `shell=False`.
- `PATH`dagi bajariladigan fayl `shutil.which` bilan tekshiriladi.
- Timeout (`SINS_TOOL_TIMEOUT_SECONDS`, sukut 900) — butun process guruhi
  o'ldiriladi (`killpg`), farzand jarayonlar qolmaydi.
- Chiqish `MAX_OUTPUT_BYTES` bilan cheklanadi (xotira himoyasi).
- Muhit (env) tozalanadi: tool'ga bizning sirlarimiz uzatilmaydi.

## HTTP qatlami

- Rate limit: token-bucket, kalit yoki IP bo'yicha, `429` + `Retry-After`.
- `X-Request-ID`: faqat `[A-Za-z0-9_-]`, 64 belgi — log injection bloklanadi.
- Barcha xato javoblari `{"detail": ...}`; stack trace mijozga chiqmaydi.
- CORS yoqilmagan (server-server API). UI kerak bo'lsa — aniq origin ro'yxati.

## Konteyner

- Non-root foydalanuvchi (`uid 10001`).
- Multi-stage build — kompilyatorlar runtime obrazida yo'q.
- `.dockerignore` `.env`, `.git`, testlarni chiqarib tashlaydi.
- `HEALTHCHECK` → `/healthz`.
- `nuclei`/`osv-scanner` obrazga kirmaydi: ularni mount qiling yoki alohida
  konteynerda ishlating (versiya nazorati osonroq).

## Nima ataylab yo'q

| Imkoniyat | Sabab |
|---|---|
| Brute-force (Hydra) | Huquqiy javobgarlik; mijoz roziligi isbotlanmaydi |
| DDoS / stress-test | Xizmat ko'rsatishni to'xtatish — jinoyat |
| Qo'lda exploit payload | 0-day mas'uliyati; natija yetarli |
| Public signup | Har bir tenant qo'lda yaratiladi (`sins create-tenant`) |

## Incidentda nima qilish

[`RUNBOOK.md`](RUNBOOK.md) → "Incident" bo'limi: kalit rotatsiyasi, tenant
bloklash, loglarni yig'ish.
