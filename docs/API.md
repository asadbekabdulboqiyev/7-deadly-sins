# HTTP API

Base URL: `http://127.0.0.1:8000` · Interaktiv hujjat: `/docs` (OpenAPI: `/openapi.json`)

## Autentifikatsiya

Har bir biznes so'rovida:

```
X-API-Key: sins_...
```

Kalit bazada faqat SHA-256 hash sifatida saqlanadi. Xato javobi bitta xil
(401) — kalit mavjudligi oshkor qilinmaydi.

## Umumiy sarlavhalar

| Sarlavha | Yo'nalish | Ma'no |
|---|---|---|
| `X-API-Key` | so'rov | Tenant identifikatsiyasi |
| `X-Request-ID` | ikkalasi | Mijoz yuborsa — saqlanadi, aks holda generatsiya qilinadi |
| `Idempotency-Key` | so'rov | `POST /scans` takrorlanishini bloklaydi |
| `Retry-After` | javob | 429 da qancha kutish (sekund) |

## Xatolar

|xolat|holat|ma'no|
|---|---|---|
|400|`ServiceError`, `OwnershipError`|noto'g'ri so'rov / biznes qoidasi|
|401|—|kalit yo'q yoki noto'g'ri|
|404|`NotFound`|resurs topilmadi (yoki boshqa tenantga tegishli)|
|409|`TargetNotVerified`, `ScanBusy`, `NotCancellable`, `InvalidScanState`|holat to'qnashuvi|
|422|`InvalidTarget`|nishon formati noto'g'ri|
|429|—|rate limit|

Barcha xato javoblari: `{"detail": "..."}`.

## Nishonlar

### `POST /targets` → 201

```json
{"value": "example.com"}
```

Javob:

```json
{
  "id": "…", "value": "example.com", "kind": "domain",
  "verified_at": null, "verify_method": null,
  "verify_token": "sinsv_…", "verify_expires_at": "…",
  "instructions": {
    "dns_record": "_sins-verify.example.com",
    "dns_value": "sinsv_…",
    "http_url": "https://example.com/.well-known/sins-verify-sinsv_…"
  }
}
```

Lab nishonlari (`localhost`, private IP) avtomatik tasdiqlanadi
(`verify_method="lab"`, `instructions=null`).

### `GET /targets?limit=200&offset=0` → 200

### `POST /targets/{id}/verify` → 200

DNS TXT yoki `.well-known` faylini tekshiradi. Token muddati o'tsa — 409 va
javobda yangi `verify_token` qaytadi.

## Skanlar

### `POST /scans` → 202

```http
POST /scans
Idempotency-Key: 9f2c1a7e-...
Content-Type: application/json

{"target_id": "…", "engines": ["nuclei"], "severities": ["critical","high"]}
```

- `engines` bo'sh bo'lsa — barcha ruxsat etilganlar (`SINS_ALLOWED_ENGINES`).
- `severities` bo'sh bo'lsa — `critical, high, medium, low` (`info` yo'q).
- Egalik tasdiqlanmagan → 409.
- Shu nishonda faol skan bor → 409.
- `Idempotency-Key` takrorlansa → o'sha skan qaytadi (yangi job yo'q).

### `GET /scans?limit=50&offset=0&status=done&target_id=…` → 200

`limit` 1–500. `status` takrorlanishi mumkin (`?status=done&status=failed`) yoki
vergul bilan (`?status=done,failed`).

### `GET /scans/{id}` → 200

```json
{
  "id": "…", "target_id": "…", "status": "running", "progress": 45,
  "engines": ["nuclei"], "severities": ["critical","high"],
  "current_engine": "nuclei", "error": null,
  "started_at": "…", "finished_at": null, "created_at": "…",
  "finding_count": 12
}
```

### `GET /scans/{id}/findings` → 200

Query: `severity` (takrorlanadi), `engine`, `limit` (1–500, sukut 100), `offset`.

```json
{
  "scan_id": "…", "total": 42, "limit": 100, "offset": 0, "has_more": false,
  "severity_counts": {"critical": 2, "high": 5, "medium": 10, "low": 25, "info": 0},
  "items": [
    {
      "id": "…", "category": "vuln", "severity": "critical",
      "title": "Apache Log4j2 RCE", "cvss": 10.0,
      "cve": ["CVE-2021-44228"], "cwe": ["CWE-502"],
      "location": "example.com:443/api", "source_tools": ["nuclei"],
      "remediation": {"summary": "…", "steps": ["…"], "fixed_version": "2.17.1"},
      "evidence": {"template_id": "…"}, "dedup_key": "…"
    }
  ]
}
```

### `POST /scans/{id}/cancel` → 200

`pending` yoki `running` skanni bekor qiladi → `status: "cancelled"`.
Tugagan skan uchun → 409 (`NotCancellable`).

### `GET /scans/{id}/diff?against={scan_id}` → 200

`against` berilmasa — shu nishondagi oldingi tugagan skan olinadi.

```json
{
  "scan_id": "…", "against_scan_id": "…", "baseline": true,
  "new": [{"dedup_key": "…", "severity": "high", "title": "…", "location": "…"}],
  "resolved": [{"…": "…"}],
  "persisting": 17
}
```

`baseline: false` — oldingi skan yo'q, hammasi `new`.

### `GET /scans/{id}/report.pdf` → 200 `application/pdf`

Faqat `done` skan uchun; aks holda 409.

## Tenant

### `GET /tenant/me` → 200

```json
{"id": "…", "name": "Demo Bank", "api_key_prefix": "sins_-YUo", "created_at": "…"}
```

### `POST /tenant/rotate-key` → 200

```json
{
  "api_key": "sins_…",
  "api_key_prefix": "sins_AbCd",
  "warning": "Eski kalit shu zahoti ishlamaydi. Yangi kalitni xavfsiz saqlang."
}
```

Yangi kalit faqat bir marta ko'rinadi. Eski kalit darhol 401 beradi.

## Tizim

| Endpoint | Ma'no |
|---|---|
| `GET /healthz` | `{"status":"ok"}` — liveness, DB tekshirilmaydi |
| `GET /readyz` | `{"ready":true,"db":"ok","queue":"ok"}` — tayyorlik (503 bo'lishi mumkin) |
| `GET /metrics` | Prometheus text format |

`queue` qiymati: `ok` (ARQ ulangan) yoki `inline` (Redis yo'q, dev rejimi).

## Rate limit

Sukut: **600 so'rov/daqiqa** kalit (yoki IP) bo'yicha, token-bucket.
Chegaradan oshsa:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 2
```

```json
{"detail": "So'rovlar soni chegaradan oshdi. Keyinroq qayta urinib ko'ring.",
 "retry_after_seconds": 1.2}
```

`/metrics`, `/healthz`, `/readyz`, `/docs`, `/redoc`, `/openapi.json` — cheklanmaydi.
Sozlash: `SINS_RATE_LIMIT_ENABLED`, `SINS_RATE_LIMIT_PER_MINUTE`.
