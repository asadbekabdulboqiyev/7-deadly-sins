# HTTP API

Base URL: `http://127.0.0.1:8000` | Interactive docs: `/docs` (OpenAPI: `/openapi.json`)

## Authentication

Every business request carries:

```
X-API-Key: sins_...
```

The key is stored in the database as a SHA-256 hash only. A rejected request
always looks the same (401) - whether the key exists is never disclosed.

## Common headers

| Header | Direction | Meaning |
|---|---|---|
| `X-API-Key` | request | Tenant identity |
| `X-Request-ID` | both | Reused when the client sends one, generated otherwise |
| `Idempotency-Key` | request | Blocks duplicate `POST /scans` |
| `Retry-After` | response | Seconds to wait on 429 |

## Errors

|Status|Error|Meaning|
|---|---|---|
|400|`ServiceError`, `OwnershipError`|bad request / business rule|
|401|-|missing or wrong key|
|404|`NotFound`|resource does not exist (or belongs to another tenant)|
|409|`TargetNotVerified`, `ScanBusy`, `NotCancellable`, `InvalidScanState`|state conflict|
|422|`InvalidTarget`|malformed target|
|429|-|rate limited|

Every error response is `{"detail": "..."}`.

## Targets

### `POST /targets` → 201

```json
{"value": "example.com"}
```

Response:

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

Lab targets (`localhost`, private IPs) are verified automatically
(`verify_method="lab"`, `instructions=null`).

### `GET /targets?limit=200&offset=0` → 200

### `POST /targets/{id}/verify` → 200

Checks the DNS TXT record or the `.well-known` file. If the token has expired
it returns 409 and a fresh `verify_token` in the body.

## Scans

### `POST /scans` → 202

```http
POST /scans
Idempotency-Key: 9f2c1a7e-...
Content-Type: application/json

{"target_id": "…", "engines": ["nuclei"], "severities": ["critical","high"]}
```

- An empty `engines` means every allowed engine (`SINS_ALLOWED_ENGINES`).
  Default: `nuclei,osv,pride,envy`.
- An empty `severities` means `critical, high, medium, low` (no `info`).
- Ownership not verified → 409.
- An active scan on the same target → 409.
- A repeated `Idempotency-Key` → the same scan is returned (no new job).

### `GET /scans?limit=50&offset=0&status=done&target_id=…` → 200

Each item is a `ScanOut` plus `finding_count` (from a single grouped query).

`limit` is 1–500. `status` may repeat (`?status=done&status=failed`) or be
comma-separated (`?status=done,failed`).

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

Query: `severity` (repeatable), `engine`, `limit` (1–500, default 100), `offset`.

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

Cancels a `pending` or `running` scan → `status: "cancelled"`.
For a finished scan → 409 (`NotCancellable`).

### `GET /scans/{id}/diff?against={scan_id}` → 200

When `against` is omitted, the previous finished scan on the same target is used.

```json
{
  "scan_id": "…", "against_scan_id": "…", "baseline": true,
  "new": [{"dedup_key": "…", "severity": "high", "title": "…", "location": "…"}],
  "resolved": [{"…": "…"}],
  "persisting": 17
}
```

`baseline: false` means there is no previous scan, so everything is `new`.

### `GET /scans/{id}/report.pdf` → 200 `application/pdf`

Only for a `done` scan; anything else → 409.

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
  "warning": "The old key stops working immediately. Store the new key securely."
}
```

The new key is visible exactly once. The old key returns 401 from that moment.

## System

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | `{"status":"ok"}` - liveness, does not touch the DB |
| `GET /readyz` | `{"ready":true,"db":"ok","queue":"ok"}` - readiness (may return 503) |
| `GET /metrics` | Prometheus text format |

`queue` is `ok` (ARQ connected) or `inline` (no Redis, dev mode).

## Rate limit

Default: **600 requests/minute** per key (or IP), token-bucket. Above the limit:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 2
```

```json
{"detail": "Request rate limit exceeded. Try again later.",
 "retry_after_seconds": 1.2}
```

`/metrics`, `/healthz`, `/readyz`, `/docs`, `/redoc`, `/openapi.json` are not
limited. Configure with `SINS_RATE_LIMIT_ENABLED` and
`SINS_RATE_LIMIT_PER_MINUTE`.
