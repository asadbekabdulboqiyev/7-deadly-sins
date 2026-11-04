# Security

## Threat model

| Threat | Control |
|---|---|
| Unauthorized scanning | Ownership gate (DNS TXT / `.well-known`); `--lab` accepts private IPs only |
| Cross-tenant data leakage | Every query is bounded by `tenant_id`; a foreign ID returns 404 |
| Stolen API key | Only a SHA-256 hash in the database; rotation endpoint; prefix kept for logs |
| Command injection | `runner.py` - argv list, `shell=False`, allowlist |
| Resource exhaustion (DoS) | Rate limit, `max_rps`, tool timeout, output size cap |
| Leakage through logs | Keys and passwords are never logged; `X-Request-ID` is sanitized |
| Unbounded data growth | `sins prune` + ARQ cron (`SINS_RETENTION_DAYS`, default 180) |
| Tool producing too much output | `MAX_OUTPUT_BYTES`, finding count capped by `MAX_FINDINGS_PER_SCAN=5000` |

## Ownership gate

Target ownership is proven before any scan:

1. `sins verify example.com` → token (`sinsv_…`, TTL `SINS_VERIFY_TOKEN_TTL_HOURS`).
2. Verification: `_sins-verify.example.com TXT "<token>"` **or**
   `https://example.com/.well-known/sins-verify-<token>`.
3. Re-checked every `SINS_VERIFY_RECHECK_DAYS` (default 30); if it fails the
   scan becomes `blocked` and no tool is started.

`--lab` / lab targets: `localhost`, `127.0.0.0/8`, `10/8`, `172.16/12`,
`192.168/16`, `::1`, `.local` only. An external address with `--lab` is
**rejected**.

## Secrets

- `.env` is never committed (`.gitignore`); `.env.example` is a template only.
- API key: 32 bytes from `secrets.token_urlsafe`, `sins_` prefix.
- Stored as `sha256(api_key)` plus the first 12 characters (for logs and the dashboard).
- A key never reaches a log line, a metric or an error message.
- The rate limit bucket is keyed on the hash as well - the raw key is never held
  in memory for that purpose.

Before committing:

```bash
git diff --cached | grep -iE "sins_|password|secret|api[_-]?key" || echo "clean"
```

## Subprocess safety

Rules enforced by `runner.py`:

- **argv list only** - no string concatenation, `shell=False`.
- The binary on `PATH` is resolved with `shutil.which`.
- Timeout (`SINS_TOOL_TIMEOUT_SECONDS`, default 900) kills the entire process
  group (`killpg`), so no child process survives.
- Output is capped by `MAX_OUTPUT_BYTES` (memory protection).
- The environment is scrubbed: our secrets are not passed to the tool.

## HTTP layer

- Rate limit: token-bucket per key or IP, `429` + `Retry-After`.
- `X-Request-ID`: `[A-Za-z0-9_-]` only, 64 characters - blocks log injection.
- Every error response is `{"detail": ...}`; stack traces never reach the client.
- CORS is off (server-to-server API). If a UI needs it, use an explicit origin
  allowlist.

## Container

- Non-root user (`uid 10001`).
- Multi-stage build - compilers are not in the runtime image.
- `.dockerignore` excludes `.env`, `.git` and the tests.
- `HEALTHCHECK` → `/healthz`.
- `nuclei` and `osv-scanner` are not baked into the image: mount them or run
  them in a separate container (version control is simpler that way).

## Deliberately absent

| Capability | Reason |
|---|---|
| Brute force (Hydra) | Legal liability; customer consent cannot be proven |
| DDoS / stress testing | Taking a service down is a criminal offense |
| Hand-written exploit payloads | 0-day responsibility; the result is produced without them |
| Public signup | Every tenant is created by hand (`sins create-tenant`) |

## What to do during an incident

[`RUNBOOK.md`](RUNBOOK.md) → the "Incident" section: key rotation, tenant
blocking, log collection.
