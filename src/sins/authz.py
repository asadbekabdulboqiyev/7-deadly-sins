"""Authorization gate.

THIS is the product's license. Target ownership is proven BEFORE a scan.
Without it the platform is hacking-as-a-service.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl

import dns.asyncresolver
import httpx

VERIFY_LABEL = "_sins-verify"


class OwnershipError(RuntimeError):
    """Target ownership was not proven — the scan is blocked."""


def issue_token() -> str:
    return secrets.token_urlsafe(32)


async def verify_dns_txt(domain: str, token: str, *, timeout: float = 5.0) -> bool:
    """The `_sins-verify.<domain>` TXT record must equal the token."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = await resolver.resolve(f"{VERIFY_LABEL}.{domain}", "TXT")
    except Exception:
        return False

    for rdata in answers:
        raw = getattr(rdata, "strings", None)
        value = b"".join(raw).decode("utf-8", "replace") if raw else rdata.to_text()
        if value.strip('"').strip() == token:
            return True
    return False


async def verify_http_file(host: str, token: str, *, timeout: float = 10.0) -> bool:
    """The `/.well-known/sins-verify-<token>` file must return 200."""
    path = f"/.well-known/sins-verify-{token}"
    # We check even on certificate errors — this is only proof of ownership, not confidential data.
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{host}{path}")
            except (httpx.HTTPError, ssl.SSLError, OSError):
                continue
            if resp.status_code == 200 and token in resp.text:
                return True
    return False


async def verify_ownership(target: str, token: str) -> tuple[bool, str]:
    """Tries both methods in parallel. Returns whichever succeeded."""
    host = target
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    host = host.split("/")[0].split(":")[0]

    is_ip = host.replace(".", "").isdigit()
    checks = [("http", verify_http_file(host, token))]
    if not is_ip:
        checks.append(("dns", verify_dns_txt(host, token)))

    results = await asyncio.gather(*(coro for _, coro in checks), return_exceptions=True)
    for (method, _), result in zip(checks, results, strict=True):
        if result is True:
            return True, method
    return False, "none"


async def assert_authorized(target: str, token: str) -> str:
    """Called before starting a scan. Raises if it fails."""
    ok, method = await verify_ownership(target, token)
    if not ok:
        raise OwnershipError(
            f"Ownership of '{target}' was not proven. "
            f"TXT record: {VERIFY_LABEL}.<domain> = <token> "
            f"or file: /.well-known/sins-verify-<token>"
        )
    return method
