"""Authorization gate.

BU — mahsulotning litsenziyasi. Skandan OLDIN nishon egaligi isbotlanadi.
Usiz platforma hacking-as-a-service bo'lib qoladi.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl

import dns.asyncresolver
import httpx

VERIFY_LABEL = "_sins-verify"


class OwnershipError(RuntimeError):
    """Nishon egaligi isbotlanmadi — skan bloklanadi."""


def issue_token() -> str:
    return secrets.token_urlsafe(32)


async def verify_dns_txt(domain: str, token: str, *, timeout: float = 5.0) -> bool:
    """`_sins-verify.<domain>` TXT yozuvi tokenga teng bo'lishi kerak."""
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
    """`/.well-known/sins-verify-<token>` fayli 200 qaytarishi kerak."""
    path = f"/.well-known/sins-verify-{token}"
    # Sertifikat xatosi bo'lsa ham tekshiramiz — bu faqat egalik isboti, maxfiy ma'lumot emas.
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
    """Ikki usulni parallel sinab ko'radi. Qaysi biri ishlaganini qaytaradi."""
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
    """Skanni boshlashdan oldin chaqiriladi. O'tmasa — exception."""
    ok, method = await verify_ownership(target, token)
    if not ok:
        raise OwnershipError(
            f"'{target}' egaligi isbotlanmadi. "
            f"TXT yozuvi: {VERIFY_LABEL}.<domain> = <token> "
            f"yoki fayl: /.well-known/sins-verify-<token>"
        )
    return method
