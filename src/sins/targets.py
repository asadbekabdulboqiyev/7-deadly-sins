"""Nishon bilan ishlash: turini aniqlash, tozalash, lab-cheklovi.

Bu modul ATAYLAB tool'lardan mustaqil: CLI ham, API ham, worker ham
bir xil qoidalar bilan ishlaydi.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Domen uchun oddiy, lekin yetarli tekshiruv. IDN (punycode) ham o'tadi.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

LAB_SUFFIXES = (".local", ".test", ".localhost", ".internal")


class InvalidTarget(ValueError):
    """Nishon formati noto'g'ri — skan boshlanmaydi."""


def extract_host(value: str) -> str:
    """`https://example.com:8443/path` -> `example.com`."""
    raw = value.strip()
    if "://" in raw:
        host = urlsplit(raw).hostname or ""
    else:
        host = raw.split("/")[0]
        if host.startswith("["):  # [::1]:8080
            host = host.split("]")[0].lstrip("[")
        elif host.count(":") == 1:  # host:port
            host = host.split(":")[0]
    return host.lower().rstrip(".")


def classify_target(value: str) -> str:
    """`domain` | `url` | `ip` | `path`.

    `path` — lokal papka (osv-scanner uchun). API orqali faqat lab rejimida.
    """
    raw = value.strip()
    host = extract_host(raw)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "ip"

    if raw.startswith(("http://", "https://")):
        return "url"
    if _DOMAIN_RE.match(host):
        return "domain"
    # Lab nishonlari: `localhost`, `app.local` kabi bir qismli nomlar
    if is_lab_target(raw):
        return "url" if raw.startswith(("http://", "https://")) else "domain"
    if raw.startswith(("/", "./", "~")) or raw in {".", ".."}:
        return "path"
    raise InvalidTarget(
        f"'{value}' nishon sifatida tanilmadi. Domen (example.com), URL yoki IP kiriting."
    )


def normalize_target(value: str) -> str:
    """Nishonni yagona ko'rinishga keltiradi (takroriy yozuvlarni oldini oladi)."""
    raw = value.strip()
    if not raw:
        raise InvalidTarget("Nishon bo'sh bo'lishi mumkin emas.")
    if len(raw) > 255:
        raise InvalidTarget("Nishon juda uzun (255 belgidan oshdi).")
    if any(ch.isspace() for ch in raw):
        raise InvalidTarget("Nishonda bo'sh joy bo'lishi mumkin emas.")
    # Argument injection: `nuclei -u -foo` kabi holatlarni to'sadi.
    if raw.startswith("-"):
        raise InvalidTarget("Nishon '-' bilan boshlanishi mumkin emas.")

    kind = classify_target(raw)
    if kind == "url":
        return raw.rstrip("/")
    if kind in {"domain", "ip"}:
        return extract_host(raw)
    return raw


def is_lab_target(value: str) -> bool:
    """Faqat lokal/lab nishonlar uchun egalik tekshiruvisiz ruxsat."""
    host = extract_host(value)
    if host in {"localhost", "::1", "0.0.0.0"} or host.endswith(LAB_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local
