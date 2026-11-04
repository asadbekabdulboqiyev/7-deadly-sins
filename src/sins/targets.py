"""Target handling: kind detection, normalization, lab check.

This module is DELIBERATELY independent of tools: CLI, API and worker all
follow the same rules.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Simple but sufficient validation for domains. IDN (punycode) also passes.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

LAB_SUFFIXES = (".local", ".test", ".localhost", ".internal")


class InvalidTarget(ValueError):
    """Invalid target format — the scan is not started."""


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

    `path` — a local directory (for osv-scanner). Via the API only in lab mode.
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
    # Lab targets: single-label names such as `localhost`, `app.local`
    if is_lab_target(raw):
        return "url" if raw.startswith(("http://", "https://")) else "domain"
    if raw.startswith(("/", "./", "~")) or raw in {".", ".."}:
        return "path"
    raise InvalidTarget(
        f"'{value}' is not recognized as a target. Enter a domain (example.com), URL or IP."
    )


def normalize_target(value: str) -> str:
    """Normalizes the target into a single form (prevents duplicate entries)."""
    raw = value.strip()
    if not raw:
        raise InvalidTarget("Target must not be empty.")
    if len(raw) > 255:
        raise InvalidTarget("Target is too long (over 255 characters).")
    if any(ch.isspace() for ch in raw):
        raise InvalidTarget("Target must not contain whitespace.")
    # Argument injection: blocks cases like `nuclei -u -foo`.
    if raw.startswith("-"):
        raise InvalidTarget("Target must not start with '-'.")

    kind = classify_target(raw)
    if kind == "url":
        return raw.rstrip("/")
    if kind in {"domain", "ip"}:
        return extract_host(raw)
    return raw


def is_lab_target(value: str) -> bool:
    """Allows local/lab targets without an ownership check."""
    host = extract_host(value)
    if host in {"localhost", "::1", "0.0.0.0"} or host.endswith(LAB_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local
