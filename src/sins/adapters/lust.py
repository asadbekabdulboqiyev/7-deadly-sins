"""Lust: authentication posture.

Goal: inspect how the target authenticates, passively and safely.

Checks performed:
  - Basic authentication served over plain HTTP
  - Login form served over plain HTTP
  - Session cookie flags (Secure / HttpOnly / SameSite)
  - JWT structural hygiene (alg=none, missing exp, long-lived tokens)

Deliberately not performed:
  - Brute force, credential guessing, default-login testing
  - Anything that could authenticate or attack a real account
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
from typing import ClassVar

from ..dedup import dedup_key
from ..runner import run_tool, which
from ..schemas import Category, FindingContract, Severity
from ..targets import InvalidTarget, classify_target
from .base import ScanContext
from .pride import _resolve_tool, _write_hosts

log = logging.getLogger(__name__)

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class LustAdapter:
    name: ClassVar[str] = "lust"
    category: ClassVar[Category] = Category.auth
    sin: ClassVar[str] = "Lust"

    def available(self) -> bool:
        return which("httpx") is not None and which("nuclei") is not None

    def applies_to(self, target: str) -> bool:
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return True
        return kind in {"domain", "url", "ip"}

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        binary = _resolve_tool("httpx")
        if binary is None:
            return []
        hosts = [ctx.target]
        path = _write_hosts(hosts)
        try:
            result = run_tool(
                [binary, "-list", path, "-json", "-silent", "-irr", "-x", "GET"],
                timeout=ctx.timeout,
            )
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)

        findings: list[FindingContract] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("failed"):
                continue
            findings.extend(self._findings_from_response(payload, ctx.target))
        return findings

    def _findings_from_response(self, payload: dict, target: str) -> list[FindingContract]:
        raw_headers = str(payload.get("raw_header") or "")
        headers: list[tuple[str, str]] = []
        for line in raw_headers.split("\r\n")[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers.append((name.strip().lower(), value.strip()))

        values: dict[str, str] = {}
        cookies: list[dict] = []
        for name, value in headers:
            if name == "set-cookie":
                cookies.append(_parse_cookie(value))
            elif name not in values:
                values[name] = value

        scheme = str(payload.get("scheme") or "https")
        url = str(payload.get("url") or target)

        findings: list[FindingContract] = []
        basic = values.get("www-authenticate") or ""
        if "basic" in basic.lower() and scheme == "http":
            findings.append(
                self._finding(
                    title="Basic authentication served over plain HTTP",
                    severity=Severity.high,
                    dedup_source="lust-basic-http",
                    url=url,
                    evidence={
                        "scheme": scheme,
                        "www_authenticate": basic,
                        "host": str(payload.get("host") or target),
                    },
                )
            )

        body = str(payload.get("body") or "")
        content_type = str(payload.get("content_type") or "")
        if scheme == "http" and (
            "password" in body.lower() or "login" in body.lower() or "form" in content_type.lower()
        ):
            findings.append(
                self._finding(
                    title="Login form served over plain HTTP",
                    severity=Severity.medium,
                    dedup_source="lust-login-http",
                    url=url,
                    evidence={"scheme": scheme, "content_type": content_type},
                )
            )

        for cookie in cookies:
            flags = cookie.get("flags") or {}
            if scheme == "https" and not flags.get("secure"):
                findings.append(
                    self._finding(
                        title=f"Session cookie '{cookie.get('name')}' lacks the Secure flag",
                        severity=Severity.medium,
                        dedup_source=f"lust-cookie-{cookie.get('name')}",
                        url=url,
                        evidence={"scheme": scheme, "cookie": cookie},
                    )
                )
            if (flags.get("samesite") or "").lower() == "none" and not flags.get("secure"):
                findings.append(
                    self._finding(
                        title=(
                            f"Session cookie '{cookie.get('name')}' uses "
                            "SameSite=None without Secure"
                        ),
                        severity=Severity.medium,
                        dedup_source=f"lust-samesite-{cookie.get('name')}",
                        url=url,
                        evidence={"scheme": scheme, "cookie": cookie},
                    )
                )

        for token in _JWT_RE.findall(body):
            decoded = _decode_jwt(token)
            if decoded is None:
                continue
            header = decoded.get("header") or {}
            claims = decoded.get("claims") or {}
            if str(header.get("alg") or "").lower() == "none":
                findings.append(
                    self._finding(
                        title="JWT uses unsigned algorithm (alg=none)",
                        severity=Severity.critical,
                        dedup_source="lust-jwt-alg-none",
                        url=url,
                        evidence={"header": header, "claims": claims},
                    )
                )
            if not claims.get("exp"):
                findings.append(
                    self._finding(
                        title="JWT is missing the exp claim",
                        severity=Severity.high,
                        dedup_source="lust-jwt-no-exp",
                        url=url,
                        evidence={"header": header, "claims": claims},
                    )
                )
            exp = claims.get("exp")
            if isinstance(exp, (int, float)) and exp > 90 * 24 * 3600:
                findings.append(
                    self._finding(
                        title="JWT is long-lived (exp more than 90 days)",
                        severity=Severity.low,
                        dedup_source="lust-jwt-long-lived",
                        url=url,
                        evidence={"header": header, "claims": claims},
                    )
                )

        return findings

    def _finding(
        self, *, title: str, severity: Severity, dedup_source: str, url: str, evidence: dict
    ) -> FindingContract:
        return FindingContract(
            category=Category.auth,
            title=title,
            severity=severity,
            cvss=None,
            cve=[],
            cwe=[
                "CWE-319"
                if any(k in dedup_source for k in ("cookie", "basic", "login"))
                else "CWE-347",
            ],
            location=url,
            evidence=evidence,
            source_tools=["httpx", self.name],
            dedup_key=dedup_key(self.name, url, dedup_source),
            remediation=None,
        )


def _parse_cookie(raw: str) -> dict:
    parts = raw.split(";")
    name_value = parts[0].strip()
    name, _, value = name_value.partition("=")
    flags: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            flags[key.strip().lower()] = val.strip().lower()
        else:
            flags[part.strip().lower()] = "true"
    return {
        "name": name.strip(),
        "value": value.strip(),
        "flags": {
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": flags.get("samesite", ""),
        },
    }


def _decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None

    def b64url_decode(seg: str) -> bytes:
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad)

    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return {"header": header, "claims": claims}
