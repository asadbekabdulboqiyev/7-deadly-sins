"""Lust adapter tests - for the authentication posture checks.

The checks are pure HTTP-shape checks over crafted payloads, so they are
tested without a live service.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from sins.adapters.base import ScanContext
from sins.adapters.lust import LustAdapter
from sins.runner import RunResult

_TARGET = "example.com"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _b64url(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _jwt(header: dict[str, Any], claims: dict[str, Any]) -> str:
    return f"{_b64url(header)}.{_b64url(claims)}.sig"


def _payload(
    *,
    scheme: str = "https",
    body: str = "",
    content_type: str = "text/html",
    raw_header: str = "",
) -> dict[str, Any]:
    return {
        "failed": False,
        "scheme": scheme,
        "url": "https://example.com/",
        "host": "example.com",
        "body": body,
        "content_type": content_type,
        "raw_header": raw_header,
    }


def _raw_header(
    *, authenticate: str = "", cookie: str = "", content_type: str = "text/html"
) -> str:
    lines = ["HTTP/1.0 200 OK", f"Content-Type: {content_type}"]
    if authenticate:
        lines.append(f"WWW-Authenticate: {authenticate}")
    if cookie:
        lines.append(f"Set-Cookie: {cookie}")
    lines.append("")
    return "\r\n".join(lines) + "\r\n"


def _install(monkeypatch, payloads: list[dict[str, Any]]) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        calls.append(list(argv))
        stdout = "".join(json.dumps(p) + "\n" for p in payloads)
        return RunResult(argv=argv, returncode=0, stdout=stdout, duration_ms=1)

    monkeypatch.setattr("sins.adapters.lust._resolve_tool", lambda tool: tool)
    monkeypatch.setattr("sins.adapters.lust.run_tool", fake_run)
    return calls


def _titles(findings: list[Any]) -> set[str]:
    return {f.title for f in findings}


# -- basic auth over plain HTTP --------------------------------------------


def test_basic_auth_over_plain_http_is_reported(monkeypatch) -> None:
    _install(
        monkeypatch,
        [_payload(scheme="http", raw_header=_raw_header(authenticate='Basic realm="Corp"'))],
    )

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    assert "Basic authentication served over plain HTTP" in _titles(findings)
    assert findings[0].severity.value == "high"
    assert findings[0].cwe == ["CWE-319"]


def test_no_basic_auth_over_plain_http_no_finding(monkeypatch) -> None:
    _install(monkeypatch, [_payload(scheme="http", raw_header=_raw_header())])

    assert LustAdapter().run(ScanContext(target=_TARGET)) == []


# -- login form over plain HTTP --------------------------------------------


def test_login_form_over_plain_http_is_reported(monkeypatch) -> None:
    _install(
        monkeypatch, [_payload(scheme="http", body="<form>login</form>", content_type="text/html")]
    )

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    assert "Login form served over plain HTTP" in _titles(findings)
    assert findings[0].severity.value == "medium"


def test_login_form_over_https_is_not_flagged(monkeypatch) -> None:
    _install(
        monkeypatch,
        [_payload(scheme="https", body="<form>login</form>", content_type="text/html")],
    )

    assert LustAdapter().run(ScanContext(target=_TARGET)) == []


# -- session cookie flags -------------------------------------------------


def test_cookie_without_secure_flag_is_reported(monkeypatch) -> None:
    _install(
        monkeypatch,
        [
            _payload(
                scheme="https",
                raw_header=_raw_header(cookie="session=abc; Path=/; HttpOnly; SameSite=Lax"),
            )
        ],
    )

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    assert "Session cookie 'session' lacks the Secure flag" in _titles(findings)


def test_samesite_none_without_secure_is_reported(monkeypatch) -> None:
    _install(
        monkeypatch,
        [
            _payload(
                scheme="https",
                raw_header=_raw_header(cookie="session=abc; Path=/; HttpOnly; SameSite=None"),
            )
        ],
    )

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    assert "Session cookie 'session' uses SameSite=None without Secure" in _titles(findings)


def test_secure_cookie_is_not_flagged(monkeypatch) -> None:
    _install(
        monkeypatch,
        [
            _payload(
                scheme="https",
                raw_header=_raw_header(
                    cookie="session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
                ),
            )
        ],
    )

    assert LustAdapter().run(ScanContext(target=_TARGET)) == []


# -- JWT hygiene ------------------------------------------------------------


def test_unsigned_jwt_is_critical(monkeypatch) -> None:
    token = _jwt({"alg": "none"}, {"sub": "user"})
    _install(monkeypatch, [_payload(scheme="https", body=f'<script src="{token}"></script>')])

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    unsigned = [f for f in findings if "unsigned algorithm" in f.title]
    assert len(unsigned) == 1
    assert unsigned[0].severity.value == "critical"
    assert unsigned[0].cwe == ["CWE-347"]


def test_jwt_missing_exp_is_high(monkeypatch) -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "user"})
    _install(monkeypatch, [_payload(scheme="https", body=f"<script src='{token}'></script>")])

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    missing = [f for f in findings if "missing the exp claim" in f.title]
    assert len(missing) == 1
    assert missing[0].severity.value == "high"


def test_jwt_long_lived_is_low(monkeypatch) -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "user", "exp": 120 * 24 * 3600})
    _install(monkeypatch, [_payload(scheme="https", body=f"<script src='{token}'></script>")])

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    long_lived = [f for f in findings if "long-lived" in f.title]
    assert len(long_lived) == 1
    assert long_lived[0].severity.value == "low"


def test_expired_jwt_is_not_flagged(monkeypatch) -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "user", "exp": 10 * 24 * 3600})
    _install(monkeypatch, [_payload(scheme="https", body=f"<script src='{token}'></script>")])

    findings = LustAdapter().run(ScanContext(target=_TARGET))
    assert [f for f in findings if "long-lived" in f.title] == []


def test_no_jwt_means_no_jwt_findings(monkeypatch) -> None:
    _install(monkeypatch, [_payload(scheme="https", body="<html>plain</html>")])

    assert LustAdapter().run(ScanContext(target=_TARGET)) == []
