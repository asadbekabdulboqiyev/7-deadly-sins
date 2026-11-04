"""Gluttony adapter tests - for the resilience posture checks."""

from __future__ import annotations

import json
from typing import Any

from sins.adapters.base import ScanContext
from sins.adapters.gluttony import GluttonyAdapter
from sins.runner import RunResult


def _response(*, server: str = "", powered: str = "", allow: str = "") -> dict[str, Any]:
    header: dict[str, str] = {}
    if server:
        header["server"] = server
    if powered:
        header["x-powered-by"] = powered
    if allow:
        header["allow"] = allow
    return {
        "failed": False,
        "scheme": "https",
        "url": "https://example.com/",
        "host": "example.com",
        "header": header,
    }


def _install(monkeypatch, responses: dict[str, dict[str, Any]]) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        calls.append(list(argv))
        method = argv[argv.index("-x") + 1] if "-x" in argv else "GET"
        payload = responses.get(method) or responses["GET"]
        stdout = json.dumps(payload) + "\n"
        return RunResult(argv=argv, returncode=0, stdout=stdout, duration_ms=1)

    monkeypatch.setattr("sins.adapters.gluttony._resolve_tool", lambda tool: tool)
    monkeypatch.setattr("sins.adapters.gluttony.run_tool", fake_run)
    return calls


def test_server_and_powered_by_headers_are_reported(monkeypatch) -> None:
    calls = _install(
        monkeypatch,
        {
            "GET": _response(server="nginx/1.25.3", powered="Express"),
            "OPTIONS": _response(allow="GET, HEAD, OPTIONS"),
        },
    )

    findings = GluttonyAdapter().run(ScanContext(target="example.com"))

    assert [c[0] for c in calls] == ["httpx", "httpx"]
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert "Server header discloses product information" in titles
    assert "X-Powered-By header discloses implementation" in titles
    assert all(f.severity.value == "low" for f in findings)


def test_dangerous_allowed_method_is_reported(monkeypatch) -> None:
    _install(
        monkeypatch,
        {
            "GET": _response(),
            "OPTIONS": _response(allow="GET, HEAD, OPTIONS, TRACE"),
        },
    )

    findings = GluttonyAdapter().run(ScanContext(target="example.com"))
    assert len(findings) == 1
    assert findings[0].title == "Dangerous HTTP methods are allowed"
    assert findings[0].severity.value == "high"


def test_allow_header_without_dangerous_methods_is_clean(monkeypatch) -> None:
    _install(
        monkeypatch,
        {
            "GET": _response(),
            "OPTIONS": _response(allow="GET, HEAD, OPTIONS"),
        },
    )

    assert GluttonyAdapter().run(ScanContext(target="example.com")) == []
