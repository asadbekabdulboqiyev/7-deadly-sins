"""Pride adapter tests - for the real JSONL output of subfinder/naabu/httpx.

The formats were verified against the local tools (subfinder v2.16, naabu v2.16,
httpx v1.6): naabu writes one JSON line per port, `ports`
does not exist.
"""

from __future__ import annotations

import json
import os

from sins.adapters.base import ScanContext
from sins.adapters.pride import (
    MAX_PORTS,
    PrideAdapter,
    _resolve_tool,
    parse_httpx,
    parse_naabu,
    parse_subfinder,
)
from sins.runner import RunResult
from sins.schemas import Severity

_TARGET = "example.com"


# -- parsers -------------------------------------------------------------


def test_parse_subfinder_jsonl() -> None:
    stdout = (
        '{"host":"a.example.com","input":"example.com","source":"crtsh"}\n'
        '{"host":"B.Example.com","input":"example.com","source":"dnsdumpster"}\n'
    )
    assert parse_subfinder(stdout) == ["a.example.com", "b.example.com"]


def test_parse_subfinder_array() -> None:
    stdout = json.dumps([{"host": "a.example.com"}, {"host": "b.example.com"}])
    assert parse_subfinder(stdout) == ["a.example.com", "b.example.com"]


def test_parse_subfinder_ignores_garbage() -> None:
    stdout = 'not json\n[broken\n{"host":"a.example.com"}\n'
    assert parse_subfinder(stdout) == ["a.example.com"]


def test_parse_naabu_real_shape() -> None:
    stdout = (
        '{"ip":"93.184.216.34","timestamp":"2026-01-01T00:00:00Z","port":443,'
        '"protocol":"tcp","tls":true}\n'
        '{"ip":"93.184.216.34","port":80,"protocol":"tcp","tls":false}\n'
    )
    ports = parse_naabu(stdout)
    assert ports == [
        {
            "host": "93.184.216.34",
            "ip": "93.184.216.34",
            "port": 443,
            "protocol": "tcp",
            "tls": True,
        },
        {
            "host": "93.184.216.34",
            "ip": "93.184.216.34",
            "port": 80,
            "protocol": "tcp",
            "tls": False,
        },
    ]


def test_parse_naabu_dedupes_and_skips_bad_lines() -> None:
    stdout = (
        '{"ip":"1.1.1.1","port":22,"protocol":"tcp"}\n'
        '{"ip":"1.1.1.1","port":22,"protocol":"tcp"}\n'
        '{"ip":"1.1.1.1","port":"x","protocol":"tcp"}\n'
        '{"ip":"","port":80}\n'
        "\n"
    )
    ports = parse_naabu(stdout)
    assert len(ports) == 1
    assert ports[0]["port"] == 22


def test_parse_httpx_real_shape() -> None:
    stdout = (
        '{"url":"http://a.example.com","status_code":200,"title":"Home",'
        '"webserver":"nginx","tech":["nginx","PHP"],"failed":false}\n'
        '{"url":"https://a.example.com","status_code":301,"title":"",'
        '"webserver":"nginx","tech":[]}\n'
    )
    alive = parse_httpx(stdout)
    assert [item["url"] for item in alive] == [
        "http://a.example.com",
        "https://a.example.com",
    ]
    assert alive[0]["status_code"] == 200
    assert alive[0]["tech"] == ["nginx", "PHP"]


def test_parse_httpx_skips_failed_and_duplicates() -> None:
    stdout = (
        '{"url":"http://a.example.com","status_code":0,"failed":true}\n'
        '{"url":"http://a.example.com","status_code":200}\n'
        '{"url":"http://a.example.com","status_code":200}\n'
    )
    alive = parse_httpx(stdout)
    assert len(alive) == 1
    assert alive[0]["status_code"] == 200


# -- findings ------------------------------------------------------------


def test_port_findings_severity_map() -> None:
    ports = [
        {"host": "10.0.0.5", "port": 3306, "protocol": "tcp", "tls": False},
        {"host": "10.0.0.5", "port": 2375, "protocol": "tcp", "tls": False},
        {"host": "10.0.0.5", "port": 80, "protocol": "tcp", "tls": False},
        {"host": "10.0.0.5", "port": 9999, "protocol": "tcp", "tls": False},
    ]
    findings = {f.title: f for f in PrideAdapter().port_findings(ports, _TARGET)}
    assert findings["MySQL exposed on 10.0.0.5:3306/tcp"].severity == Severity.high
    assert findings["Docker API exposed on 10.0.0.5:2375/tcp"].severity == Severity.critical
    assert findings["HTTP exposed on 10.0.0.5:80/tcp"].severity == Severity.info
    assert findings["unknown exposed on 10.0.0.5:9999/tcp"].severity == Severity.low


def test_port_findings_have_english_title_and_remediation() -> None:
    ports = [{"host": "10.0.0.5", "port": 5432, "protocol": "tcp", "tls": False}]
    (finding,) = PrideAdapter().port_findings(ports, _TARGET)
    assert finding.title.isascii()
    assert finding.location == "10.0.0.5:5432"
    assert finding.remediation is not None
    assert finding.source_tools == ["pride"]


def test_alive_findings_are_low_with_status() -> None:
    alive = [{"url": "https://a.example.com", "status_code": 200, "title": "Home"}]
    (finding,) = PrideAdapter().alive_findings(alive, _TARGET)
    assert finding.severity == Severity.low
    assert finding.title == "HTTP service responded on https://a.example.com (200)"
    assert finding.evidence["title"] == "Home"


def test_alive_findings_skip_url_without_status() -> None:
    assert PrideAdapter().alive_findings([{"url": "", "status_code": 0}], _TARGET) == []


# -- pipeline ------------------------------------------------------------


class _FakeTools:
    """Instead of run_tool: pre-made output for each tool."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.temp_paths: list[str] = []
        self.httpx_ports: str | None = None
        self.naabu_hosts: list[str] = []

    def __call__(self, argv: list[str], *, timeout: int = 900) -> RunResult:
        self.calls.append(argv)
        tool = argv[0]
        if tool == "subfinder":
            stdout = (
                '{"host":"www.example.com","input":"example.com"}\n'
                '{"host":"api.example.com","input":"example.com"}\n'
            )
        elif tool == "naabu":
            path = argv[argv.index("-list") + 1]
            self.temp_paths.append(path)
            with open(path, encoding="utf-8") as handle:
                self.naabu_hosts = handle.read().split()
            stdout = (
                '{"ip":"93.184.216.34","port":443,"protocol":"tcp","tls":true}\n'
                '{"ip":"93.184.216.34","port":80,"protocol":"tcp","tls":false}\n'
            )
        elif tool == "httpx":
            path = argv[argv.index("-list") + 1]
            self.temp_paths.append(path)
            if "-ports" in argv:
                self.httpx_ports = argv[argv.index("-ports") + 1]
            stdout = (
                '{"url":"https://www.example.com","status_code":200,'
                '"title":"Example","webserver":"nginx","tech":["nginx"]}\n'
            )
        else:  # pragma: no cover - kutilmagan tool
            stdout = ""
        return RunResult(argv=argv, returncode=0, stdout=stdout, duration_ms=1)


def _install(monkeypatch) -> _FakeTools:
    fake = _FakeTools()
    monkeypatch.setattr("sins.adapters.pride._resolve_tool", lambda tool: tool)
    monkeypatch.setattr("sins.adapters.pride.run_tool", fake)
    return fake


def test_pipeline_domain_runs_all_stages(monkeypatch) -> None:
    fake = _install(monkeypatch)
    findings = PrideAdapter().run(ScanContext(target=_TARGET))

    assert [call[0] for call in fake.calls] == ["subfinder", "naabu", "httpx"]
    assert fake.naabu_hosts == ["example.com", "www.example.com", "api.example.com"]
    assert fake.httpx_ports == "443,80"

    titles = {f.title for f in findings}
    assert "HTTPS exposed on 93.184.216.34:443/tcp" in titles
    assert "HTTP service responded on https://www.example.com (200)" in titles


def test_pipeline_ip_skips_subfinder(monkeypatch) -> None:
    fake = _install(monkeypatch)
    PrideAdapter().run(ScanContext(target="93.184.216.34"))
    assert "subfinder" not in [call[0] for call in fake.calls]


def test_pipeline_cleans_temp_files(monkeypatch) -> None:
    fake = _install(monkeypatch)
    PrideAdapter().run(ScanContext(target=_TARGET))
    assert fake.temp_paths
    assert not any(os.path.exists(path) for path in fake.temp_paths)


def test_pipeline_survives_missing_naabu(monkeypatch) -> None:
    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        if argv[0] == "naabu":
            from sins.runner import ToolNotFound

            raise ToolNotFound("naabu")
        if argv[0] == "httpx":
            return RunResult(
                argv=argv,
                returncode=0,
                stdout='{"url":"http://example.com","status_code":200}\n',
            )
        return RunResult(argv=argv, returncode=0, stdout="")

    monkeypatch.setattr("sins.adapters.pride._resolve_tool", lambda tool: tool)
    monkeypatch.setattr("sins.adapters.pride.run_tool", fake_run)

    findings = PrideAdapter().run(ScanContext(target=_TARGET))
    assert [f.title for f in findings] == ["HTTP service responded on http://example.com (200)"]


def test_pipeline_filters_unsafe_subdomains(monkeypatch) -> None:
    fake = _install(monkeypatch)
    monkeypatch.setattr(
        PrideAdapter,
        "_subfinder",
        lambda self, host, ctx: ["ok.example.com", "-bad", "has space", "ok.example.com"],
    )
    hosts = PrideAdapter().enumerate_hosts("example.com", "domain", ScanContext(target=_TARGET))
    assert hosts == ["example.com", "ok.example.com"]
    assert fake.calls == []


def test_pipeline_caps_hosts(monkeypatch) -> None:
    adapter = PrideAdapter()
    monkeypatch.setattr(
        adapter, "_subfinder", lambda host, ctx: [f"h{i}.example.com" for i in range(500)]
    )
    hosts = adapter.enumerate_hosts("example.com", "domain", ScanContext(target=_TARGET))
    assert len(hosts) == 200


def test_ports_arg_is_capped() -> None:
    ports = [{"port": 1000 + i} for i in range(MAX_PORTS + 10)]
    from sins.adapters.pride import _ports_arg

    assert len(_ports_arg(ports).split(",")) == MAX_PORTS


# -- adapter contract ----------------------------------------------------


def test_applies_to_network_targets_only() -> None:
    adapter = PrideAdapter()
    assert adapter.applies_to("example.com")
    assert adapter.applies_to("https://example.com")
    assert adapter.applies_to("127.0.0.1")
    assert not adapter.applies_to("./src")


def test_available_with_any_single_tool(monkeypatch) -> None:
    monkeypatch.setattr(
        "sins.adapters.pride._resolve_tool",
        lambda tool: "/usr/bin/httpx" if tool == "httpx" else None,
    )
    assert PrideAdapter().available() is True
    monkeypatch.setattr("sins.adapters.pride._resolve_tool", lambda tool: None)
    assert PrideAdapter().available() is False


def test_resolve_tool_env_override(monkeypatch) -> None:
    monkeypatch.setenv("SINS_HTTPX_BIN", "/custom/httpx")
    assert _resolve_tool("httpx") == "/custom/httpx"


def test_resolve_tool_skips_shadowing_binary(monkeypatch, tmp_path) -> None:
    """PATH'dagi Python httpx soyasi emas, ProjectDiscovery binari tanlanadi."""
    shadow = tmp_path / "venv-bin"
    shadow.mkdir()
    shadow_bin = shadow / "httpx"
    shadow_bin.write_text("#!/bin/sh\n")
    good = tmp_path / "go-bin"
    good.mkdir()
    good_bin = good / "httpx"
    good_bin.write_text("#!/bin/sh\n")

    monkeypatch.setattr("sins.adapters.pride.which", lambda tool: str(shadow_bin))
    monkeypatch.setattr("sins.adapters.pride._FALLBACK_BIN_DIRS", (str(good),))
    monkeypatch.setattr(
        "sins.adapters.pride._is_projectdiscovery", lambda path: path == str(good_bin)
    )
    assert _resolve_tool("httpx") == str(good_bin)


def test_registry_contains_both_new_engines() -> None:
    from sins.adapters import REGISTRY

    assert REGISTRY["pride"].name == "pride"
    assert REGISTRY["envy"].name == "envy"
