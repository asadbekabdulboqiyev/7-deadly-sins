"""Envy adapter tests - for the real sslyze 6.x JSON schema parser.

The fixtures are hand-written real schema samples (from sslyze `--json_out -`
output): `server_scan_results[].scan_result.<plugin>.result`.
We compute from `now` - the tests must not break as time passes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sins.adapters.base import ScanContext
from sins.adapters.envy import EnvyAdapter
from sins.runner import RunResult
from sins.schemas import Severity

_TARGET = "example.com"


def _ts(days: int) -> str:
    moment = datetime.now(UTC) + timedelta(days=days)
    return moment.isoformat().replace("+00:00", "Z")


def _payload(
    *,
    not_after: str | None = None,
    subject: str = "CN=example.com",
    issuer: str = "CN=Example CA",
    leaf_hash: str = "sha256",
    validated: bool = True,
    chain_sha1: bool = False,
    accepted: dict[str, int] | None = None,
    heartbleed: bool = False,
    compression: bool = False,
    hsts: str | None = "max-age=31536000",
    scan_status: str = "COMPLETED",
    http_error: str | None = None,
) -> dict[str, Any]:
    not_after = not_after or _ts(200)
    deployments = [
        {
            "received_certificate_chain": [
                {
                    "not_valid_before": _ts(-30),
                    "not_valid_after": not_after,
                    "subject": {"rfc4514_string": subject},
                    "issuer": {"rfc4514_string": issuer},
                    "signature_hash_algorithm": {"name": leaf_hash, "digest_size": 32},
                }
            ],
            "path_validation_results": [
                {
                    "was_validation_successful": validated,
                    "validation_error": None if validated else "unable to get local issuer",
                    "trust_store": {"name": "Mozilla"},
                }
            ],
            "verified_chain_has_sha1_signature": chain_sha1,
        }
    ]
    scan_result: dict[str, Any] = {
        "certificate_info": {
            "status": "COMPLETED",
            "result": {"certificate_deployments": deployments},
        },
        "http_headers": {
            "status": "COMPLETED",
            "result": {
                "http_request_sent": "GET / HTTP/1.1\r\n\r\n",
                "http_error_trace": http_error,
                "http_path_redirected_to": "/",
                "strict_transport_security_header": hsts,
            },
        },
        "tls_compression": {
            "status": "COMPLETED",
            "result": {"supports_compression": compression},
        },
        "heartbleed": {
            "status": "COMPLETED",
            "result": {"is_vulnerable_to_heartbleed": heartbleed},
        },
    }
    for plugin in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites"):
        scan_result[plugin] = {"status": "NOT_SCHEDULED", "result": None}
    for plugin in ("tls_1_0_cipher_suites", "tls_1_1_cipher_suites"):
        scan_result[plugin] = {"status": "NOT_SCHEDULED", "result": None}
    for plugin, count in (accepted or {}).items():
        scan_result[plugin] = {
            "status": "COMPLETED",
            "result": {"accepted_cipher_suites": [{"cipher_suite": {}}] * count},
        }

    return {
        "server_scan_results": [
            {
                "scan_status": scan_status,
                "connectivity_status": "COMPLETED",
                "server_location": {"hostname": "example.com", "port": 443},
                "scan_result": scan_result,
            }
        ]
    }


def _parse(payload: dict[str, Any]) -> list[Any]:
    return EnvyAdapter().parse(json.dumps(payload), _TARGET)


def _by_title(findings: list[Any]) -> dict[str, Any]:
    return {f.title: f for f in findings}


# -- certificate ---------------------------------------------------------


def test_expired_certificate_is_high() -> None:
    findings = _by_title(_parse(_payload(not_after=_ts(-10))))
    finding = findings["TLS certificate has expired"]
    assert finding.severity == Severity.high
    assert finding.evidence["days_left"] < 0
    assert finding.remediation is not None
    assert finding.location == "example.com:443"


def test_expiring_soon_certificate_is_medium() -> None:
    findings = _by_title(_parse(_payload(not_after=_ts(10))))
    assert findings["TLS certificate expires in 10 days"].severity == Severity.medium


def test_valid_certificate_has_no_expiry_finding() -> None:
    titles = {f.title for f in _parse(_payload(not_after=_ts(200)))}
    assert not any("expire" in title.lower() for title in titles)


def test_self_signed_certificate_is_flagged_once() -> None:
    payload = _payload(subject="CN=localhost", issuer="CN=localhost", validated=False)
    findings = _parse(payload)
    trust = [f for f in findings if "certificate is" in f.title]
    assert len(trust) == 1
    assert trust[0].title == "TLS certificate is self-signed"
    assert trust[0].severity == Severity.high
    assert trust[0].evidence["self_signed"] is True


def test_untrusted_certificate_is_flagged() -> None:
    findings = _by_title(_parse(_payload(validated=False)))
    finding = findings["TLS certificate is not trusted"]
    assert finding.severity == Severity.high
    assert finding.evidence["self_signed"] is False
    assert finding.evidence["trust_stores_checked"] == 1


def test_trusted_certificate_has_no_trust_finding() -> None:
    titles = {f.title for f in _parse(_payload(validated=True))}
    assert not any("trusted" in title or "self-signed" in title for title in titles)


def test_weak_leaf_signature_is_high() -> None:
    findings = _by_title(_parse(_payload(leaf_hash="sha1")))
    assert findings["TLS certificate uses weak SHA1 signature"].severity == Severity.high


def test_sha1_in_chain_is_medium() -> None:
    findings = _by_title(_parse(_payload(chain_sha1=True)))
    assert findings["Certificate chain contains a SHA-1 signature"].severity == Severity.medium


def test_sha1_chain_not_reported_when_leaf_is_sha1() -> None:
    titles = {f.title for f in _parse(_payload(leaf_hash="sha1", chain_sha1=True))}
    assert "Certificate chain contains a SHA-1 signature" not in titles


# -- protocols -----------------------------------------------------------


def test_sslv2_is_critical() -> None:
    payload = _payload(accepted={"ssl_2_0_cipher_suites": 3})
    findings = _by_title(_parse(payload))
    assert findings["SSL 2.0 is enabled"].severity == Severity.critical


def test_sslv3_is_high() -> None:
    payload = _payload(accepted={"ssl_3_0_cipher_suites": 2})
    findings = _by_title(_parse(payload))
    assert findings["SSL 3.0 is enabled"].severity == Severity.high


def test_tls10_and_tls11_are_medium() -> None:
    payload = _payload(accepted={"tls_1_0_cipher_suites": 4, "tls_1_1_cipher_suites": 4})
    findings = _by_title(_parse(payload))
    assert findings["TLS 1.0 is enabled"].severity == Severity.medium
    assert findings["TLS 1.1 is enabled"].severity == Severity.medium


def test_unscheduled_protocol_checks_are_ignored() -> None:
    assert "SSL 3.0 is enabled" not in _by_title(_parse(_payload()))


def test_heartbleed_is_critical() -> None:
    findings = _by_title(_parse(_payload(heartbleed=True)))
    finding = findings["Server is vulnerable to Heartbleed (CVE-2014-0160)"]
    assert finding.severity == Severity.critical
    assert finding.remediation is not None


def test_tls_compression_is_medium() -> None:
    findings = _by_title(_parse(_payload(compression=True)))
    assert findings["TLS compression is enabled (CRIME)"].severity == Severity.medium


def test_missing_hsts_is_low() -> None:
    findings = _by_title(_parse(_payload(hsts=None)))
    assert findings["HSTS header is missing"].severity == Severity.low


def test_present_hsts_is_not_reported() -> None:
    assert "HSTS header is missing" not in _by_title(_parse(_payload()))


def test_hsts_skipped_when_http_request_failed() -> None:
    payload = _payload(hsts=None, http_error="connection reset")
    assert "HSTS header is missing" not in _by_title(_parse(payload))


# -- robustness ----------------------------------------------------------


def test_invalid_json_returns_empty() -> None:
    assert EnvyAdapter().parse("not json", _TARGET) == []


def test_non_completed_scan_is_skipped() -> None:
    assert _parse(_payload(scan_status="ERROR")) == []


def test_empty_output_returns_empty() -> None:
    assert EnvyAdapter().parse("   ", _TARGET) == []


def test_duplicate_deployment_is_deduped() -> None:
    payload = _payload(not_after=_ts(-1))
    payload["server_scan_results"][0]["scan_result"]["certificate_info"]["result"][
        "certificate_deployments"
    ].append(
        payload["server_scan_results"][0]["scan_result"]["certificate_info"]["result"][
            "certificate_deployments"
        ][0]
    )
    findings = _parse(payload)
    assert len(findings) == len({f.dedup_key for f in findings})


def test_every_finding_has_english_title_and_remediation() -> None:
    payload = _payload(
        not_after=_ts(-1),
        validated=False,
        leaf_hash="sha1",
        accepted={"ssl_3_0_cipher_suites": 1},
        heartbleed=True,
        compression=True,
        hsts=None,
    )
    findings = _parse(payload)
    assert findings
    for finding in findings:
        assert finding.title.isascii(), finding.title
        assert finding.remediation is not None


# -- argv / target handling ----------------------------------------------


def test_cli_flags_match_sslyze_6(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        seen["argv"] = argv
        return RunResult(argv=argv, returncode=0, stdout=json.dumps(_payload()))

    monkeypatch.setattr("sins.adapters.envy.run_tool", fake_run)
    EnvyAdapter().run(ScanContext(target="https://example.com/path"))

    argv = seen["argv"]
    assert argv[0] == "sslyze"
    assert "--json_out" in argv
    assert argv[argv.index("--json_out") + 1] == "-"
    assert "--jsonfile" not in argv
    assert "--regular" not in argv
    assert argv[-1] == "example.com:443"
    for flag in ("--certinfo", "--compression", "--http_headers", "--sslv3", "--heartbleed"):
        assert flag in argv


def test_run_uses_http_default_port(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        seen["argv"] = argv
        return RunResult(argv=argv, returncode=0, stdout="")

    monkeypatch.setattr("sins.adapters.envy.run_tool", fake_run)
    EnvyAdapter().run(ScanContext(target="http://example.com"))
    assert seen["argv"][-1] == "example.com:80"


def test_run_handles_missing_tool(monkeypatch) -> None:
    from sins.runner import ToolNotFound

    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        raise ToolNotFound("sslyze")

    monkeypatch.setattr("sins.adapters.envy.run_tool", fake_run)
    assert EnvyAdapter().run(ScanContext(target=_TARGET)) == []


def test_run_handles_failed_returncode(monkeypatch) -> None:
    def fake_run(argv: list[str], *, timeout: int = 900) -> RunResult:
        return RunResult(argv=argv, returncode=2, stderr="boom")

    monkeypatch.setattr("sins.adapters.envy.run_tool", fake_run)
    assert EnvyAdapter().run(ScanContext(target=_TARGET)) == []


def test_applies_to_network_targets_only() -> None:
    adapter = EnvyAdapter()
    assert adapter.applies_to("example.com")
    assert adapter.applies_to("https://example.com")
    assert adapter.applies_to("127.0.0.1")
    assert not adapter.applies_to("./src")


def test_available_uses_which(monkeypatch) -> None:
    monkeypatch.setattr("sins.adapters.envy.which", lambda tool: "/usr/bin/sslyze")
    assert EnvyAdapter().available() is True
    monkeypatch.setattr("sins.adapters.envy.which", lambda tool: None)
    assert EnvyAdapter().available() is False
