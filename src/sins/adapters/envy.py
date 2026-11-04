"""Envy: TLS/SSL configuration check (sslyze adapter).

What runs (a single subprocess, shell=False):
  sslyze --json_out - --certinfo --compression --http_headers
         --sslv2 --sslv3 --tlsv1 --tlsv1_1 --heartbleed  host:port

Why sslyze:
  - Checks the certificate chain, protocol versions and Heartbleed in one
    pass; we never implement TLS handshake logic ourselves.
  - `--json_out -` is a stable, documented machine-readable format.
  - sslyze 6.x dropped `--regular` — checks are requested with explicit
    flags. There is no `--jsonfile` flag; it is `--json_out`.

Output shape (sslyze 6.x):
  {"server_scan_results": [{"scan_status": "COMPLETED",
                            "server_location": {"hostname": ..., "port": ...},
                            "scan_result": {"certificate_info": {...},
                                            "ssl_3_0_cipher_suites": {...}}}]}

Each plugin looks like `{"status": "COMPLETED"|"NOT_SCHEDULED"|"ERROR", "result": ...}`.
`NOT_SCHEDULED` means the check was not requested; it is skipped silently.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

from ..dedup import dedup_key
from ..runner import ToolNotFound, run_tool, which
from ..schemas import Category, FindingContract, Remediation, Severity
from ..targets import InvalidTarget, classify_target, extract_host
from .base import ScanContext

log = logging.getLogger(__name__)

# Warn when the certificate has fewer than this many days left.
EXPIRY_WARNING_DAYS = 30

# Weak signature algorithms (certificate or chain).
_WEAK_SIGNATURE_HASHES = {"md5", "sha1"}

# Protocol versions: plugin key -> (display name, severity).
_LEGACY_PROTOCOLS: dict[str, tuple[str, Severity]] = {
    "ssl_2_0_cipher_suites": ("SSL 2.0", Severity.critical),
    "ssl_3_0_cipher_suites": ("SSL 3.0", Severity.high),
    "tls_1_0_cipher_suites": ("TLS 1.0", Severity.medium),
    "tls_1_1_cipher_suites": ("TLS 1.1", Severity.medium),
}

_SSLYZE_CHECKS = [
    "--certinfo",
    "--compression",
    "--http_headers",
    "--sslv2",
    "--sslv3",
    "--tlsv1",
    "--tlsv1_1",
    "--heartbleed",
]


class EnvyAdapter:
    name: ClassVar[str] = "envy"
    category: ClassVar[Category] = Category.tls
    sin: ClassVar[str] = "Envy"

    def available(self) -> bool:
        return which("sslyze") is not None

    def applies_to(self, target: str) -> bool:
        """TLS is meaningful only for network targets, not local directories."""
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return True
        return kind in {"domain", "url", "ip"}

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        host, port = _split_host_port(ctx.target)
        if not host:
            log.warning("envy: could not extract host from target: %r", ctx.target)
            return []

        argv = ["sslyze", *_SSLYZE_CHECKS, "--json_out", "-", f"{host}:{port}"]
        try:
            result = run_tool(argv, timeout=ctx.timeout)
        except ToolNotFound as exc:
            log.warning("sslyze not found: %s", exc)
            return []

        if not result.ok:
            log.warning(
                "sslyze returncode=%s stderr=%r",
                result.returncode,
                result.stderr[:300],
            )
            return []

        return self.parse(result.stdout, ctx.target)

    # -- parsing ---------------------------------------------------------

    def parse(self, stdout: str, target: str) -> list[FindingContract]:
        text = stdout.strip()
        if not text:
            return []
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            log.warning("envy: sslyze output is not JSON")
            return []
        if not isinstance(payload, dict):
            return []

        findings: list[FindingContract] = []
        for server in payload.get("server_scan_results") or []:
            if not isinstance(server, dict):
                continue
            if server.get("scan_status") != "COMPLETED":
                log.info(
                    "envy: scan did not complete (%s) — skipped",
                    server.get("scan_status"),
                )
                continue
            scan_result = server.get("scan_result")
            if not isinstance(scan_result, dict):
                continue
            location = _location(server, target)
            findings += self._certificate_findings(scan_result, location, target)
            findings += self._protocol_findings(scan_result, location, target)

        return _dedupe(findings)

    def _certificate_findings(
        self,
        scan_result: dict[str, Any],
        location: str,
        target: str,
    ) -> list[FindingContract]:
        info = _plugin_result(scan_result, "certificate_info")
        if not info:
            return []

        findings: list[FindingContract] = []
        deployments = info.get("certificate_deployments") or []
        for deployment in deployments:
            if not isinstance(deployment, dict):
                continue
            chain = deployment.get("received_certificate_chain") or []
            leaf = chain[0] if chain and isinstance(chain[0], dict) else {}

            findings += self._expiry_finding(leaf, location, target)
            findings += self._signature_finding(deployment, leaf, location, target)
            findings += self._trust_finding(deployment, leaf, location, target)
        return findings

    def _expiry_finding(
        self,
        leaf: dict[str, Any],
        location: str,
        target: str,
    ) -> list[FindingContract]:
        not_after = _parse_timestamp(leaf.get("not_valid_after"))
        if not_after is None:
            return []

        delta = not_after - datetime.now(UTC)
        # Round down for negative values and up for positive ones: a certificate
        # with 9.9 days left is shown as "10 days", not "9 days".
        if delta.total_seconds() < 0:
            days_left = math.floor(delta.total_seconds() / 86400)
        else:
            days_left = math.ceil(delta.total_seconds() / 86400)
        if days_left < 0:
            return [
                self._finding(
                    location=location,
                    target=target,
                    title="TLS certificate has expired",
                    severity=Severity.high,
                    evidence={
                        "not_valid_after": leaf.get("not_valid_after"),
                        "days_left": days_left,
                    },
                    remediation=_remediation("cert_expired"),
                )
            ]
        if days_left <= EXPIRY_WARNING_DAYS:
            return [
                self._finding(
                    location=location,
                    target=target,
                    title=f"TLS certificate expires in {days_left} days",
                    severity=Severity.medium,
                    evidence={
                        "not_valid_after": leaf.get("not_valid_after"),
                        "days_left": days_left,
                    },
                    remediation=_remediation("cert_expiring"),
                )
            ]
        return []

    def _signature_finding(
        self,
        deployment: dict[str, Any],
        leaf: dict[str, Any],
        location: str,
        target: str,
    ) -> list[FindingContract]:
        findings: list[FindingContract] = []
        leaf_hash = _hash_name(leaf.get("signature_hash_algorithm"))
        if leaf_hash in _WEAK_SIGNATURE_HASHES:
            findings.append(
                self._finding(
                    location=location,
                    target=target,
                    title=f"TLS certificate uses weak {leaf_hash.upper()} signature",
                    severity=Severity.high,
                    evidence={"signature_hash_algorithm": leaf_hash},
                    remediation=_remediation("weak_signature"),
                )
            )
        elif deployment.get("verified_chain_has_sha1_signature"):
            findings.append(
                self._finding(
                    location=location,
                    target=target,
                    title="Certificate chain contains a SHA-1 signature",
                    severity=Severity.medium,
                    evidence={"verified_chain_has_sha1_signature": True},
                    remediation=_remediation("weak_chain_signature"),
                )
            )
        return findings

    def _trust_finding(
        self,
        deployment: dict[str, Any],
        leaf: dict[str, Any],
        location: str,
        target: str,
    ) -> list[FindingContract]:
        validations = [
            v for v in (deployment.get("path_validation_results") or []) if isinstance(v, dict)
        ]
        if not validations:
            return []
        if any(v.get("was_validation_successful") for v in validations):
            return []

        subject = _rfc4514(leaf.get("subject"))
        issuer = _rfc4514(leaf.get("issuer"))
        self_signed = bool(subject) and subject == issuer

        errors = sorted(
            {
                str(v.get("validation_error") or "").strip()
                for v in validations
                if v.get("validation_error")
            }
        )
        return [
            self._finding(
                location=location,
                target=target,
                title=(
                    "TLS certificate is self-signed"
                    if self_signed
                    else "TLS certificate is not trusted"
                ),
                severity=Severity.high,
                evidence={
                    "subject": subject,
                    "issuer": issuer,
                    "self_signed": self_signed,
                    "trust_stores_checked": len(validations),
                    "validation_errors": errors[:5],
                },
                remediation=_remediation("untrusted"),
            )
        ]

    def _protocol_findings(
        self,
        scan_result: dict[str, Any],
        location: str,
        target: str,
    ) -> list[FindingContract]:
        findings: list[FindingContract] = []

        for plugin, (label, severity) in _LEGACY_PROTOCOLS.items():
            result = _plugin_result(scan_result, plugin)
            if not result:
                continue
            if result.get("accepted_cipher_suites"):
                findings.append(
                    self._finding(
                        location=location,
                        target=target,
                        title=f"{label} is enabled",
                        severity=severity,
                        evidence={
                            "protocol": label,
                            "accepted_cipher_suites": len(result["accepted_cipher_suites"]),
                        },
                        remediation=_remediation("legacy_protocol"),
                    )
                )

        heartbleed = _plugin_result(scan_result, "heartbleed")
        if heartbleed and heartbleed.get("is_vulnerable_to_heartbleed"):
            findings.append(
                self._finding(
                    location=location,
                    target=target,
                    title="Server is vulnerable to Heartbleed (CVE-2014-0160)",
                    severity=Severity.critical,
                    evidence={"is_vulnerable_to_heartbleed": True},
                    remediation=_remediation("heartbleed"),
                )
            )

        compression = _plugin_result(scan_result, "tls_compression")
        if compression and compression.get("supports_compression"):
            findings.append(
                self._finding(
                    location=location,
                    target=target,
                    title="TLS compression is enabled (CRIME)",
                    severity=Severity.medium,
                    evidence={"supports_compression": True},
                    remediation=_remediation("compression"),
                )
            )

        headers = _plugin_result(scan_result, "http_headers")
        if (
            headers
            and headers.get("http_request_sent")
            and not headers.get("http_error_trace")
            and not headers.get("strict_transport_security_header")
        ):
            findings.append(
                self._finding(
                    location=location,
                    target=target,
                    title="HSTS header is missing",
                    severity=Severity.low,
                    evidence={
                        "strict_transport_security_header": None,
                        "http_path_redirected_to": headers.get("http_path_redirected_to"),
                    },
                    remediation=_remediation("hsts"),
                )
            )
        return findings

    def _finding(
        self,
        *,
        location: str,
        target: str,
        title: str,
        severity: Severity,
        evidence: dict[str, Any],
        remediation: Remediation,
    ) -> FindingContract:
        return FindingContract(
            category=self.category,
            title=title,
            severity=severity,
            location=location,
            evidence=evidence,
            source_tools=[self.name],
            dedup_key=dedup_key(self.name, target, location, title),
            remediation=remediation,
        )


# -- helpers -------------------------------------------------------------


def _split_host_port(value: str) -> tuple[str, int]:
    """`https://example.com/path` -> `("example.com", 443)`.

    If no port is given, it is chosen by scheme (http -> 80, otherwise 443).
    Malformed IPv6 input does not crash either — the host comes back empty.
    """
    raw = value.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = parts.port or (80 if parts.scheme == "http" else 443)
    except ValueError:
        return extract_host(value), 443
    return host, port


def _location(server: dict[str, Any], fallback: str) -> str:
    loc = server.get("server_location") or {}
    host = str(loc.get("hostname") or extract_host(fallback))
    port = loc.get("port") or 443
    return f"{host}:{port}".lower()


def _plugin_result(scan_result: dict[str, Any], plugin: str) -> dict[str, Any] | None:
    entry = scan_result.get(plugin)
    if not isinstance(entry, dict) or entry.get("status") != "COMPLETED":
        return None
    result = entry.get("result")
    return result if isinstance(result, dict) else None


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _hash_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or "").strip().lower()
    return str(value or "").strip().lower()


def _rfc4514(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("rfc4514_string") or "").strip()
    return ""


def _dedupe(findings: list[FindingContract]) -> list[FindingContract]:
    seen: set[str] = set()
    out: list[FindingContract] = []
    for finding in findings:
        if finding.dedup_key in seen:
            continue
        seen.add(finding.dedup_key)
        out.append(finding)
    return out


def _remediation(code: str) -> Remediation:
    """Remediation path — practical steps."""
    table: dict[str, Remediation] = {
        "cert_expired": Remediation(
            summary=("The TLS certificate has expired — browsers show the site as untrusted."),
            steps=[
                "Renew the certificate (e.g. `certbot renew` or from the CA panel).",
                "Make sure renewal is automated: 30 days before expiry.",
                "After renewal, verify the full chain is installed.",
            ],
            references=["https://letsencrypt.org/docs/renewal-reminder/"],
        ),
        "cert_expiring": Remediation(
            summary="The TLS certificate expires in the coming days.",
            steps=[
                "Verify automatic renewal (ACME/`certbot`) is configured.",
                "If renewal fails, reissue the certificate manually.",
                "Add an expiry warning to your monitoring.",
            ],
        ),
        "weak_signature": Remediation(
            summary="The certificate is signed with a weak algorithm.",
            steps=[
                "Obtain a new certificate signed with SHA-256 or stronger.",
                "Confirm with your CA that SHA-1 has been retired.",
            ],
        ),
        "weak_chain_signature": Remediation(
            summary="The certificate chain contains a SHA-1 signature.",
            steps=[
                "Replace intermediate certificates with a modern SHA-256 chain.",
                "Reinstall the full chain (leaf + intermediate) on the server.",
            ],
        ),
        "untrusted": Remediation(
            summary="The certificate cannot be trusted through a trusted CA chain.",
            steps=[
                "Obtain a certificate from a public CA, or distribute your internal CA to clients.",
                "Install the full chain (leaf + intermediate) on the server.",
                "Verify the certificate CN/SAN matches the target domain.",
            ],
        ),
        "legacy_protocol": Remediation(
            summary="A legacy TLS/SSL protocol is enabled — risk of weak encryption.",
            steps=[
                "Disable legacy protocols in the server configuration (SSLv2/SSLv3/TLS 1.0/1.1).",
                "Keep only TLS 1.2 and TLS 1.3.",
                "If legacy clients depend on them, plan their upgrade.",
            ],
            references=["https://ssl-config.mozilla.org/"],
        ),
        "heartbleed": Remediation(
            summary="The server is vulnerable to Heartbleed — memory can be read remotely.",
            steps=[
                "Update OpenSSL immediately (1.0.1g or later).",
                "Replace the certificate and private keys — they may have been stolen.",
                "Revoke all session tokens.",
            ],
            references=["https://heartbleed.com/"],
        ),
        "compression": Remediation(
            summary="TLS compression is enabled — it opens the door to CRIME attacks.",
            steps=[
                "Disable TLS compression in the server configuration.",
                "Use compression at the application layer instead (e.g. gzip over HTTP).",
            ],
        ),
        "hsts": Remediation(
            summary="The HSTS header is missing — the first request can be hijacked over HTTP.",
            steps=[
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                "Redirect all HTTP requests to HTTPS.",
                "Before adding to the preload list, verify every subdomain works over HTTPS.",
            ],
            references=[
                "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
            ],
        ),
    }
    return table[code]


__all__ = ["EnvyAdapter"]
