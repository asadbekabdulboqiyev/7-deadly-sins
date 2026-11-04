"""Pride: attack surface mapping (subfinder + naabu + httpx).

Stages (each a separate subprocess, shell=False):
  1. subfinder -d <domain> -json -silent   → subdomains (domains only)
  2. naabu -list hosts.txt -json -silent   → open TCP ports
  3. httpx -l hosts.txt -ports ... -json   → live HTTP(S) services

Why this way:
  - Three tools doing three well-defined jobs; we only wire them together.
  - Every stage is best-effort: if a tool is missing or fails, the remaining
    stages keep running. One failure never stops the whole scan.
  - Naabu output is one JSON line per port (JSONL), not an array.
  - Ports are passed to httpx via `-ports` — otherwise non-standard ports
    such as 8099 are never checked.

applies_to: domain | URL | IP. Not applicable to local directories (osv-scanner).
category: exposure.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Any, ClassVar

from ..dedup import dedup_key
from ..runner import ToolNotFound, run_tool, which
from ..schemas import Category, FindingContract, Remediation, Severity
from ..targets import InvalidTarget, classify_target, extract_host
from .base import ScanContext

log = logging.getLogger(__name__)

# Maximum number of hosts checked in one scan (subdomain expansion).
MAX_HOSTS = 200
# Maximum number of ports passed to httpx.
MAX_PORTS = 64

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")

# The first `httpx` on PATH may not be ProjectDiscovery's: the Python
# `httpx` package installs its own CLI into the venv and shadows the real one.
# That is why tools are verified explicitly and fallback directories are checked.
_TOOL_ENV = {
    "subfinder": "SINS_SUBFINDER_BIN",
    "naabu": "SINS_NAABU_BIN",
    "httpx": "SINS_HTTPX_BIN",
}
_FALLBACK_BIN_DIRS = ("~/go/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/.local/bin")

# Port -> (service name, severity). A port not in the list is low.
_PORT_RISK: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.medium),
    22: ("SSH", Severity.medium),
    23: ("Telnet", Severity.high),
    25: ("SMTP", Severity.low),
    53: ("DNS", Severity.low),
    80: ("HTTP", Severity.info),
    110: ("POP3", Severity.medium),
    143: ("IMAP", Severity.medium),
    443: ("HTTPS", Severity.info),
    445: ("SMB", Severity.high),
    1433: ("MSSQL", Severity.high),
    1521: ("Oracle DB", Severity.high),
    2375: ("Docker API", Severity.critical),
    3306: ("MySQL", Severity.high),
    3389: ("RDP", Severity.high),
    5432: ("PostgreSQL", Severity.high),
    5900: ("VNC", Severity.high),
    6379: ("Redis", Severity.high),
    8080: ("HTTP alternate", Severity.low),
    8443: ("HTTPS alternate", Severity.low),
    9200: ("Elasticsearch", Severity.high),
    11211: ("Memcached", Severity.high),
    27017: ("MongoDB", Severity.high),
}


class PrideAdapter:
    name: ClassVar[str] = "pride"
    category: ClassVar[Category] = Category.exposure
    sin: ClassVar[str] = "Pride"

    def available(self) -> bool:
        # The adapter works when at least one tool exists — stages are best-effort.
        return any(_resolve_tool(tool) for tool in ("subfinder", "naabu", "httpx"))

    def applies_to(self, target: str) -> bool:
        try:
            kind = classify_target(target)
        except InvalidTarget:
            return False
        return kind in {"domain", "url", "ip"}

    # -- pipeline --------------------------------------------------------

    def run(self, ctx: ScanContext) -> list[FindingContract]:
        kind = classify_target(ctx.target)
        host = extract_host(ctx.target)
        if not host:
            log.warning("pride: could not extract host from target: %r", ctx.target)
            return []

        hosts = self.enumerate_hosts(host, kind, ctx)
        ports = self.scan_ports(hosts, ctx)
        alive = self.probe_http(hosts, ports, ctx)

        findings = self.port_findings(ports, ctx.target)
        findings += self.alive_findings(alive, ctx.target)
        return _dedupe(findings)

    def enumerate_hosts(self, host: str, kind: str, ctx: ScanContext) -> list[str]:
        """Expands a domain with subfinder, otherwise returns the host alone."""
        hosts = [host]
        if kind == "domain":
            hosts += self._subfinder(host, ctx)
        return _clean_hosts(hosts)[:MAX_HOSTS]

    def scan_ports(self, hosts: list[str], ctx: ScanContext) -> list[dict[str, Any]]:
        if not hosts or _resolve_tool("naabu") is None:
            return []
        try:
            return self._naabu(hosts, ctx)
        except ToolNotFound as exc:
            log.warning("naabu not found: %s", exc)
        except Exception as exc:  # noqa: BLE001 — best-effort stage
            log.warning("naabu failed: %s", exc)
        return []

    def probe_http(
        self,
        hosts: list[str],
        ports: list[dict[str, Any]],
        ctx: ScanContext,
    ) -> list[dict[str, Any]]:
        if not hosts or _resolve_tool("httpx") is None:
            return []
        try:
            return self._httpx(hosts, ports, ctx)
        except ToolNotFound as exc:
            log.warning("httpx not found: %s", exc)
        except Exception as exc:  # noqa: BLE001 — best-effort stage
            log.warning("httpx failed: %s", exc)
        return []

    # -- subfinder -------------------------------------------------------

    def _subfinder(self, host: str, ctx: ScanContext) -> list[str]:
        binary = _resolve_tool("subfinder")
        if binary is None:
            return []
        argv = [binary, "-d", host, "-json", "-silent"]
        result = run_tool(argv, timeout=ctx.timeout)
        if not result.ok:
            log.warning(
                "subfinder returncode=%s stderr=%r",
                result.returncode,
                result.stderr[:300],
            )
            return []
        return parse_subfinder(result.stdout)

    # -- naabu -----------------------------------------------------------

    def _naabu(self, hosts: list[str], ctx: ScanContext) -> list[dict[str, Any]]:
        path = _write_hosts(hosts)
        try:
            argv = [
                _resolve_tool("naabu") or "naabu",
                "-list",
                path,
                "-json",
                "-silent",
                "-rate",
                str(max(1, min(ctx.max_rps, 500))),
            ]
            result = run_tool(argv, timeout=ctx.timeout)
            if not result.ok:
                log.warning(
                    "naabu returncode=%s stderr=%r",
                    result.returncode,
                    result.stderr[:300],
                )
                return []
            return parse_naabu(result.stdout)
        finally:
            _unlink(path)

    # -- httpx -----------------------------------------------------------

    def _httpx(
        self,
        hosts: list[str],
        ports: list[dict[str, Any]],
        ctx: ScanContext,
    ) -> list[dict[str, Any]]:
        path = _write_hosts(hosts)
        try:
            argv = [_resolve_tool("httpx") or "httpx", "-list", path, "-json", "-silent"]
            port_list = _ports_arg(ports)
            if port_list:
                argv += ["-ports", port_list]
            result = run_tool(argv, timeout=ctx.timeout)
            if not result.ok:
                log.warning(
                    "httpx returncode=%s stderr=%r",
                    result.returncode,
                    result.stderr[:300],
                )
                return []
            return parse_httpx(result.stdout)
        finally:
            _unlink(path)

    # -- findings --------------------------------------------------------

    def port_findings(
        self,
        ports: list[dict[str, Any]],
        target: str,
    ) -> list[FindingContract]:
        findings: list[FindingContract] = []
        for item in ports:
            ip = str(item.get("host") or item.get("ip") or "").strip()
            port = int(item.get("port") or 0)
            if not ip or not port:
                continue
            protocol = str(item.get("protocol") or "tcp").strip().lower() or "tcp"
            service, severity = _PORT_RISK.get(port, ("unknown", Severity.low))
            if item.get("tls") and port in {80, 8080}:
                service, severity = f"{service} (TLS)", Severity.low

            findings.append(
                FindingContract(
                    category=self.category,
                    title=f"{service} exposed on {ip}:{port}/{protocol}",
                    severity=severity,
                    location=f"{ip}:{port}".lower(),
                    evidence={
                        "host": ip,
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "tls": bool(item.get("tls")),
                        "source": "naabu",
                    },
                    source_tools=[self.name],
                    dedup_key=dedup_key(self.name, target, ip.lower(), str(port), protocol),
                    remediation=_port_remediation(port, service),
                )
            )
        return findings

    def alive_findings(
        self,
        alive: list[dict[str, Any]],
        target: str,
    ) -> list[FindingContract]:
        findings: list[FindingContract] = []
        for item in alive:
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            status = int(item.get("status_code") or 0)
            title = f"HTTP service responded on {url} ({status})"
            findings.append(
                FindingContract(
                    category=self.category,
                    title=title,
                    severity=Severity.low,
                    location=url,
                    evidence={
                        "url": url,
                        "status_code": status,
                        "title": item.get("title") or "",
                        "webserver": item.get("webserver") or "",
                        "tech": item.get("tech") or [],
                        "source": "httpx",
                    },
                    source_tools=[self.name],
                    dedup_key=dedup_key(self.name, target, url.lower()),
                    remediation=_remediation("alive"),
                )
            )
        return findings


# -- parsers (pure, tested separately) ----------------------------------


def parse_subfinder(stdout: str) -> list[str]:
    """subfinder `-json` output is JSONL: `{"host": "a.example.com", ...}`."""
    hosts: list[str] = []
    for obj in _iter_json(stdout):
        host = obj.get("host") or obj.get("subdomain") or obj.get("input")
        if isinstance(host, str) and host.strip():
            hosts.append(host.strip().lower())
    return hosts


def parse_naabu(stdout: str) -> list[dict[str, Any]]:
    """naabu `-json` output is JSONL: `{"ip": ..., "port": 443, "protocol": "tcp"}`."""
    ports: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for obj in _iter_json(stdout):
        host = obj.get("host") or obj.get("ip") or ""
        try:
            port = int(obj.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not host or not port:
            continue
        protocol = str(obj.get("protocol") or "tcp").strip().lower() or "tcp"
        key = (str(host).lower(), port, protocol)
        if key in seen:
            continue
        seen.add(key)
        ports.append(
            {
                "host": str(host).lower(),
                "ip": str(obj.get("ip") or ""),
                "port": port,
                "protocol": protocol,
                "tls": bool(obj.get("tls")),
            }
        )
    return ports


def parse_httpx(stdout: str) -> list[dict[str, Any]]:
    """httpx `-json` output is JSONL: `{"url": ..., "status_code": 200, ...}`."""
    alive: list[dict[str, Any]] = []
    seen: set[str] = set()
    for obj in _iter_json(stdout):
        if obj.get("failed") is True:
            continue
        url = obj.get("url") or obj.get("final_url") or ""
        if not isinstance(url, str) or not url.strip():
            continue
        url = url.strip()
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            status = int(obj.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        alive.append(
            {
                "url": url,
                "status_code": status,
                "title": obj.get("title") or "",
                "webserver": obj.get("webserver") or "",
                "tech": [str(t) for t in (obj.get("tech") or []) if isinstance(t, str)],
            }
        )
    return alive


# -- helpers -------------------------------------------------------------


def _resolve_tool(name: str) -> str | None:
    """Locates a ProjectDiscovery tool, bypassing the venv shadow.

    Order: `SINS_<TOOL>_BIN` -> PATH -> fallback directories. A binary counts
    as genuine only when its `-version` output contains "projectdiscovery".
    """
    override = os.environ.get(_TOOL_ENV[name], "").strip()
    if override:
        return override

    found = which(name)
    candidates: list[str] = [found] if found else []
    for directory in _FALLBACK_BIN_DIRS:
        candidate = os.path.join(os.path.expanduser(directory), name)
        if os.path.isfile(candidate) and candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        if _is_projectdiscovery(candidate):
            return candidate
    return found


def _is_projectdiscovery(path: str) -> bool:
    try:
        proc = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    output = f"{proc.stdout}\n{proc.stderr}".lower()
    return proc.returncode == 0 and "projectdiscovery" in output


def _iter_json(stdout: str):
    """JSONL or a JSON array — iterates over objects in both cases."""
    text = stdout.strip()
    if not text:
        return
    if text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            log.warning("failed to parse JSON array")
            return
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item
        return

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


def _clean_hosts(hosts: list[str]) -> list[str]:
    """Removes duplicates and keeps names safe for argv/files."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in hosts:
        host = str(raw).strip().lower().rstrip(".")
        if not host or host.startswith("-") or host in seen:
            continue
        if not _HOST_RE.match(host):
            continue
        seen.add(host)
        out.append(host)
    return out


def _write_hosts(hosts: list[str]) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".txt",
        prefix="sins-pride-",
        delete=False,
        encoding="utf-8",
    ) as handle:
        handle.write("\n".join(hosts) + "\n")
        return handle.name


def _unlink(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


def _ports_arg(ports: list[dict[str, Any]]) -> str:
    unique: list[int] = []
    for item in ports:
        port = int(item.get("port") or 0)
        if port and port not in unique:
            unique.append(port)
        if len(unique) >= MAX_PORTS:
            break
    return ",".join(str(p) for p in unique)


def _dedupe(findings: list[FindingContract]) -> list[FindingContract]:
    seen: set[str] = set()
    out: list[FindingContract] = []
    for finding in findings:
        if finding.dedup_key in seen:
            continue
        seen.add(finding.dedup_key)
        out.append(finding)
    return out


def _port_remediation(port: int, service: str) -> Remediation:
    if port in {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211}:
        return Remediation(
            summary=(
                f"{service} port is exposed to the external network — the database "
                "is directly reachable for attack."
            ),
            steps=[
                "Restrict the port to internal network/VPN addresses (firewall).",
                "Configure the database with authentication and TLS.",
                "If it must stay open, use a strong password and an IP allowlist.",
            ],
            references=["https://owasp.org/www-project-top-ten/"],
        )
    if port == 3389:
        return Remediation(
            summary=(
                "RDP is exposed to the external network - a prime target for brute-force "
                "and ransomware."
            ),
            steps=[
                "Restrict RDP through a VPN or bastion host.",
                "Enable NLA and add MFA.",
                "Close direct internet access.",
            ],
        )
    if port == 23:
        return Remediation(
            summary="Telnet is an unencrypted protocol — login credentials travel in plain text.",
            steps=[
                "Disable Telnet and switch to SSH.",
                "Allow device console access only from the internal network.",
            ],
        )
    return Remediation(
        summary=f"{service} service is exposed on port {port} to the external network.",
        steps=[
            "Verify the port is actually needed; close it if not.",
            "If needed, restrict source IPs with a firewall.",
            "Upgrade the service to the latest version.",
        ],
    )


def _remediation(code: str) -> Remediation:
    if code == "alive":
        return Remediation(
            summary="An HTTP service is responding from the external network.",
            steps=[
                "Confirm this service is meant to be public.",
                "If not, close the port or add authentication.",
                "Upgrade the service version and configure security headers.",
            ],
        )
    raise ValueError(f"unknown remediation code: {code}")


__all__ = ["PrideAdapter", "parse_httpx", "parse_naabu", "parse_subfinder"]
