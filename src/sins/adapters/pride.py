"""Sin 1 — Pride: hujum yuzasini xaritalash (subfinder + naabu + httpx).

Bosqichlar (har biri alohida subprocess, shell=False):
  1. subfinder -d <domain> -json -silent   → subdomenlar (faqat domen uchun)
  2. naabu -list hosts.txt -json -silent   → ochiq TCP portlar
  3. httpx -l hosts.txt -ports ... -json   → jonli HTTP(S) xizmatlar

Nega shunday:
  - Uchta tool uchta aniq ishni qiladi; biz ularni faqat bog'laymiz.
  - Har bosqich best-effort: tool yo'q yoki yiqilsa, qolgan bosqichlar
    ishlashda davom etadi. Bitta nosozlik butun skanni to'xtatmaydi.
  - Naabu chiqishi har bir port uchun alohida JSON satr (JSONL), massiv emas.
  - Httpx'ga portlar `-ports` bilan beriladi — aks holda 8099 kabi
    nostandart portlar umuman tekshirilmaydi.

applies_to: domen | URL | IP. Lokal papka (osv-scanner) uchun mos emas.
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

# Bitta skanda tekshiriladigan maksimal host soni (subdomen portlashi).
MAX_HOSTS = 200
# httpx'ga beriladigan maksimal port soni.
MAX_PORTS = 64

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")

# PATH'dagi birinchi `httpx` ProjectDiscovery'niki bo'lmasligi mumkin: Python
# `httpx` paketi venv ichiga o'z CLI'sini qo'yadi va loyihaniki soyada qoladi.
# Shu sababli tool'lar aniq tekshiriladi va zaxira papkalar ko'riladi.
_TOOL_ENV = {
    "subfinder": "SINS_SUBFINDER_BIN",
    "naabu": "SINS_NAABU_BIN",
    "httpx": "SINS_HTTPX_BIN",
}
_FALLBACK_BIN_DIRS = ("~/go/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/.local/bin")

# Port -> (xizmat nomi, severity). Ro'yxatda yo'q port — low.
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
        # Kamida bitta tool bo'lsa adapter ishlaydi — bosqichlar best-effort.
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
            log.warning("pride: nishondan host ajratib bo'lmadi: %r", ctx.target)
            return []

        hosts = self.enumerate_hosts(host, kind, ctx)
        ports = self.scan_ports(hosts, ctx)
        alive = self.probe_http(hosts, ports, ctx)

        findings = self.port_findings(ports, ctx.target)
        findings += self.alive_findings(alive, ctx.target)
        return _dedupe(findings)

    def enumerate_hosts(self, host: str, kind: str, ctx: ScanContext) -> list[str]:
        """Domen bo'lsa subfinder bilan kengaytiradi, aks holda faqat host."""
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
            log.warning("naabu topilmadi: %s", exc)
        except Exception as exc:  # noqa: BLE001 — best-effort bosqich
            log.warning("naabu nosoz: %s", exc)
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
            log.warning("httpx topilmadi: %s", exc)
        except Exception as exc:  # noqa: BLE001 — best-effort bosqich
            log.warning("httpx nosoz: %s", exc)
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


# -- parsers (pure, alohida testlanadi) ----------------------------------


def parse_subfinder(stdout: str) -> list[str]:
    """subfinder `-json` chiqishi JSONL: `{"host": "a.example.com", ...}`."""
    hosts: list[str] = []
    for obj in _iter_json(stdout):
        host = obj.get("host") or obj.get("subdomain") or obj.get("input")
        if isinstance(host, str) and host.strip():
            hosts.append(host.strip().lower())
    return hosts


def parse_naabu(stdout: str) -> list[dict[str, Any]]:
    """naabu `-json` chiqishi JSONL: `{"ip": ..., "port": 443, "protocol": "tcp"}`."""
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
    """httpx `-json` chiqishi JSONL: `{"url": ..., "status_code": 200, ...}`."""
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
    """ProjectDiscovery tool'ini topadi; venv soyasini chetlab o'tadi.

    Tartib: `SINS_<TOOL>_BIN` -> PATH -> zaxira papkalar. Faqat `-version`
    chiqishida "projectdiscovery" bo'lgan binary haqiqiy deb hisoblanadi.
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
    """JSONL yoki JSON massiv — ikkalasini ham obyektlar bo'ylab yuradi."""
    text = stdout.strip()
    if not text:
        return
    if text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            log.warning("JSON massiv parse qilinmadi")
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
    """Dublikatlarni olib tashlaydi va argv/fayl uchun xavfsiz nomlarni qoldiradi."""
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
                f"{service} porti tashqi tarmoqqa ochiq — ma'lumotlar bazasi "
                "to'g'ridan-to'g'ri hujumga ochiq."
            ),
            steps=[
                "Portni faqat ichki tarmoq/VPN manzillariga cheklang (firewall).",
                "Bazani autentifikatsiya va TLS bilan sozlang.",
                "Ochiq qolishi shart bo'lsa, kuchli parol va IP allowlist qo'llang.",
            ],
            references=["https://owasp.org/www-project-top-ten/"],
        )
    if port == 3389:
        return Remediation(
            summary="RDP tashqi tarmoqqa ochiq — brute-force va ransomware uchun asosiy nishon.",
            steps=[
                "RDP'ni VPN yoki bastion host orqali cheklang.",
                "NLA yoqing va MFA qo'shing.",
                "Internetdan to'g'ridan-to'g'ri kirishni yoping.",
            ],
        )
    if port == 23:
        return Remediation(
            summary="Telnet shifrlanmagan protokol — login ma'lumotlari ochiq matnda ketadi.",
            steps=[
                "Telnet'ni o'chiring va SSH'ga o'ting.",
                "Qurilma konsoliga faqat ichki tarmoqdan ruxsat bering.",
            ],
        )
    return Remediation(
        summary=f"{service} xizmati {port}-portda tashqi tarmoqqa ochiq.",
        steps=[
            "Port haqiqatan kerakligini tekshiring; kerak bo'lmasa yoping.",
            "Kerak bo'lsa, manba IP'larni firewall bilan cheklang.",
            "Xizmatni eng so'nggi versiyaga yangilang.",
        ],
    )


def _remediation(code: str) -> Remediation:
    if code == "alive":
        return Remediation(
            summary="HTTP xizmati tashqi tarmoqdan javob bermoqda.",
            steps=[
                "Bu xizmat ommaviy bo'lishi shartligini tasdiqlang.",
                "Kerak bo'lmasa, portni yoping yoki autentifikatsiya qo'shing.",
                "Xizmat versiyasini yangilab, xavfsizlik sarlavhalarini sozlang.",
            ],
        )
    raise ValueError(f"noma'lum remediation kodi: {code}")


__all__ = ["PrideAdapter", "parse_httpx", "parse_naabu", "parse_subfinder"]
