"""Seed a demo tenant with five finished scans, findings and a real drift story.

Why this exists: on demo day a live scan can fail for reasons that have nothing
to do with the product (no network, a missing engine binary, a target that went
down). A judge must still see a populated History, a findings table, a diff with
new/resolved/regressed rows and five downloadable PDFs.

Everything here is written through the same tables the API reads, so the seeded
data is indistinguishable from a real run: the endpoints do not have a "demo"
branch.

Usage (inside the compose network or against a local Postgres):

    uv run python scripts/seed_demo.py                     # tenant "Demo Bank"
    uv run python scripts/seed_demo.py --api-key sins_demo_key_for_stage
    uv run python scripts/seed_demo.py --reset             # wipe demo scans first
    uv run python scripts/seed_demo.py --json              # machine-readable ids
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from rich.console import Console
from rich.table import Table
from sqlalchemy import delete, func, select

from sins.db import get_engine, get_sessionmaker
from sins.dedup import dedup_key as make_dedup_key
from sins.drift import fingerprint
from sins.models import Finding, FindingState, Scan, ScanStatus, Target, Tenant
from sins.schemas import Category, FindingContract, Remediation, Severity
from sins.security import display_prefix, hash_api_key
from sins.services import scan_service

console = Console()

DEFAULT_TENANT = "Demo Bank"
DEFAULT_TARGET = "https://demo-app.local"
DEFAULT_API_KEY = "sins_demo_stage_key_do_not_use_in_production"

# The demo target is a lab address (`.local`), so the ownership gate passes
# without a DNS record and the report generator skips public intel entirely.
SCAN_DAYS_AGO = (28, 21, 14, 7, 0)


@dataclass(frozen=True)
class DemoFinding:
    key: str
    title: str
    severity: Severity
    category: Category
    location: str
    tools: tuple[str, ...]
    cve: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    cvss: float | None = None
    remediation: tuple[str, list[str]] | None = None


CATALOGUE: dict[str, DemoFinding] = {
    "sqli": DemoFinding(
        key="sqli",
        title="SQL injection in product search",
        severity=Severity.critical,
        category=Category.vuln,
        location="https://demo-app.local/search",
        tools=("nuclei",),
        cwe=("CWE-89",),
        cvss=9.8,
        remediation=(
            "Use parameterised queries for the `q` parameter.",
            ["Replace string concatenation with bound parameters", "Add a regression test"],
        ),
    ),
    "log4shell": DemoFinding(
        key="log4shell",
        title="Apache Log4j2 remote code execution (Log4Shell)",
        severity=Severity.critical,
        category=Category.vuln,
        location="https://demo-app.local/api/login",
        tools=("nuclei", "osv"),
        cve=("CVE-2021-44228",),
        cwe=("CWE-502",),
        cvss=10.0,
        remediation=(
            "Upgrade log4j-core to 2.17.1 or later.",
            ["Bump log4j-core to 2.17.1", "Redeploy the API", "Re-scan to confirm"],
        ),
    ),
    "tls10": DemoFinding(
        key="tls10",
        title="TLS 1.0 still enabled on the public endpoint",
        severity=Severity.high,
        category=Category.tls,
        location="demo-app.local:443",
        tools=("sslyze",),
        cwe=("CWE-326",),
        remediation=(
            "Disable TLS 1.0 and 1.1; keep 1.2 and 1.3 only.",
            ["Update the load-balancer policy", "Re-run the TLS scan"],
        ),
    ),
    "lodash": DemoFinding(
        key="lodash",
        title="Prototype pollution in lodash",
        severity=Severity.high,
        category=Category.dependency,
        location="package.json:lodash@4.17.15",
        tools=("osv",),
        cve=("CVE-2020-8203",),
        cvss=7.4,
        remediation=(
            "Upgrade lodash to 4.17.21.",
            ["Update the lockfile", "Run the unit tests", "Rebuild the bundle"],
        ),
    ),
    "citrix": DemoFinding(
        key="citrix",
        title="Citrix Bleed session token disclosure",
        severity=Severity.high,
        category=Category.vuln,
        location="https://demo-app.local/vpn",
        tools=("nuclei",),
        cve=("CVE-2023-4966",),
        cwe=("CWE-200",),
        cvss=9.4,
    ),
    "csp": DemoFinding(
        key="csp",
        title="Content-Security-Policy header missing",
        severity=Severity.medium,
        category=Category.misconfig,
        location="https://demo-app.local",
        tools=("nuclei",),
        cwe=("CWE-693",),
        remediation=(
            "Send a restrictive Content-Security-Policy header.",
            ["Start in report-only mode", "Then enforce default-src 'self'"],
        ),
    ),
    "banner": DemoFinding(
        key="banner",
        title="Server version disclosure",
        severity=Severity.low,
        category=Category.misconfig,
        location="https://demo-app.local",
        tools=("nuclei",),
        cwe=("CWE-200",),
    ),
    "env": DemoFinding(
        key="env",
        title="Publicly exposed .env file with database credentials",
        severity=Severity.critical,
        category=Category.exposure,
        location="https://demo-app.local/.env",
        tools=("nuclei",),
        cwe=("CWE-538",),
        cvss=9.1,
        remediation=(
            "Remove `.env` from the web root and rotate every leaked credential.",
            [
                "Block dotfiles at the reverse proxy",
                "Rotate the database password",
                "Purge the file from the CDN cache",
            ],
        ),
    ),
}

# Which findings each scan reported. The gaps are deliberate: they produce
# new / resolved / regressed rows in `GET /scans/{id}/diff`. The *latest* scan
# also differs from the previous one, so the demo never lands on an empty diff.
SCHEDULE: tuple[tuple[str, ...], ...] = (
    ("sqli", "tls10", "lodash", "csp", "banner"),  # 28 days ago
    ("sqli", "log4shell", "tls10", "lodash", "csp", "banner"),  # 21 — Log4Shell appears
    ("sqli", "log4shell", "lodash", "banner"),  # 14 — TLS and CSP fixed
    ("sqli", "log4shell", "tls10", "citrix", "banner"),  # 7 — TLS regressed, lodash fixed
    ("sqli", "log4shell", "tls10", "banner", "env"),  # today — Citrix fixed, .env leaked
)

ENGINES = ("nuclei", "osv", "pride", "envy")
SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class Seeded:
    tenant_name: str
    api_key: str
    target_id: str
    scans: list[dict[str, Any]] = field(default_factory=list)
    states: dict[str, dict[str, Any]] = field(default_factory=dict)


def _contract(spec: DemoFinding) -> FindingContract:
    remediation = None
    if spec.remediation is not None:
        summary, steps = spec.remediation
        remediation = Remediation(summary=summary, steps=list(steps))
    return FindingContract(
        category=spec.category,
        title=spec.title,
        severity=spec.severity,
        cvss=spec.cvss,
        cve=list(spec.cve),
        cwe=list(spec.cwe),
        location=spec.location,
        evidence={"seeded": True, "engine": spec.tools[0]},
        source_tools=list(spec.tools),
        dedup_key=make_dedup_key(spec.category.value, spec.title, spec.location),
        remediation=remediation,
    )


async def _get_or_create_tenant(session, name: str, api_key: str | None) -> tuple[Tenant, str]:
    tenant = await session.scalar(select(Tenant).where(Tenant.name == name))
    raw = api_key or DEFAULT_API_KEY

    if tenant is None:
        tenant = Tenant(
            name=name.strip(),
            api_key_hash=hash_api_key(raw),
            api_key_prefix=display_prefix(raw),
        )
        session.add(tenant)
        await session.commit()
        await session.refresh(tenant)
        return tenant, raw

    if api_key is not None:
        # A fixed key keeps the stage config stable across re-seeds.
        tenant.api_key_hash = hash_api_key(raw)
        tenant.api_key_prefix = display_prefix(raw)
        await session.commit()
    return tenant, raw


async def _wipe(session, tenant: Tenant, target: Target) -> int:
    removed = await session.scalar(
        select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant.id)
    )
    await session.execute(delete(FindingState).where(FindingState.tenant_id == tenant.id))
    await session.execute(delete(Finding).where(Finding.tenant_id == tenant.id))
    await session.execute(delete(Scan).where(Scan.tenant_id == tenant.id))
    await session.commit()
    return int(removed or 0)


def _engine_stats(present: int) -> list[dict[str, Any]]:
    return [
        {
            "name": "nuclei",
            "sin": "Greed",
            "ok": True,
            "findings": max(present - 1, 0),
            "duration_ms": 41_000,
            "error": None,
            "skipped": False,
            "skip_reason": None,
        },
        {
            "name": "osv",
            "sin": "Sloth",
            "ok": True,
            "findings": 1,
            "duration_ms": 2_400,
            "error": None,
            "skipped": False,
            "skip_reason": None,
        },
        {
            "name": "pride",
            "sin": "Pride",
            "ok": True,
            "findings": 3,
            "duration_ms": 18_300,
            "error": None,
            "skipped": False,
            "skip_reason": None,
        },
        {
            "name": "envy",
            "sin": "Envy",
            "ok": True,
            "findings": 1,
            "duration_ms": 6_100,
            "error": None,
            "skipped": False,
            "skip_reason": None,
        },
    ]


async def _insert_scan(
    session,
    tenant: Tenant,
    target: Target,
    keys: tuple[str, ...],
    finished_at: datetime,
    ordinal: int,
) -> Scan:
    started_at = finished_at - timedelta(minutes=3)
    scan = Scan(
        tenant_id=tenant.id,
        target_id=target.id,
        status=ScanStatus.done,
        engines=list(ENGINES),
        severities=list(SEVERITIES),
        progress=100,
        current_engine=None,
        error=None,
        engine_stats=_engine_stats(len(keys)),
        created_at=started_at,
        started_at=started_at,
        finished_at=finished_at,
    )
    session.add(scan)
    await session.flush()

    for key in keys:
        spec = CATALOGUE[key]
        contract = _contract(spec)
        session.add(
            Finding(
                scan_id=scan.id,
                tenant_id=tenant.id,
                category=contract.category,
                severity=contract.severity,
                title=contract.title,
                cvss=contract.cvss,
                cve=contract.cve,
                cwe=contract.cwe,
                location=contract.location,
                evidence=contract.evidence,
                source_tools=contract.source_tools,
                remediation=(
                    contract.remediation.model_dump(mode="json") if contract.remediation else None
                ),
                dedup_key=contract.dedup_key,
                created_at=finished_at,
            )
        )

    console.log(f"scan #{ordinal}: {len(keys)} findings, finished {finished_at.date()}")
    return scan


async def _rebuild_states(
    session, tenant: Tenant, target: Target, history: list[tuple[datetime, set[str]]]
) -> dict[str, dict[str, Any]]:
    """Recompute the exposure lifecycle from the scan history.

    Production writes these rows incrementally during each scan; seeding five
    scans at once means the same logic runs once over the finished timeline.
    """
    out: dict[str, dict[str, Any]] = {}

    for key, spec in CATALOGUE.items():
        seen = [when for when, keys in history if key in keys]
        if not seen:
            continue

        first_seen, last_seen = seen[0], seen[-1]
        last_scan = history[-1][1]
        still_open = key in last_scan

        resolved_at = None
        if not still_open:
            for when, keys in history:
                if when > last_seen and key not in keys:
                    resolved_at = when
                    break
            resolved_at = resolved_at or last_seen + timedelta(days=1)

        # A regression is a resolved -> open transition. Recompute by walking
        # the presence pattern instead of trusting a counter.
        regressions = 0
        was_present = False
        seen_gap = False
        for _, keys in history:
            present = key in keys
            if present and was_present is False and seen_gap:
                regressions += 1
            if not present and was_present:
                seen_gap = True
            was_present = present

        latest_scan = await session.scalar(
            select(Scan)
            .join(Finding, Finding.scan_id == Scan.id)
            .where(
                Finding.tenant_id == tenant.id,
                Finding.dedup_key == make_dedup_key(spec.category.value, spec.title, spec.location),
            )
            .order_by(Scan.finished_at.desc())
            .limit(1)
        )
        if latest_scan is None:  # pragma: no cover - defensive
            continue

        state = FindingState(
            tenant_id=tenant.id,
            target_id=target.id,
            fingerprint=fingerprint(
                target=target.value,
                category=spec.category.value,
                title=spec.title,
                location=spec.location,
                cve=list(spec.cve),
            ),
            category=spec.category.value,
            severity=spec.severity.value,
            title=spec.title,
            location=spec.location,
            status="open" if still_open else "resolved",
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            resolved_at=resolved_at,
            occurrences=len(seen),
            regressions=regressions,
            scan_id=latest_scan.id,
        )
        session.add(state)
        out[key] = {
            "status": state.status,
            "first_seen": first_seen.date().isoformat(),
            "last_seen": last_seen.date().isoformat(),
            "occurrences": state.occurrences,
            "regressions": state.regressions,
        }

    await session.commit()
    return out


async def seed(*, tenant_name: str, target_value: str, api_key: str | None, reset: bool) -> Seeded:
    async with get_sessionmaker()() as session:
        tenant, raw_key = await _get_or_create_tenant(session, tenant_name, api_key)
        target = await scan_service.create_target(session, tenant, target_value)

        existing = await session.scalar(
            select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant.id)
        )
        if existing and not reset:
            raise SystemExit(
                f"Tenant '{tenant.name}' already has {existing} scans. "
                "Re-run with --reset to replace them."
            )
        if existing:
            console.log(f"removed {await _wipe(session, tenant, target)} previous scans")

        now = datetime.now(UTC).replace(microsecond=0)
        history: list[tuple[datetime, set[str]]] = []
        scans: list[dict[str, Any]] = []

        for ordinal, days in enumerate(SCAN_DAYS_AGO, start=1):
            keys = SCHEDULE[ordinal - 1]
            finished_at = now - timedelta(days=days)
            scan = await _insert_scan(session, tenant, target, keys, finished_at, ordinal)
            history.append((finished_at, set(keys)))
            scans.append(
                {
                    "id": str(scan.id),
                    "finished_at": finished_at.isoformat(),
                    "findings": len(keys),
                }
            )

        await session.commit()
        states = await _rebuild_states(session, tenant, target, history)

        return Seeded(
            tenant_name=tenant.name,
            api_key=raw_key,
            target_id=str(target.id),
            scans=scans,
            states=states,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed demo scans for 7 Deadly Sins")
    parser.add_argument("--tenant", default=DEFAULT_TENANT, help="tenant name")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="lab target value")
    parser.add_argument(
        "--api-key",
        default=None,
        help="fix the API key (default: a stable demo key; existing tenants are rotated)",
    )
    parser.add_argument("--reset", action="store_true", help="delete existing demo scans first")
    parser.add_argument("--json", action="store_true", help="print a machine-readable summary")
    args = parser.parse_args()

    async def _run() -> Seeded:
        try:
            return await seed(
                tenant_name=args.tenant,
                target_value=args.target,
                api_key=args.api_key,
                reset=args.reset,
            )
        finally:
            await get_engine().dispose()

    result = asyncio.run(_run())

    if args.json:
        print(
            json.dumps(
                {
                    "tenant": result.tenant_name,
                    "api_key": result.api_key,
                    "target_id": result.target_id,
                    "scans": result.scans,
                    "states": result.states,
                },
                indent=2,
            )
        )
        return 0

    console.print(f"\n[bold]Tenant[/bold] {result.tenant_name}")
    console.print(f"[bold]API key[/bold] {result.api_key}")
    console.print(f"[bold]Target[/bold] {result.target_id}\n")

    table = Table(title="Seeded scans")
    table.add_column("#", justify="right")
    table.add_column("Scan id")
    table.add_column("Finished")
    table.add_column("Findings", justify="right")
    for index, scan in enumerate(result.scans, start=1):
        table.add_row(
            str(index),
            scan["id"][:8],
            scan["finished_at"][:10],
            str(scan["findings"]),
        )
    console.print(table)

    states = Table(title="Exposure states")
    states.add_column("Finding")
    states.add_column("Status")
    states.add_column("First seen")
    states.add_column("Last seen")
    states.add_column("Seen", justify="right")
    states.add_column("Regressions", justify="right")
    for key, state in result.states.items():
        states.add_row(
            key,
            state["status"],
            state["first_seen"],
            state["last_seen"],
            str(state["occurrences"]),
            str(state["regressions"]),
        )
    console.print(states)

    console.print("\nNext:")
    console.print(f"  curl -s localhost:8000/scans -H 'X-API-Key: {result.api_key}' | head -c 400")
    console.print("  open http://localhost:5173/ and point the demo section at the API above")
    return 0


if __name__ == "__main__":
    sys.exit(main())
