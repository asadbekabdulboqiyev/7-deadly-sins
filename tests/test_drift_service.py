"""Exposure timeline service tests - state upsert and timeline reads."""

from __future__ import annotations

from typing import Any

from sins.models import Finding, ScanStatus, utcnow
from sins.schemas import Category, FindingContract, Severity
from sins.services import drift_service, scan_service


async def _target(session, owner, value: str = "http://localhost:8099"):
    return await scan_service.create_target(session, owner, value)


async def _scan(session, owner, target, *, status: str | None = None) -> Any:
    scan = await scan_service.create_scan(session, owner, target.id)
    if status is not None:
        scan.status = status
    await session.commit()
    return scan


async def _done_scan(session, owner, target) -> Any:
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    scan.finished_at = utcnow()
    await session.commit()
    return scan


async def _finding(session, owner, scan, dedup_key: str) -> Finding:
    row = Finding(
        tenant_id=owner.id,
        scan_id=scan.id,
        category=Category.vuln,
        severity=Severity.high,
        title="Log4j RCE",
        location="https://example.com:443/api",
        dedup_key=dedup_key,
        source_tools=["nuclei"],
        cve=[],
        cwe=[],
        evidence={},
    )
    session.add(row)
    await session.commit()
    return row


async def test_upsert_creates_open_states(session, tenant) -> None:
    owner, _tenant_obj = tenant
    target = await _target(session, owner)
    scan = await _done_scan(session, owner, target)

    contracts = [
        FindingContract(
            category=Category.vuln,
            title="Log4j RCE",
            severity=Severity.critical,
            cvss=10.0,
            cve=["CVE-2021-44228"],
            location="https://example.com:443/api",
            dedup_key="nuclei|abc|Log4j RCE",
            source_tools=["nuclei"],
        ),
        FindingContract(
            category=Category.auth,
            title="Basic auth over HTTP",
            severity=Severity.high,
            location="https://example.com:8080",
            dedup_key="lust|abc|Basic auth over HTTP",
            source_tools=["httpx"],
        ),
    ]
    states = await drift_service.upsert_finding_states(session, scan, contracts)

    assert len(states) == 2
    assert all(state.status == "open" for state in states)
    assert all(state.resolved_at is None for state in states)

    fetched = await drift_service.list_finding_states(session, owner, target.id)
    assert len(fetched) == 2


async def test_upsert_increments_occurrences_and_counts_regressions(session, tenant) -> None:
    owner, _tenant_obj = tenant
    target = await _target(session, owner)
    scan = await _done_scan(session, owner, target)

    contracts = [
        FindingContract(
            category=Category.vuln,
            title="Log4j RCE",
            severity=Severity.critical,
            location="https://example.com:443/api",
            dedup_key="nuclei|abc|Log4j RCE",
            source_tools=["nuclei"],
        ),
    ]
    await drift_service.upsert_finding_states(session, scan, contracts)

    state = (await drift_service.list_finding_states(session, owner, target.id))[0]
    state.occurrences = 1
    state.status = "resolved"
    state.resolved_at = utcnow()
    await session.commit()

    second = await _done_scan(session, owner, target)
    await drift_service.upsert_finding_states(session, second, contracts)

    re_opened = (await drift_service.list_finding_states(session, owner, target.id))[0]
    assert re_opened.status == "open"
    assert re_opened.occurrences == 2
    assert re_opened.regressions == 1
    assert re_opened.resolved_at is None


async def test_exposure_timeline_returns_daily_points(session, tenant) -> None:
    owner, _tenant_obj = tenant
    target = await _target(session, owner)
    scan = await _done_scan(session, owner, target)
    await _finding(session, owner, scan, "k1")

    timeline = await drift_service.exposure_timeline(session, owner, target.id, days=2)

    assert timeline["target_id"] == str(target.id)
    assert timeline["days"] == 2
    assert len(timeline["points"]) == 3
    assert set(timeline["points"][0].keys()) >= {"day", "open", "resolved", "regressed", "score"}
    assert timeline["score_now"] >= 0
    assert timeline["open_now"] >= 0
