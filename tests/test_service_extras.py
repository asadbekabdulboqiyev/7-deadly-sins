"""Xizmat qatlami: idempotentlik, bekor qilish, diff, rotatsiya, tozalash, sahifalash."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from sins.db import get_sessionmaker
from sins.models import Finding, Scan, ScanStatus, utcnow
from sins.schemas import Category, Severity
from sins.services import scan_service

DONE_TARGET = "http://localhost:8099"


async def _target(session, owner, value: str = DONE_TARGET):
    return await scan_service.create_target(session, owner, value)


async def _scan(session, owner, target, *, status: str | None = None, key: str | None = None):
    scan = await scan_service.create_scan(session, owner, target.id, idempotency_key=key)
    if status is not None:
        scan.status = status
    await session.commit()
    return scan


async def _finding(
    session,
    owner,
    scan,
    dedup_key: str,
    *,
    severity: Severity = Severity.high,
    engine: str = "nuclei",
    title: str = "Topilma",
) -> Finding:
    row = Finding(
        tenant_id=owner.id,
        scan_id=scan.id,
        category=Category.vuln,
        severity=severity,
        title=title,
        location="example.com:443",
        dedup_key=dedup_key,
        source_tools=[engine],
        cve=[],
        cwe=[],
        evidence={},
    )
    session.add(row)
    await session.commit()
    return row


# ---------------------------------------------------------------------------
# Idempotentlik
# ---------------------------------------------------------------------------


async def test_same_idempotency_key_returns_existing_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)

    first = await scan_service.create_scan(session, owner, target.id, idempotency_key="req-1")
    second = await scan_service.create_scan(session, owner, target.id, idempotency_key="req-1")

    assert first.id == second.id
    rows = list(await session.scalars(select(Scan).where(Scan.tenant_id == owner.id)))
    assert len(rows) == 1


async def test_idempotency_key_is_persisted_trimmed(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)

    scan = await scan_service.create_scan(
        session, owner, target.id, idempotency_key="  spaced-key  "
    )

    assert scan.idempotency_key == "spaced-key"


async def test_idempotency_key_is_scoped_per_tenant(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    first = await scan_service.create_scan(session, owner, target.id, idempotency_key="shared")

    other, _ = await scan_service.create_tenant(session, "Ikkinchi mijoz")
    other_target = await _target(session, other)
    second = await scan_service.create_scan(
        session, other, other_target.id, idempotency_key="shared"
    )

    assert first.id != second.id


async def test_find_scan_by_idempotency_key_ignores_blank(session, tenant) -> None:
    owner, _ = tenant
    assert await scan_service.find_scan_by_idempotency_key(session, owner, "   ") is None


async def test_find_scan_by_idempotency_key_returns_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await scan_service.create_scan(session, owner, target.id, idempotency_key="lookup-me")

    found = await scan_service.find_scan_by_idempotency_key(session, owner, "lookup-me")
    assert found is not None
    assert found.id == scan.id


# ---------------------------------------------------------------------------
# Bekor qilish
# ---------------------------------------------------------------------------


async def test_cancel_pending_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target)

    cancelled = await scan_service.cancel_scan(session, owner, scan.id)

    assert cancelled.status == ScanStatus.cancelled
    assert cancelled.finished_at is not None
    assert cancelled.current_engine is None


async def test_cancel_running_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.running)

    cancelled = await scan_service.cancel_scan(session, owner, scan.id)
    assert cancelled.status == ScanStatus.cancelled


@pytest.mark.parametrize(
    "status",
    [ScanStatus.done, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.blocked],
)
async def test_finished_scan_cannot_be_cancelled(session, tenant, status) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=status)

    with pytest.raises(scan_service.NotCancellable):
        await scan_service.cancel_scan(session, owner, scan.id)


async def test_cancelled_scan_is_not_executed(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target)
    await scan_service.cancel_scan(session, owner, scan.id)
    scan_id = scan.id

    await scan_service.execute_scan(scan_id)

    async with get_sessionmaker()() as fresh_session:
        fresh = await fresh_session.get(Scan, scan_id)
        assert fresh is not None
        assert fresh.status == ScanStatus.cancelled
        rows = list(await fresh_session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        assert rows == []


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


async def test_diff_without_baseline_returns_all_new(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "k1")
    await _finding(session, owner, scan, "k2")

    diff = await scan_service.diff_scan(session, owner, scan)

    assert diff.has_baseline is False
    assert diff.against_scan_id is None
    assert {row.dedup_key for row in diff.new} == {"k1", "k2"}
    assert diff.resolved == []
    assert diff.persisting == 0


async def test_diff_detects_new_resolved_and_persisting(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)

    base = await _scan(session, owner, target, status=ScanStatus.done)
    base.created_at = utcnow() - timedelta(days=1)
    await session.commit()
    await _finding(session, owner, base, "k1")
    await _finding(session, owner, base, "k2")

    current = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, current, "k2")
    await _finding(session, owner, current, "k3")

    diff = await scan_service.diff_scan(session, owner, current)

    assert diff.against_scan_id == base.id
    assert [row.dedup_key for row in diff.new] == ["k3"]
    assert [row.dedup_key for row in diff.resolved] == ["k1"]
    assert diff.persisting == 1


async def test_diff_uses_explicit_baseline(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)

    first = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, first, "a")
    second = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, second, "b")

    diff = await scan_service.diff_scan(session, owner, second, against_id=first.id)

    assert diff.against_scan_id == first.id
    assert [row.dedup_key for row in diff.new] == ["b"]
    assert [row.dedup_key for row in diff.resolved] == ["a"]


async def test_diff_requires_done_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target)

    with pytest.raises(scan_service.InvalidScanState):
        await scan_service.diff_scan(session, owner, scan)


async def test_diff_rejects_scan_of_another_target(session, tenant) -> None:
    owner, _ = tenant
    target_a = await _target(session, owner, "http://localhost:8099")
    target_b = await _target(session, owner, "http://localhost:8098")
    base = await _scan(session, owner, target_a, status=ScanStatus.done)
    current = await _scan(session, owner, target_b)
    current.status = ScanStatus.done
    await session.commit()

    with pytest.raises(scan_service.InvalidScanState):
        await scan_service.diff_scan(session, owner, current, against_id=base.id)


async def test_diff_rejects_baseline_that_is_not_done(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    base = await _scan(session, owner, target, status=ScanStatus.failed)
    current = await _scan(session, owner, target, status=ScanStatus.done)

    with pytest.raises(scan_service.InvalidScanState):
        await scan_service.diff_scan(session, owner, current, against_id=base.id)


# ---------------------------------------------------------------------------
# Kalit rotatsiyasi
# ---------------------------------------------------------------------------


async def test_rotate_api_key_invalidates_old_key(session, tenant) -> None:
    owner, old_key = tenant

    new_key = await scan_service.rotate_api_key(session, owner)

    assert new_key != old_key
    assert await scan_service.get_tenant_by_key(session, old_key) is None
    found = await scan_service.get_tenant_by_key(session, new_key)
    assert found is not None
    assert found.id == owner.id


# ---------------------------------------------------------------------------
# Tozalash (retention)
# ---------------------------------------------------------------------------


async def _old_scan(session, owner, *, days: int = 60):
    target = await _target(session, owner, f"http://localhost:{8090 + days}")
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    scan.created_at = utcnow() - timedelta(days=days)
    await session.commit()
    return scan


async def _purge_leftovers(session) -> None:
    """Oldingi testlardan qolgan eski skanlarni tozalaydi (prune global ishlaydi)."""
    await scan_service.prune_scans(session, older_than_days=1)


async def test_prune_dry_run_keeps_data(session, tenant) -> None:
    await _purge_leftovers(session)
    owner, _ = tenant
    scan = await _old_scan(session, owner)
    await _finding(session, owner, scan, "old-1")
    scan_id = scan.id

    scans, findings = await scan_service.prune_scans(session, older_than_days=30, dry_run=True)

    assert (scans, findings) == (1, 1)
    session.expire_all()
    assert await session.get(Scan, scan_id) is not None


async def test_prune_deletes_old_scans_and_findings(session, tenant) -> None:
    await _purge_leftovers(session)
    owner, _ = tenant
    scan = await _old_scan(session, owner)
    await _finding(session, owner, scan, "old-1")
    scan_id = scan.id

    scans, findings = await scan_service.prune_scans(session, older_than_days=30)

    assert (scans, findings) == (1, 1)
    session.expire_all()
    assert await session.get(Scan, scan_id) is None
    assert list(await session.scalars(select(Finding).where(Finding.scan_id == scan_id))) == []


async def test_prune_keeps_recent_scans(session, tenant) -> None:
    await _purge_leftovers(session)
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    scan_id = scan.id

    scans, _ = await scan_service.prune_scans(session, older_than_days=30)

    assert scans == 0
    session.expire_all()
    assert await session.get(Scan, scan_id) is not None


@pytest.mark.parametrize("days", [0, -5])
async def test_prune_rejects_invalid_window(session, days: int) -> None:
    with pytest.raises(ValueError):
        await scan_service.prune_scans(session, older_than_days=days)


# ---------------------------------------------------------------------------
# Sahifalash va filtrlar
# ---------------------------------------------------------------------------


async def test_list_scans_pagination(session, tenant) -> None:
    owner, _ = tenant
    for index in range(3):
        target = await _target(session, owner, f"http://localhost:807{index}")
        await _scan(session, owner, target, status=ScanStatus.done)

    first = await scan_service.list_scans(session, owner, limit=2, offset=0)
    second = await scan_service.list_scans(session, owner, limit=2, offset=2)

    assert len(first) == 2
    assert len(second) == 1
    assert {s.id for s in first}.isdisjoint({s.id for s in second})


async def test_list_scans_status_filter(session, tenant) -> None:
    owner, _ = tenant
    target_a = await _target(session, owner, "http://localhost:8061")
    target_b = await _target(session, owner, "http://localhost:8062")
    await _scan(session, owner, target_a, status=ScanStatus.done)
    await _scan(session, owner, target_b, status=ScanStatus.failed)

    done = await scan_service.list_scans(session, owner, status_filter=["done"])
    failed = await scan_service.list_scans(session, owner, status_filter=["failed"])

    assert [s.status for s in done] == ["done"]
    assert [s.status for s in failed] == ["failed"]


async def test_count_scans_and_filter(session, tenant) -> None:
    owner, _ = tenant
    target_a = await _target(session, owner, "http://localhost:8051")
    target_b = await _target(session, owner, "http://localhost:8052")
    await _scan(session, owner, target_a, status=ScanStatus.done)
    await _scan(session, owner, target_b, status=ScanStatus.failed)

    assert await scan_service.count_scans(session, owner) == 2
    assert await scan_service.count_scans(session, owner, status_filter=["done"]) == 1


async def test_list_targets_pagination(session, tenant) -> None:
    owner, _ = tenant
    for index in range(3):
        await _target(session, owner, f"http://localhost:804{index}")

    first = await scan_service.list_targets(session, owner, limit=2)
    second = await scan_service.list_targets(session, owner, limit=2, offset=2)

    assert len(first) == 2
    assert len(second) == 1


async def test_query_findings_filters_by_severity(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "c1", severity=Severity.critical)
    await _finding(session, owner, scan, "l1", severity=Severity.low)

    rows = await scan_service.query_findings(session, scan, severities=["critical"])

    assert [row.dedup_key for row in rows] == ["c1"]


async def test_query_findings_filters_by_engine(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "n1", engine="nuclei")
    await _finding(session, owner, scan, "o1", engine="osv")

    rows = await scan_service.query_findings(session, scan, engine="osv")

    assert [row.dedup_key for row in rows] == ["o1"]


async def test_list_findings_pagination_keeps_severity_order(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "low", severity=Severity.low, title="B")
    await _finding(session, owner, scan, "crit", severity=Severity.critical, title="A")
    await _finding(session, owner, scan, "med", severity=Severity.medium, title="C")

    page = await scan_service.list_findings(session, scan, limit=2, offset=0)

    assert [row.dedup_key for row in page] == ["crit", "med"]


async def test_count_findings_respects_filters(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "a", severity=Severity.high)
    await _finding(session, owner, scan, "b", severity=Severity.high)
    await _finding(session, owner, scan, "c", severity=Severity.low)

    assert await scan_service.count_findings(session, scan) == 3
    assert await scan_service.count_findings(session, scan, severities=["high"]) == 2


async def test_severity_counts_include_all_levels(session, tenant) -> None:
    owner, _ = tenant
    target = await _target(session, owner)
    scan = await _scan(session, owner, target, status=ScanStatus.done)
    await _finding(session, owner, scan, "a", severity=Severity.critical)
    await _finding(session, owner, scan, "b", severity=Severity.critical)
    await _finding(session, owner, scan, "c", severity=Severity.low)

    rows = await scan_service.query_findings(session, scan)
    counts = scan_service.severity_counts(rows)

    assert counts["critical"] == 2
    assert counts["low"] == 1
    assert counts["info"] == 0
    assert set(counts) == {"critical", "high", "medium", "low", "info"}


async def test_finding_counts_for_many_scans(session, tenant) -> None:
    owner, _ = tenant
    first = await _scan(session, owner, await _target(session, owner, "http://localhost:8001"))
    second = await _scan(session, owner, await _target(session, owner, "http://localhost:8002"))
    empty = await _scan(session, owner, await _target(session, owner, "http://localhost:8003"))
    await _finding(session, owner, first, "a")
    await _finding(session, owner, first, "b")
    await _finding(session, owner, second, "c")

    counts = await scan_service.finding_counts(session, [first.id, second.id, empty.id])

    # Topilmasi yo'q skan lug'atda umuman yo'q — chaqiruvchi `.get(id, 0)` ishlatadi.
    assert counts == {first.id: 2, second.id: 1}
    assert counts.get(empty.id, 0) == 0


async def test_finding_counts_handles_empty_input(session) -> None:
    assert await scan_service.finding_counts(session, []) == {}


async def test_unknown_scan_raises_not_found(session, tenant) -> None:
    owner, _ = tenant
    with pytest.raises(scan_service.NotFound):
        await scan_service.get_scan(session, owner, uuid.uuid4())
