"""Scan service: ownership gate, tenant isolation, result persistence."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fakes import FakeOrchestrator
from sqlalchemy import select

from sins.db import get_sessionmaker
from sins.models import Finding, Scan, ScanStatus, Target, utcnow
from sins.schemas import Severity
from sins.services import scan_service


async def test_external_target_requires_verification(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "example.com")

    assert target.verified_at is None
    assert target.verify_token
    assert target.kind == "domain"

    with pytest.raises(scan_service.TargetNotVerified):
        await scan_service.create_scan(session, owner, target.id)


async def test_lab_target_is_auto_verified(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "http://localhost:8099")
    assert target.verified_at is not None
    assert target.verify_method == "lab"

    scan = await scan_service.create_scan(session, owner, target.id)
    assert scan.status == ScanStatus.pending
    assert scan.engines == ["nuclei", "osv", "pride", "envy", "lust", "gluttony", "wrath"]


async def test_create_target_is_idempotent(session, tenant) -> None:
    owner, _ = tenant
    first = await scan_service.create_target(session, owner, "example.com")
    second = await scan_service.create_target(session, owner, "EXAMPLE.com.")
    assert first.id == second.id


async def test_unknown_engine_rejected(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "localhost")
    with pytest.raises(scan_service.InvalidEngine):
        await scan_service.create_scan(session, owner, target.id, ["nikto"])


async def test_unknown_severity_rejected(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "localhost")
    with pytest.raises(scan_service.InvalidEngine):
        await scan_service.create_scan(session, owner, target.id, severities=["apocalyptic"])


async def test_default_severities_exclude_info(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "localhost")
    scan = await scan_service.create_scan(session, owner, target.id)
    assert scan.severities == ["critical", "high", "medium", "low"]


async def test_second_scan_while_pending_is_rejected(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "127.0.0.1")
    await scan_service.create_scan(session, owner, target.id)
    with pytest.raises(scan_service.ScanBusy):
        await scan_service.create_scan(session, owner, target.id)


async def test_tenant_cannot_see_foreign_scan(session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "localhost")
    scan = await scan_service.create_scan(session, owner, target.id)

    intruder, _ = await scan_service.create_tenant(session, "Boshqa mijoz")
    with pytest.raises(scan_service.NotFound):
        await scan_service.get_scan(session, intruder, scan.id)
    with pytest.raises(scan_service.NotFound):
        await scan_service.get_target(session, intruder, target.id)


async def test_execute_scan_persists_findings(monkeypatch, session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "http://localhost:8099")
    scan = await scan_service.create_scan(session, owner, target.id)
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)

    scan_id = scan.id
    await scan_service.execute_scan(scan_id)

    # Read the results from a NEW session - this verifies the worker wrote them.
    async with get_sessionmaker()() as reader:
        fresh = await reader.get(Scan, scan_id)
        assert fresh is not None
        assert fresh.status == ScanStatus.done
        assert fresh.progress == 100
        assert fresh.current_engine is None
        assert fresh.finished_at is not None
        assert [e["name"] for e in fresh.engine_stats] == [
            "nuclei",
            "osv",
            "pride",
            "envy",
            "lust",
            "gluttony",
            "wrath",
        ]

        rows = list(await reader.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        assert len(rows) == 3
        assert {r.dedup_key for r in rows} == {"k1", "k2", "k3"}
        # Remediation is stored as JSONB and re-read.
        log4j = next(r for r in rows if r.dedup_key == "k1")
        assert log4j.remediation["fixed_version"] == "2.17.1"
        assert log4j.severity == Severity.critical

        # Report context is built from the DB findings.
        ctx = await scan_service.build_report_context(reader, owner, fresh)
    assert ctx["total_findings"] == 3
    assert ctx["risk_score"] > 0
    assert ctx["findings"][0].severity is Severity.critical
    assert ctx["engine_names"] == "nuclei, osv, pride, envy, lust, gluttony, wrath"


async def test_execute_scan_is_idempotent(monkeypatch, session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "localhost")
    scan = await scan_service.create_scan(session, owner, target.id)
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)

    scan_id = scan.id
    await scan_service.execute_scan(scan_id)
    await scan_service.execute_scan(scan_id)

    rows = list(await session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    assert len(rows) == 3


async def test_scan_blocked_when_ownership_lost(monkeypatch, session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "example.com")
    # Ownership was verified once, but the re-check window expired 60 days later
    target.verified_at = utcnow() - timedelta(days=60)
    target.verify_method = "dns"
    await session.commit()

    scan = await scan_service.create_scan(session, owner, target.id)

    async def _deny(*_args, **_kwargs):
        return False, "none"

    monkeypatch.setattr(scan_service, "verify_ownership", _deny)

    scan_id = scan.id
    await scan_service.execute_scan(scan_id)

    session.expire_all()
    fresh = await session.get(Scan, scan_id)
    assert fresh is not None
    assert fresh.status == ScanStatus.blocked
    assert "blocked" in (fresh.error or "").lower()

    rows = list(await session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    assert rows == []


async def test_verify_target_reissues_expired_token(monkeypatch, session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "example.com")
    target.verify_expires_at = utcnow() - timedelta(hours=1)
    await session.commit()
    old_token = target.verify_token
    target_id = target.id

    with pytest.raises(scan_service.VerifyTokenExpired) as exc_info:
        await scan_service.verify_target(session, owner, target_id)

    assert exc_info.value.token != old_token
    session.expire_all()
    fresh = await session.get(Target, target_id)
    assert fresh is not None
    assert fresh.verify_token == exc_info.value.token


async def test_verify_target_succeeds(monkeypatch, session, tenant) -> None:
    owner, _ = tenant
    target = await scan_service.create_target(session, owner, "example.com")

    async def _allow(*_args, **_kwargs):
        return True, "dns"

    monkeypatch.setattr(scan_service, "verify_ownership", _allow)

    verified = await scan_service.verify_target(session, owner, target.id)
    assert verified.verified_at is not None
    assert verified.verify_method == "dns"
