"""The demo seed must keep telling the same story on every run.

A judge sees the seeded data, not the code, so the guarantees that matter are
behavioural: five scans, a populated findings table, a diff with a new and a
resolved row on the *latest* scan, and a finding that regressed at least once.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy import func, select

from sins.models import Finding, FindingState, Scan, Tenant
from sins.services import scan_service

_SEED_PATH = Path(__file__).resolve().parents[1] / "scripts" / "seed_demo.py"
_spec = importlib.util.spec_from_file_location("seed_demo", _SEED_PATH)
assert _spec is not None and _spec.loader is not None
seed_demo = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = seed_demo
_spec.loader.exec_module(seed_demo)


async def _seed(session, *, reset: bool = True):
    return await seed_demo.seed(
        tenant_name="Seed Demo",
        target_value=seed_demo.DEFAULT_TARGET,
        api_key=None,
        reset=reset,
    )


async def test_seed_builds_five_scans_and_seven_findings(session) -> None:
    seeded = await _seed(session)

    assert len(seeded.scans) == 5
    assert len(seeded.states) == len(seed_demo.CATALOGUE) == 8

    tenant = await session.scalar(select(Tenant).where(Tenant.name == "Seed Demo"))
    assert tenant is not None
    assert (
        await session.scalar(
            select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant.id)
        )
        == 5
    )
    assert (
        await session.scalar(
            select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant.id)
        )
        > 20
    )


async def test_latest_scan_has_a_non_empty_diff(session) -> None:
    """The newest scan must show one new and one resolved row, never a blank diff."""
    seeded = await _seed(session)
    tenant = await session.scalar(select(Tenant).where(Tenant.name == "Seed Demo"))
    assert tenant is not None
    latest = await session.get(Scan, seeded.scans[-1]["id"])

    diff = await scan_service.diff_scan(session, tenant, latest)

    assert [row.title for row in diff.new] == [seed_demo.CATALOGUE["env"].title]
    assert [row.title for row in diff.resolved] == [seed_demo.CATALOGUE["citrix"].title]
    assert diff.persisting == 4


async def test_states_capture_resolved_and_regressed(session) -> None:
    seeded = await _seed(session)
    tenant = await session.scalar(select(Tenant).where(Tenant.name == "Seed Demo"))
    assert tenant is not None
    rows = {
        row.title: row
        for row in await session.scalars(
            select(FindingState).where(FindingState.tenant_id == tenant.id)
        )
    }

    tls = rows[seed_demo.CATALOGUE["tls10"].title]
    assert tls.status == "open"
    assert tls.regressions == 1
    assert tls.occurrences == 4

    lodash = rows[seed_demo.CATALOGUE["lodash"].title]
    assert lodash.status == "resolved"
    assert lodash.resolved_at is not None
    assert lodash.last_seen_at < lodash.resolved_at

    assert seeded.states["citrix"]["status"] == "resolved"


async def test_reset_replaces_instead_of_duplicating(session) -> None:
    await _seed(session)
    await _seed(session)

    tenant = await session.scalar(select(Tenant).where(Tenant.name == "Seed Demo"))
    assert tenant is not None
    assert (
        await session.scalar(
            select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant.id)
        )
        == 5
    )


async def test_refuses_to_touch_a_tenant_that_already_has_scans(session) -> None:
    await _seed(session)

    with pytest.raises(SystemExit, match="already has"):
        await _seed(session, reset=False)
