"""Exposure lifecycle service — timeline reads and state writes."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from ..drift import exposure_score, fingerprint
from ..models import FindingState, Scan, Target, Tenant, utcnow
from ..schemas import FindingContract

log = logging.getLogger(__name__)


async def upsert_finding_states(
    session, scan: Scan, findings: list[FindingContract]
) -> list[FindingState]:
    """Write or refresh the exposure lifecycle row for every finding of a scan."""
    target = await session.get(Target, scan.target_id)
    if target is None:
        return []

    states: list[FindingState] = []
    now = utcnow()
    for finding in findings:
        key = fingerprint(
            target=target.value,
            category=str(finding.category),
            title=finding.title,
            location=finding.location,
            cve=finding.cve,
        )
        state = await session.scalar(
            select(FindingState)
            .where(FindingState.target_id == target.id, FindingState.fingerprint == key)
            .limit(1)
        )
        if state is None:
            state = FindingState(
                tenant_id=scan.tenant_id,
                target_id=target.id,
                fingerprint=key,
                category=str(finding.category),
                severity=str(finding.severity),
                title=finding.title[:500],
                location=finding.location[:1000],
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                occurrences=1,
                regressions=0,
                scan_id=scan.id,
            )
        else:
            regressed = state.status == "resolved" and state.resolved_at is not None
            state.status = "open"
            state.last_seen_at = now
            state.occurrences = int(state.occurrences or 0) + 1
            state.regressions = int(state.regressions or 0) + (1 if regressed else 0)
            state.scan_id = scan.id
        state.resolved_at = None

        session.add(state)
        states.append(state)

    await session.commit()
    return states


async def list_finding_states(session, tenant: Tenant, target_id) -> list[FindingState]:
    """Exposure states of one target, newest first."""
    stmt = (
        select(FindingState)
        .where(FindingState.tenant_id == tenant.id, FindingState.target_id == target_id)
        .order_by(FindingState.first_seen_at.desc())
    )
    return list(await session.scalars(stmt))


async def exposure_timeline(
    session,
    tenant: Tenant,
    target_id,
    *,
    days: int = 365,
) -> dict[str, Any]:
    """Daily exposure series for a target."""
    window_days = max(1, min(int(days), 730))
    now = utcnow()
    start = now - timedelta(days=window_days)

    rows = list(
        await session.scalars(
            select(FindingState).where(
                FindingState.tenant_id == tenant.id,
                FindingState.target_id == target_id,
                FindingState.last_seen_at >= start,
            )
        )
    )

    points: list[dict[str, Any]] = []
    for offset in range(window_days, -1, -1):
        day_start = start + timedelta(days=offset)
        day_end = day_start + timedelta(days=1)
        open_rows = [
            r
            for r in rows
            if (
                r.status == "open"
                and r.first_seen_at < day_end
                and (r.resolved_at is None or r.resolved_at > day_start)
            )
        ]
        points.append(
            {
                "day": day_start.date().isoformat(),
                "open": len(open_rows),
                "resolved": len(
                    [
                        r
                        for r in rows
                        if r.status == "resolved"
                        and r.resolved_at is not None
                        and r.resolved_at > day_start
                    ]
                ),
                "regressed": sum(int(r.regressions or 0) for r in rows if r.target_id == target_id),
                "score": round(exposure_score(open_rows), 2),
            }
        )

    current = [r for r in rows if r.status == "open" and r.first_seen_at <= now]
    return {
        "target_id": str(target_id),
        "days": window_days,
        "from_day": start.date().isoformat(),
        "to_day": now.date().isoformat(),
        "open_now": len(current),
        "score_now": round(exposure_score(current), 2),
        "points": points,
    }
