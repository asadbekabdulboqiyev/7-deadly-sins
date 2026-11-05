"""Scan lifecycle — the single business-logic layer.

The CLI, the HTTP API and the ARQ worker all call exactly these functions.
As a result the rules (ownership checks, tenant isolation, limits) live in
one place and are never duplicated.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import any_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..adapters import ScanContext
from ..authz import OwnershipError, issue_token, verify_ownership
from ..config import get_settings
from ..db import get_sessionmaker
from ..drift import fingerprint
from ..intel import enrich
from ..models import Finding, FindingState, Scan, ScanStatus, Target, Tenant, utcnow
from ..observability import track_engine, track_scan_finished, track_scan_started
from ..orchestrator import SinsOrchestrator
from ..report import build_context
from ..schemas import SEVERITY_ORDER, Category, FindingContract, Remediation, Severity
from ..security import display_prefix, generate_api_key, hash_api_key
from ..targets import classify_target, is_lab_target, normalize_target
from . import drift_service

log = logging.getLogger(__name__)

# Maximum findings allowed per scan (DB protection).
MAX_FINDINGS_PER_SCAN = 5000
# Raw tool output inside evidence is dropped when it exceeds this size.
MAX_EVIDENCE_BYTES = 8192


class ServiceError(RuntimeError):
    """Base class for all domain errors."""


class NotFound(ServiceError):
    pass


class TargetNotVerified(ServiceError):
    pass


class VerifyTokenExpired(ServiceError):
    """Token expired — a new token was issued."""

    def __init__(self, message: str, token: str) -> None:
        super().__init__(message)
        self.token = token


class ScanBusy(ServiceError):
    pass


class InvalidEngine(ServiceError):
    pass


# --------------------------------------------------------------------------
# Tenant
# --------------------------------------------------------------------------


async def create_tenant(session: AsyncSession, name: str) -> tuple[Tenant, str]:
    """New tenant. The key is returned only once — only its hash is stored."""
    raw = generate_api_key()
    tenant = Tenant(
        name=name.strip(),
        api_key_hash=hash_api_key(raw),
        api_key_prefix=display_prefix(raw),
    )
    session.add(tenant)
    await session.commit()
    await session.refresh(tenant)
    return tenant, raw


async def get_tenant_by_key(session: AsyncSession, raw_key: str) -> Tenant | None:
    if not raw_key or not raw_key.startswith("sins_"):
        return None
    stmt = select(Tenant).where(Tenant.api_key_hash == hash_api_key(raw_key))
    return await session.scalar(stmt)


# --------------------------------------------------------------------------
# Target
# --------------------------------------------------------------------------


async def get_target(session: AsyncSession, tenant: Tenant, target_id: uuid.UUID) -> Target:
    stmt = select(Target).where(Target.id == target_id, Target.tenant_id == tenant.id)
    target = await session.scalar(stmt)
    if target is None:
        raise NotFound("Target not found.")
    return target


async def list_targets(
    session: AsyncSession,
    tenant: Tenant,
    *,
    limit: int = 200,
    offset: int = 0,
) -> list[Target]:
    stmt = (
        select(Target)
        .where(Target.tenant_id == tenant.id)
        .order_by(Target.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(await session.scalars(stmt))


async def create_target(session: AsyncSession, tenant: Tenant, value: str) -> Target:
    """Adds a target and issues an ownership token.

    Lab targets (localhost/private IP) are considered verified immediately —
    there is no point in checking them, but this path is CLOSED for external
    addresses.
    """
    settings = get_settings()
    normalized = normalize_target(value)
    kind = classify_target(normalized)

    existing = await session.scalar(
        select(Target).where(Target.tenant_id == tenant.id, Target.value == normalized)
    )
    if existing is not None:
        return existing

    now = utcnow()
    target = Target(
        tenant_id=tenant.id,
        value=normalized,
        kind=kind,
        verify_token=issue_token(),
        verify_expires_at=now + timedelta(hours=settings.verify_token_ttl_hours),
    )
    if is_lab_target(normalized):
        target.verified_at = now
        target.verify_method = "lab"

    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def verify_target(session: AsyncSession, tenant: Tenant, target_id: uuid.UUID) -> Target:
    """Verifies ownership. On success `verified_at` is written."""
    settings = get_settings()
    target = await get_target(session, tenant, target_id)
    now = utcnow()

    if target.verified_at is not None:
        age = now - target.verified_at
        if age.days < settings.verify_recheck_days:
            return target

    if is_lab_target(target.value):
        target.verified_at = now
        target.verify_method = "lab"
        await session.commit()
        return target

    if target.verify_token is None or (
        target.verify_expires_at is not None and target.verify_expires_at <= now
    ):
        target.verify_token = issue_token()
        target.verify_expires_at = now + timedelta(hours=settings.verify_token_ttl_hours)
        await session.commit()
        raise VerifyTokenExpired(
            "The verification token has expired — a new token was issued. "
            "Deploy it and call verification again.",
            target.verify_token,
        )

    ok, method = await verify_ownership(target.value, target.verify_token)
    if not ok:
        raise OwnershipError(
            f"Ownership of '{target.value}' was not verified. "
            f"DNS TXT: _sins-verify.<domain> = <token> "
            f"or file: /.well-known/sins-verify-<token>"
        )

    target.verified_at = now
    target.verify_method = method
    await session.commit()
    await session.refresh(target)
    return target


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------


async def get_scan(session: AsyncSession, tenant: Tenant, scan_id: uuid.UUID) -> Scan:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant.id)
    scan = await session.scalar(stmt)
    if scan is None:
        raise NotFound("Scan not found.")
    return scan


async def list_scans(
    session: AsyncSession,
    tenant: Tenant,
    *,
    limit: int = 50,
    offset: int = 0,
    status_filter: list[str] | None = None,
    target_id: uuid.UUID | None = None,
) -> list[Scan]:
    """Tenant scans, newest first. Pagination and filters."""
    stmt = select(Scan).where(Scan.tenant_id == tenant.id)
    if status_filter:
        stmt = stmt.where(Scan.status.in_(status_filter))
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    stmt = stmt.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    return list(await session.scalars(stmt))


async def count_scans(
    session: AsyncSession,
    tenant: Tenant,
    *,
    status_filter: list[str] | None = None,
    target_id: uuid.UUID | None = None,
) -> int:
    stmt = select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant.id)
    if status_filter:
        stmt = stmt.where(Scan.status.in_(status_filter))
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    return int(await session.scalar(stmt) or 0)


async def find_scan_by_idempotency_key(
    session: AsyncSession, tenant: Tenant, key: str
) -> Scan | None:
    """The scan created with this key, if any — prevents double enqueueing."""
    cleaned = key.strip()[:80]
    if not cleaned:
        return None
    return await session.scalar(
        select(Scan).where(Scan.tenant_id == tenant.id, Scan.idempotency_key == cleaned)
    )


async def prior_findings_for_target(
    session: AsyncSession, tenant_id: uuid.UUID, target_id: uuid.UUID
) -> list[FindingContract]:
    """Findings of the latest completed scan for a target.

    Used as the confirmation base for the exploit pass (Wrath). The first scan
    for a target has no base, so it returns an empty list.
    """
    scan = (
        await session.scalars(
            select(Scan)
            .where(
                Scan.tenant_id == tenant_id,
                Scan.target_id == target_id,
                Scan.status == ScanStatus.done,
            )
            .order_by(Scan.finished_at.desc().nulls_last())
            .limit(1)
        )
    ).one_or_none()
    if scan is None:
        return []

    rows = list(await session.scalars(select(Finding).where(Finding.scan_id == scan.id).limit(50)))
    contracts: list[FindingContract] = []
    for row in rows:
        contracts.append(
            FindingContract(
                category=row.category,
                title=row.title,
                severity=row.severity,
                cvss=row.cvss,
                cve=list(row.cve or []),
                cwe=list(row.cwe or []),
                location=row.location,
                evidence=dict(row.evidence or {}),
                source_tools=list(row.source_tools or []),
                dedup_key=row.dedup_key,
                remediation=Remediation.model_validate(row.remediation)
                if row.remediation
                else None,
            )
        )
    return contracts


async def query_findings(
    session: AsyncSession,
    scan: Scan,
    *,
    severities: list[str] | None = None,
    engine: str | None = None,
) -> list[Finding]:
    """Scan findings, sorted by severity.

    `ORDER BY` on the enum column sorts alphabetically (critical ends up last),
    so sorting happens in Python — predictable and DB-independent.
    Filtering runs in the DB: even with 5000 findings it is cheap.
    """
    stmt = select(Finding).where(Finding.scan_id == scan.id)
    if severities:
        stmt = stmt.where(Finding.severity.in_(severities))
    if engine:
        stmt = stmt.where(any_(Finding.source_tools) == engine)
    rows = list(await session.scalars(stmt))
    rows.sort(key=lambda r: (-SEVERITY_ORDER[Severity(r.severity)], r.title))
    return rows


async def list_findings(
    session: AsyncSession,
    scan: Scan,
    *,
    severities: list[str] | None = None,
    engine: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[Finding]:
    """Paginated list. `limit=None` — all findings (for PDF)."""
    rows = await query_findings(session, scan, severities=severities, engine=engine)
    if limit is None:
        return rows
    return rows[offset : offset + limit]


async def count_findings(
    session: AsyncSession,
    scan: Scan,
    *,
    severities: list[str] | None = None,
    engine: str | None = None,
) -> int:
    return len(await query_findings(session, scan, severities=severities, engine=engine))


async def finding_counts(session: AsyncSession, scan_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    """Finding count for several scans — a single query (no N+1).

    The returned dict contains only scans that have findings; callers use
    `.get(scan_id, 0)`.
    """
    if not scan_ids:
        return {}
    rows = await session.execute(
        select(Finding.scan_id, func.count())
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id)
    )
    return {scan_id: int(count) for scan_id, count in rows}


def severity_counts(rows: list[Finding]) -> dict[str, int]:
    """Count per severity — for the dashboard and the PDF."""
    counts = {level.value: 0 for level in Severity}
    for row in rows:
        counts[str(row.severity)] = counts.get(str(row.severity), 0) + 1
    return counts


def _select_engines(requested: list[str] | None) -> list[str]:
    allowed = get_settings().allowed_engines_list()
    if not requested:
        return allowed
    unknown = [e for e in requested if e not in allowed]
    if unknown:
        raise InvalidEngine(
            f"Noma'lum engine: {', '.join(unknown)}. Ruxsat etilgan: {', '.join(allowed)}"
        )
    return requested


_SEVERITY_VALUES = {"critical", "high", "medium", "low", "info"}
DEFAULT_SEVERITIES = ["critical", "high", "medium", "low"]


def _select_severities(requested: list[str] | None) -> list[str]:
    if not requested:
        return list(DEFAULT_SEVERITIES)
    unknown = [s for s in requested if s not in _SEVERITY_VALUES]
    if unknown:
        raise InvalidEngine(
            f"Noma'lum severity: {', '.join(unknown)}. "
            f"Ruxsat etilgan: {', '.join(sorted(_SEVERITY_VALUES))}"
        )
    return requested


async def create_scan(
    session: AsyncSession,
    tenant: Tenant,
    target_id: uuid.UUID,
    engines: list[str] | None = None,
    severities: list[str] | None = None,
    idempotency_key: str | None = None,
) -> Scan:
    """Create a scan. Rejects the scan when target ownership is not verified.

    If an `idempotency_key` is supplied and a scan already exists for that key,
    the existing scan is returned instead of creating a new one — a repeated
    network retry does not start a second scan.
    """
    if idempotency_key:
        key = idempotency_key.strip()[:80]
        existing_scan = await session.scalar(
            select(Scan).where(Scan.tenant_id == tenant.id, Scan.idempotency_key == key)
        )
        if existing_scan is not None:
            return existing_scan

    target = await get_target(session, tenant, target_id)

    if target.verified_at is None:
        raise TargetNotVerified(
            "Target ownership is not verified. Call POST /targets/{id}/verify first."
        )

    selected = _select_engines(engines)
    levels = _select_severities(severities)

    busy = await session.scalar(
        select(Scan.id).where(
            Scan.target_id == target.id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
    )
    if busy is not None:
        raise ScanBusy("A scan is already queued or running for this target.")

    scan = Scan(
        tenant_id=tenant.id,
        target_id=target.id,
        engines=selected,
        severities=levels,
        status=ScanStatus.pending,
        progress=0,
        idempotency_key=(idempotency_key.strip()[:80] if idempotency_key else None),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def _set_progress(scan_id: uuid.UUID, progress: int, engine: str | None) -> None:
    async with get_sessionmaker()() as session:
        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(progress=progress, current_engine=engine)
        )
        await session.commit()


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Raw tool output can be very large — keep the DB from exhausting memory."""
    if not evidence:
        return {}
    try:
        size = len(json.dumps(evidence, default=str))
    except (TypeError, ValueError):
        return {}
    if size <= MAX_EVIDENCE_BYTES:
        return evidence
    trimmed = {k: v for k, v in evidence.items() if k != "raw"}
    trimmed["_raw_omitted_bytes"] = size
    return trimmed


def _to_finding_row(scan: Scan, contract: FindingContract) -> Finding:
    return Finding(
        scan_id=scan.id,
        tenant_id=scan.tenant_id,
        category=contract.category,
        severity=contract.severity,
        title=contract.title[:500],
        cvss=contract.cvss,
        cve=contract.cve,
        cwe=contract.cwe,
        location=contract.location[:1000],
        evidence=_compact_evidence(contract.evidence),
        source_tools=contract.source_tools,
        remediation=(
            contract.remediation.model_dump(mode="json") if contract.remediation else None
        ),
        dedup_key=contract.dedup_key[:64],
    )


async def execute_scan(scan_id: uuid.UUID) -> None:
    """Worker entry point. Runs the scan if it has not been created yet,
    otherwise persists the resulting findings.

    Idempotent: if the scan has already finished, no changes are made.
    """
    settings = get_settings()

    async with get_sessionmaker()() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            log.warning("execute_scan: scan not found %s", scan_id)
            return
        if scan.status in {ScanStatus.done, ScanStatus.blocked, ScanStatus.cancelled}:
            log.info("execute_scan: scan %s already %s", scan_id, scan.status)
            return
        if scan.status == ScanStatus.running:
            log.warning("execute_scan: scan %s is already running", scan_id)
            return

        target = await session.get(Target, scan.target_id)
        if target is None:
            scan.status = ScanStatus.failed
            scan.error = "The target was deleted."
            scan.finished_at = utcnow()
            await session.commit()
            return

        scan.status = ScanStatus.running
        scan.started_at = utcnow()
        scan.progress = 1
        scan.error = None
        await session.commit()
        track_scan_started()

    try:
        # --- Re-check: if ownership has expired, refresh it ---
        if not is_lab_target(target.value):
            stale = (
                target.verified_at is None
                or (utcnow() - target.verified_at).days >= settings.verify_recheck_days
            )
            if stale and target.verify_token:
                ok, method = await verify_ownership(target.value, target.verify_token)
                async with get_sessionmaker()() as session:
                    fresh = await session.get(Target, target.id)
                    if ok and fresh is not None:
                        fresh.verified_at = utcnow()
                        fresh.verify_method = method
                        await session.commit()
                    elif not ok:
                        db_scan = await session.get(Scan, scan_id)
                        if db_scan is not None:
                            db_scan.status = ScanStatus.blocked
                            db_scan.error = (
                                "Ownership re-check failed — scan blocked. "
                                "The TXT record or .well-known file may have been removed."
                            )
                            db_scan.finished_at = utcnow()
                            await session.commit()
                        return

        prior = await prior_findings_for_target(session, scan.tenant_id, scan.target_id)
        ctx = ScanContext(
            target=target.value,
            max_rps=settings.max_rps,
            timeout=settings.tool_timeout_seconds,
            severities=list(scan.severities) or DEFAULT_SEVERITIES,
            prior_findings=prior,
        )
        orchestrator = SinsOrchestrator(list(scan.engines))
        total = max(1, len(orchestrator.adapters))
        done = 0

        async def on_engine_done(engine_report) -> None:  # noqa: ANN001 — EngineReport
            nonlocal done
            done += 1
            track_engine(engine_report.name, engine_report.ok, engine_report.duration_ms)
            await _set_progress(scan_id, min(95, int(done / total * 90) + 5), engine_report.name)

        report = await orchestrator.run(ctx, on_engine_done)
    except Exception as exc:  # noqa: BLE001 — scan state must be written in any case
        log.exception("scan %s failed", scan_id)
        async with get_sessionmaker()() as session:
            db_scan = await session.get(Scan, scan_id)
            if db_scan is not None:
                db_scan.status = ScanStatus.failed
                db_scan.error = f"{type(exc).__name__}: {exc}"[:2000]
                db_scan.finished_at = utcnow()
                await session.commit()
                track_scan_finished("failed", 0, 0)
        return

    # --- Persist results ---
    async with get_sessionmaker()() as session:
        db_scan = await session.get(Scan, scan_id)
        if db_scan is None:
            return

        if db_scan.status == ScanStatus.cancelled:
            # A cancelled scan must not persist findings.
            log.info("scan %s cancelled, results not persisted", scan_id)
            return

        contracts = report.findings[:MAX_FINDINGS_PER_SCAN]
        for contract in contracts:
            session.add(_to_finding_row(db_scan, contract))

        await drift_service.upsert_finding_states(session, db_scan, contracts)

        db_scan.status = ScanStatus.done
        db_scan.progress = 100
        db_scan.current_engine = None
        db_scan.finished_at = utcnow()
        db_scan.engine_stats = [
            {
                "name": e.name,
                "sin": e.sin,
                "ok": e.ok,
                "findings": e.findings,
                "duration_ms": e.duration_ms,
                "error": e.error,
                "skipped": e.skipped,
                "skip_reason": e.skip_reason,
            }
            for e in report.engines
        ]
        if len(report.findings) > MAX_FINDINGS_PER_SCAN:
            db_scan.error = (
                f"Found {len(report.findings)} findings - only the first "
                f"{MAX_FINDINGS_PER_SCAN} were kept."
            )
        await session.commit()
        track_scan_finished("done", report.duration_ms, len(contracts))
        log.info(
            "scan %s finished: %d findings, %d ms",
            scan_id,
            len(contracts),
            report.duration_ms,
        )


# --------------------------------------------------------------------------
# Operations actions: cancel, diff, rotate key, prune
# --------------------------------------------------------------------------


class NotCancellable(ServiceError):
    """The scan has already finished — it cannot be cancelled."""


class InvalidScanState(ServiceError):
    """The action is not valid for the scan's current state."""


@dataclass(slots=True)
class ScanDiff:
    """Compare two scans: what is new, what was fixed, what came back."""

    scan_id: uuid.UUID
    against_scan_id: uuid.UUID | None
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    persisting: int = 0
    regressed: list[Finding] = field(default_factory=list)

    @property
    def has_baseline(self) -> bool:
        return self.against_scan_id is not None


async def cancel_scan(session: AsyncSession, tenant: Tenant, scan_id: uuid.UUID) -> Scan:
    """Cancel a pending or running scan.

    The worker re-reads the state before writing results — so
    a cancelled scan must not write findings to the database.
    """
    scan = await get_scan(session, tenant, scan_id)
    if scan.status in {
        ScanStatus.done,
        ScanStatus.failed,
        ScanStatus.cancelled,
        ScanStatus.blocked,
    }:
        raise NotCancellable(f"The scan is in status '{scan.status}' and cannot be cancelled.")

    scan.status = ScanStatus.cancelled
    scan.current_engine = None
    scan.finished_at = utcnow()
    await session.commit()
    await session.refresh(scan)
    log.info("scan %s cancelled", scan_id)
    return scan


async def previous_completed_scan(session: AsyncSession, tenant: Tenant, scan: Scan) -> Scan | None:
    """The most recent completed scan for this target (diff base)."""
    stmt = (
        select(Scan)
        .where(
            Scan.tenant_id == tenant.id,
            Scan.target_id == scan.target_id,
            Scan.status == ScanStatus.done,
            Scan.id != scan.id,
            Scan.created_at <= scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return await session.scalar(stmt)


async def diff_scan(
    session: AsyncSession,
    tenant: Tenant,
    scan: Scan,
    against_id: uuid.UUID | None = None,
) -> ScanDiff:
    """Compare the current scan against the previous (or a given) scan.

    The diff is keyed on `dedup_key`: a finding that reappears is
    "persisting", one that is gone is "resolved", and one that newly appears
    is "new".
    """
    if scan.status != ScanStatus.done:
        raise InvalidScanState(f"Only a completed scan can be diffed (status: {scan.status}).")

    if against_id is not None:
        base = await get_scan(session, tenant, against_id)
        if base.target_id != scan.target_id:
            raise InvalidScanState("The two scans belong to different targets.")
        if base.status != ScanStatus.done:
            raise InvalidScanState("The comparison scan must be completed.")
    else:
        base = await previous_completed_scan(session, tenant, scan)

    current_rows = await query_findings(session, scan)
    if base is None:
        return ScanDiff(
            scan_id=scan.id,
            against_scan_id=None,
            new=list(current_rows),
            resolved=[],
            persisting=0,
        )

    base_rows = await query_findings(session, base)
    current_keys = {row.dedup_key for row in current_rows}
    base_keys = {row.dedup_key for row in base_rows}

    resolved = [row for row in base_rows if row.dedup_key not in current_keys]
    regressions = [row for row in resolved if await _was_seen_before(session, base, row)]

    return ScanDiff(
        scan_id=scan.id,
        against_scan_id=base.id,
        new=[row for row in current_rows if row.dedup_key not in base_keys],
        resolved=resolved,
        persisting=len(current_keys & base_keys),
        regressed=regressions,
    )


async def _was_seen_before(session: AsyncSession, scan: Scan, finding: Finding) -> bool:
    """True when the resolved finding existed in an earlier scan of this target."""
    target = await session.get(Target, scan.target_id)
    if target is None:
        return False
    key = fingerprint(
        target=target.value,
        category=str(finding.category),
        title=finding.title,
        location=finding.location,
        cve=finding.cve or [],
    )
    state = await session.scalar(
        select(FindingState)
        .where(
            FindingState.tenant_id == scan.tenant_id,
            FindingState.target_id == target.id,
            FindingState.fingerprint == key,
        )
        .limit(1)
    )
    if state is None:
        return False
    return state.first_seen_at < (scan.started_at or scan.created_at)


async def rotate_api_key(session: AsyncSession, tenant: Tenant) -> str:
    """Yangi API kalit beradi. Eski kalit shu zahoti ishlamaydi."""
    raw = generate_api_key()
    tenant.api_key_hash = hash_api_key(raw)
    tenant.api_key_prefix = display_prefix(raw)
    await session.commit()
    await session.refresh(tenant)
    log.info("API key rotated for tenant %s", tenant.id)
    return raw


async def prune_scans(
    session: AsyncSession, *, older_than_days: int, dry_run: bool = False
) -> tuple[int, int]:
    """Delete scans from the retention policy. (scans, findings)."""
    if older_than_days < 1:
        raise ValueError("older_than_days must be >= 1")

    cutoff = utcnow() - timedelta(days=older_than_days)
    scan_ids = list(await session.scalars(select(Scan.id).where(Scan.created_at < cutoff)))
    if not scan_ids:
        return 0, 0

    finding_count = await session.scalar(
        select(func.count()).select_from(Finding).where(Finding.scan_id.in_(scan_ids))
    )

    if dry_run:
        return len(scan_ids), int(finding_count or 0)

    await session.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
    await session.execute(delete(Scan).where(Scan.id.in_(scan_ids)))
    await session.commit()
    log.info("prune: %d scans, %d findings removed", len(scan_ids), finding_count)
    return len(scan_ids), int(finding_count or 0)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def _to_contract(row: Finding) -> FindingContract:
    return FindingContract(
        category=Category(row.category),
        title=row.title,
        severity=Severity(row.severity),
        cvss=row.cvss,
        cve=row.cve or [],
        cwe=row.cwe or [],
        location=row.location,
        evidence=row.evidence or {},
        source_tools=row.source_tools or [],
        dedup_key=row.dedup_key,
        remediation=Remediation(**row.remediation) if row.remediation else None,
    )


async def build_report_context(session: AsyncSession, tenant: Tenant, scan: Scan) -> dict[str, Any]:
    """Context for the PDF report. Only database-accepted results are used."""
    target = await session.get(Target, scan.target_id)
    rows = await list_findings(session, scan)
    duration_ms = 0
    if scan.started_at and scan.finished_at:
        duration_ms = int((scan.finished_at - scan.started_at).total_seconds() * 1000)

    findings = [_to_contract(r) for r in rows]
    settings = get_settings()
    intel = None
    if settings.threat_intel_enabled and findings:
        # Enrichment is additive: any failure inside `enrich` degrades to
        # "not consulted" and the report is still generated.
        try:
            intel = await enrich(
                [cve for finding in findings for cve in finding.cve],
                timeout=settings.threat_intel_timeout_seconds,
            )
        except Exception:  # noqa: BLE001 — never lose the report over intel
            log.exception("threat-intel enrichment failed — continuing without it")

    return build_context(
        scan_id=str(scan.id),
        target=target.value if target else "—",
        tenant_name=tenant.name,
        findings=findings,
        engines=scan.engine_stats or [],
        duration_ms=duration_ms,
        intel=intel,
    )
