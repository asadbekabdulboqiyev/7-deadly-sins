"""Scans API: create, status, findings, diff, cancel, PDF."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from ...config import get_settings
from ...db import get_sessionmaker
from ...models import Finding, Scan, ScanStatus
from ...services import scan_service
from ..deps import SessionDep, TenantDep
from ..schemas import (
    DiffFinding,
    FindingOut,
    FindingsPage,
    ScanCreate,
    ScanDiffOut,
    ScanOut,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

MAX_PAGE = 500


async def _enqueue(request: Request, scan_id: UUID) -> None:
    """Enqueues the scan job.

    Without Redis (dev mode) it runs as a background task in this process.
    """
    arq = getattr(request.app.state, "arq", None)
    if arq is not None:
        try:
            await arq.enqueue_job("run_scan", str(scan_id))
            return
        except Exception:  # noqa: BLE001 — a broken queue must not lose the scan
            log.exception("could not enqueue on the ARQ queue — running inline")

    task = asyncio.create_task(scan_service.execute_scan(scan_id))
    request.app.state.tasks.add(task)
    task.add_done_callback(request.app.state.tasks.discard)


def _to_out(scan: Scan, finding_count: int | None = None) -> ScanOut:
    out = ScanOut.model_validate(scan)
    out.finding_count = finding_count
    return out


def _finding_out(row: Finding) -> FindingOut:
    return FindingOut(
        id=row.id,
        category=row.category,
        severity=row.severity,
        title=row.title,
        cvss=row.cvss,
        cve=row.cve or [],
        cwe=row.cwe or [],
        location=row.location,
        source_tools=row.source_tools or [],
        remediation=row.remediation,
        evidence=row.evidence or {},
        dedup_key=row.dedup_key,
    )


def _as_filter(values: list[str] | None) -> list[str] | None:
    """Accepts repeated query parameters as well as a comma-separated string."""
    if not values:
        return None
    flat: list[str] = []
    for value in values:
        flat.extend(part.strip() for part in value.split(",") if part.strip())
    return flat or None


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanOut)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    tenant: TenantDep,
    session: SessionDep,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> ScanOut:
    """Creates a scan and enqueues it.

    If `Idempotency-Key` is given and a scan with that key already exists,
    no new scan is started — the existing one is returned (safe retry).
    Returns 409 when ownership has not been verified.
    """
    if idempotency_key:
        existing = await scan_service.find_scan_by_idempotency_key(session, tenant, idempotency_key)
        if existing is not None:
            return _to_out(existing)

    scan = await scan_service.create_scan(
        session,
        tenant,
        payload.target_id,
        payload.engines,
        payload.severities,
        idempotency_key=idempotency_key,
    )
    await _enqueue(request, scan.id)
    return _to_out(scan)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    tenant: TenantDep,
    session: SessionDep,
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0),
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    target_id: UUID | None = None,
) -> list[ScanOut]:
    scans = await scan_service.list_scans(
        session,
        tenant,
        limit=limit,
        offset=offset,
        status_filter=_as_filter(status_filter),
        target_id=target_id,
    )
    counts = await scan_service.finding_counts(session, [s.id for s in scans])
    return [_to_out(s, counts.get(s.id, 0)) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: UUID, tenant: TenantDep, session: SessionDep) -> ScanOut:
    scan = await scan_service.get_scan(session, tenant, scan_id)
    total = await scan_service.count_findings(session, scan)
    return _to_out(scan, finding_count=total)


@router.get("/{scan_id}/findings", response_model=FindingsPage)
async def get_findings(
    scan_id: UUID,
    tenant: TenantDep,
    session: SessionDep,
    severity: Annotated[list[str] | None, Query()] = None,
    engine: str | None = None,
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0),
) -> FindingsPage:
    """Findings: filter by severity and engine, pagination, totals."""
    scan = await scan_service.get_scan(session, tenant, scan_id)
    severities = _as_filter(severity)

    all_rows = await scan_service.query_findings(
        session, scan, severities=severities, engine=engine
    )
    page = all_rows[offset : offset + limit]
    return FindingsPage(
        scan_id=scan.id,
        total=len(all_rows),
        limit=limit,
        offset=offset,
        has_more=offset + len(page) < len(all_rows),
        severity_counts=scan_service.severity_counts(all_rows),
        items=[_finding_out(row) for row in page],
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: UUID, tenant: TenantDep, session: SessionDep) -> ScanOut:
    """Cancels a queued or running scan."""
    scan = await scan_service.cancel_scan(session, tenant, scan_id)
    return _to_out(scan)


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
async def diff_scan(
    scan_id: UUID,
    tenant: TenantDep,
    session: SessionDep,
    against: UUID | None = None,
) -> ScanDiffOut:
    """Difference between the current scan and a previous one: new / resolved / persisting."""
    scan = await scan_service.get_scan(session, tenant, scan_id)
    diff = await scan_service.diff_scan(session, tenant, scan, against_id=against)
    return ScanDiffOut(
        scan_id=diff.scan_id,
        against_scan_id=diff.against_scan_id,
        baseline=diff.has_baseline,
        new=[
            DiffFinding(
                dedup_key=r.dedup_key,
                severity=r.severity,
                title=r.title,
                location=r.location,
            )
            for r in diff.new
        ],
        resolved=[
            DiffFinding(
                dedup_key=r.dedup_key,
                severity=r.severity,
                title=r.title,
                location=r.location,
            )
            for r in diff.resolved
        ],
        persisting=diff.persisting,
    )


@router.get("/{scan_id}/report.pdf", response_class=Response)
async def download_report(scan_id: UUID, tenant: TenantDep, session: SessionDep) -> Response:
    """Professional PDF report. Completed scans only."""
    scan = await scan_service.get_scan(session, tenant, scan_id)
    if scan.status != ScanStatus.done:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Scan has not finished yet (status: {scan.status}). "
                "The report will be ready afterwards."
            ),
        )

    from ...report import render_pdf

    ctx = await scan_service.build_report_context(session, tenant, scan)
    # WeasyPrint is CPU-bound and slow — do not block the event loop.
    pdf = await asyncio.to_thread(render_pdf, ctx)
    filename = f"sins-report-{str(scan.id)[:8]}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: UUID,
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    api_key: Annotated[
        str | None,
        Query(description="API key for EventSource clients (browsers cannot set headers)"),
    ] = None,
) -> StreamingResponse:
    """Live scan progress as Server-Sent Events.

    One event per state change, then `event: end`. The stream is read-only and
    scoped to the caller's tenant. `?api_key=` exists only because the browser
    `EventSource` API cannot send an `X-API-Key` header; query strings are not
    written to the access log.
    """
    key = x_api_key or api_key
    async with get_sessionmaker()() as session:
        tenant = await scan_service.get_tenant_by_key(session, key or "")
        if tenant is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Pass `X-API-Key` or `?api_key=`.",
            )
        scan = await scan_service.get_scan(session, tenant, scan_id)
        tenant_id = tenant.id
        initial = {
            "status": scan.status,
            "progress": scan.progress,
            "engine": scan.current_engine,
            "findings": None,
            "error": scan.error,
        }

    poll = get_settings().sse_poll_seconds
    terminal = {ScanStatus.done, ScanStatus.failed, ScanStatus.cancelled, ScanStatus.blocked}

    async def events():
        payload = initial
        last = json.dumps(payload)
        yield f"event: progress\ndata: {last}\n\n"
        if payload["status"] in terminal:
            yield "event: end\ndata: {}\n\n"
            return

        idle = 0
        while True:
            if await request.is_disconnected():
                return
            await asyncio.sleep(poll)
            async with get_sessionmaker()() as session:
                row = await session.get(Scan, scan_id)
                if row is None or row.tenant_id != tenant_id:
                    yield 'event: error\ndata: {"detail": "scan not found"}\n\n'
                    return
                findings = None
                if row.status == ScanStatus.done:
                    findings = await session.scalar(
                        select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                    )
                payload = {
                    "status": row.status,
                    "progress": row.progress,
                    "engine": row.current_engine,
                    "findings": findings,
                    "error": row.error,
                }

            body = json.dumps(payload)
            if body != last:
                last = body
                idle = 0
                yield f"event: progress\ndata: {body}\n\n"
            else:
                idle += 1
                if idle >= 25:  # ~10 s of silence: keep proxies from closing us
                    idle = 0
                    yield ": keep-alive\n\n"

            if payload["status"] in terminal:
                yield "event: end\ndata: {}\n\n"
                return

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
