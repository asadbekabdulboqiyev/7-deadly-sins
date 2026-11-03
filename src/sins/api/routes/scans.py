"""Skanlar API'si: yaratish, holat, topilmalar, diff, bekor qilish, PDF."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status

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
    """Skan job'ini navbatga qo'yadi.

    Redis bo'lmasa (dev rejimi) — shu jarayonda fon vazifasi sifatida boshlanadi.
    """
    arq = getattr(request.app.state, "arq", None)
    if arq is not None:
        try:
            await arq.enqueue_job("run_scan", str(scan_id))
            return
        except Exception:  # noqa: BLE001 — navbat yiqilsa skan yo'qolmasin
            log.exception("ARQ navbatiga qo'shib bo'lmadi — inline bajariladi")

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
    """Takrorlanuvchi query parametrlarini ham, vergulli satrni ham qabul qiladi."""
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
    """Skan yaratadi va navbatga qo'yadi.

    `Idempotency-Key` berilsa, shu kalit bilan skan allaqachon mavjud bo'lsa
    yangi skan boshlanmaydi — mavjudi qaytariladi (xavfsiz qayta yuborish).
    Egalik tasdiqlanmagan bo'lsa — 409.
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
    return [_to_out(s) for s in scans]


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
    """Topilmalar: og'irlik va engine bo'yicha filtr, sahifalash, umumiy sonlar."""
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
    """Navbatdagi yoki bajarilayotgan skanni bekor qiladi."""
    scan = await scan_service.cancel_scan(session, tenant, scan_id)
    return _to_out(scan)


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
async def diff_scan(
    scan_id: UUID,
    tenant: TenantDep,
    session: SessionDep,
    against: UUID | None = None,
) -> ScanDiffOut:
    """Joriy skan va oldingi skan orasidagi farq: yangi / hal qilindi / saqlanib qoldi."""
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
    """Professional PDF hisobot. Faqat tugagan skan uchun."""
    scan = await scan_service.get_scan(session, tenant, scan_id)
    if scan.status != ScanStatus.done:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Skan hali tugamagan (holat: {scan.status}). Hisobot keyin tayyor bo'ladi.",
        )

    from ...report import render_pdf

    ctx = await scan_service.build_report_context(session, tenant, scan)
    # WeasyPrint CPU-bound va sekin — event loop'ni bloklamaymiz.
    pdf = await asyncio.to_thread(render_pdf, ctx)
    filename = f"sins-report-{str(scan.id)[:8]}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
