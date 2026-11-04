"""Targets API: create, verify ownership, list."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query, status

from ...models import Target
from ...services import scan_service
from ...targets import extract_host
from ..deps import SessionDep, TenantDep
from ..schemas import TargetCreate, TargetOut, VerifyInstructions

router = APIRouter(prefix="/targets", tags=["targets"])


def _instructions(target: Target) -> VerifyInstructions | None:
    if target.verified_at is not None:
        return None
    token = target.verify_token or ""
    host = extract_host(target.value)
    dns_record = None if target.kind == "ip" else f"_sins-verify.{host}"
    return VerifyInstructions(
        dns_record=dns_record,
        dns_value=token if dns_record else None,
        http_url=f"https://{host}/.well-known/sins-verify-{token}",
    )


def _to_out(target: Target) -> TargetOut:
    out = TargetOut.model_validate(target)
    out.instructions = _instructions(target)
    return out


@router.post("", status_code=status.HTTP_201_CREATED, response_model=TargetOut)
async def create_target(payload: TargetCreate, tenant: TenantDep, session: SessionDep) -> TargetOut:
    """Adds a target. The response includes precise instructions for proving ownership."""
    target = await scan_service.create_target(session, tenant, payload.value)
    return _to_out(target)


@router.get("", response_model=list[TargetOut])
async def list_targets(
    tenant: TenantDep,
    session: SessionDep,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[TargetOut]:
    """Tenant targets, newest first."""
    rows = await scan_service.list_targets(session, tenant, limit=limit, offset=offset)
    return [_to_out(t) for t in rows]


@router.post("/{target_id}/verify", response_model=TargetOut)
async def verify_target(target_id: UUID, tenant: TenantDep, session: SessionDep) -> TargetOut:
    """Checks the DNS TXT record or the `.well-known` file."""
    target = await scan_service.verify_target(session, tenant, target_id)
    return _to_out(target)
