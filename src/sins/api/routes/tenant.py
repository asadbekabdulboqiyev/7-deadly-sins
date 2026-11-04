"""Tenant API: own profile and API key rotation."""

from __future__ import annotations

from fastapi import APIRouter

from ...services import scan_service
from ..deps import SessionDep, TenantDep
from ..schemas import RotateKeyOut, TenantOut

router = APIRouter(prefix="/tenant", tags=["tenant"])


@router.get("/me", response_model=TenantOut)
async def get_me(tenant: TenantDep) -> TenantOut:
    """Shows which tenant the current key belongs to (not the key itself)."""
    return TenantOut.model_validate(tenant)


@router.post("/rotate-key", response_model=RotateKeyOut)
async def rotate_key(tenant: TenantDep, session: SessionDep) -> RotateKeyOut:
    """Issues a new API key. The old key stops working immediately.

    The new key appears in the response exactly once — only its hash is stored.
    """
    raw = await scan_service.rotate_api_key(session, tenant)
    return RotateKeyOut(api_key=raw, api_key_prefix=tenant.api_key_prefix)
