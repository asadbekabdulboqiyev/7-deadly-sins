"""Tenant API'si: o'z profili va API kalit rotatsiyasi."""

from __future__ import annotations

from fastapi import APIRouter

from ...services import scan_service
from ..deps import SessionDep, TenantDep
from ..schemas import RotateKeyOut, TenantOut

router = APIRouter(prefix="/tenant", tags=["tenant"])


@router.get("/me", response_model=TenantOut)
async def get_me(tenant: TenantDep) -> TenantOut:
    """Joriy kalit qaysi tenantga tegishli ekanini ko'rsatadi (kalitning o'zi emas)."""
    return TenantOut.model_validate(tenant)


@router.post("/rotate-key", response_model=RotateKeyOut)
async def rotate_key(tenant: TenantDep, session: SessionDep) -> RotateKeyOut:
    """Yangi API kalit beradi. Eski kalit shu zahoti ishlamaydi.

    Yangi kalit javobda faqat bir marta ko'rinadi — bazada faqat hash saqlanadi.
    """
    raw = await scan_service.rotate_api_key(session, tenant)
    return RotateKeyOut(api_key=raw, api_key_prefix=tenant.api_key_prefix)
