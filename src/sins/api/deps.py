"""FastAPI dependency'lari — autentifikatsiya va DB sessiyasi."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Tenant
from ..services import scan_service

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_tenant(
    session: SessionDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Tenant:
    """`X-API-Key` sarlavhasidan tenantni aniqlaydi.

    Kalit bazada hash sifatida saqlanadi — ochiq matn hech qayerda yo'q.
    Xato matni ataylab bir xil: qaysi kalit mavjudligini oshkor qilmaymiz.
    """
    tenant = await scan_service.get_tenant_by_key(session, x_api_key or "")
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API kalit noto'g'ri yoki yo'q. `X-API-Key` sarlavhasini tekshiring.",
            headers={"WWW-Authenticate": "X-API-Key"},
        )
    return tenant


TenantDep = Annotated[Tenant, Depends(get_tenant)]
