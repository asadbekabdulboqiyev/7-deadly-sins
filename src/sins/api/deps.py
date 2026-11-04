"""FastAPI dependencies — authentication and DB session."""

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
    """Resolves the tenant from the `X-API-Key` header.

    The key is stored in the database as a hash — the plaintext exists nowhere.
    The error message is deliberately identical: we do not reveal which keys exist.
    """
    tenant = await scan_service.get_tenant_by_key(session, x_api_key or "")
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Check the `X-API-Key` header.",
            headers={"WWW-Authenticate": "X-API-Key"},
        )
    return tenant


TenantDep = Annotated[Tenant, Depends(get_tenant)]
