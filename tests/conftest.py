"""Test muhiti sozlamalari.

MUHIM: testlar ALOHIDA bazada ishlaydi (`sins_test`).
Baza nomi `_test` bilan tugamasa — testlar umuman ishga tushmaydi,
shunda tasodifan prod bazani o'chirib yuborish mumkin emas.
"""

from __future__ import annotations

import getpass
import os

_TEST_DB = os.environ.get("SINS_TEST_DATABASE_URL") or (
    f"postgresql+asyncpg://{getpass.getuser()}@localhost:5432/sins_test"
)
_db_name = _TEST_DB.rsplit("/", 1)[-1].split("?")[0]
if not _db_name.endswith("_test"):
    raise RuntimeError(
        f"Test bazasi nomi '_test' bilan tugashi shart, aks holda testlar "
        f"haqiqiy bazani o'chirib yuboradi: {_TEST_DB}"
    )

os.environ["SINS_DATABASE_URL"] = _TEST_DB
os.environ["SINS_REDIS_URL"] = "redis://localhost:6379/15"
# Testlar rate limitga urilib qolmasin va retry kutmasin.
os.environ.setdefault("SINS_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SINS_ADAPTER_MAX_ATTEMPTS", "1")

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

from sins.api.main import create_app  # noqa: E402
from sins.db import create_all, drop_all, get_engine, get_sessionmaker  # noqa: E402
from sins.services import scan_service  # noqa: E402


async def _ensure_database() -> None:
    """Baza mavjud bo'lmasa yaratadi — testlar `createdb` ni talab qilmaydi."""
    dsn = _TEST_DB.replace("postgresql+asyncpg://", "postgresql://")
    admin_dsn = dsn.rsplit("/", 1)[0] + "/postgres"
    conn = await asyncpg.connect(admin_dsn)
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", _db_name)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{_db_name}"')
    finally:
        await conn.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _schema():
    await _ensure_database()
    await drop_all()
    await create_all()
    yield
    await get_engine().dispose()


@pytest_asyncio.fixture
async def session():
    async with get_sessionmaker()() as s:
        yield s


@pytest_asyncio.fixture
async def tenant(session):
    """Yangi mijoz + uning API kaliti."""
    return await scan_service.create_tenant(session, "Test Mijoz")


@pytest_asyncio.fixture
async def app():
    return create_app()


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
