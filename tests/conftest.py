"""Test environment settings.

IMPORTANT: tests run against the dedicated DB (`sins_test`).
If the DB name does not end with `_test`, tests will not run against the real DB,
which could accidentally delete the production DB.
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
        f"The test database name must end with `_test`, tests must not touch "
        f"the real database: {_TEST_DB}"
    )

os.environ["SINS_DATABASE_URL"] = _TEST_DB
os.environ["SINS_REDIS_URL"] = "redis://localhost:6379/15"
# Tests must not be rate-limited and must not retry.
os.environ.setdefault("SINS_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SINS_ADAPTER_MAX_ATTEMPTS", "1")
# Report tests must stay offline: KEV/EPSS calls are covered by MockTransport
# in `test_intel.py`, never by the real APIs.
os.environ.setdefault("SINS_THREAT_INTEL_ENABLED", "false")

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

from sins.api.main import create_app  # noqa: E402
from sins.db import create_all, drop_all, get_engine, get_sessionmaker  # noqa: E402
from sins.services import scan_service  # noqa: E402


async def _ensure_database() -> None:
    """Create the DB if it does not exist - tests do not need `createdb`."""
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
    """Create a new client and its API key."""
    return await scan_service.create_tenant(session, "Test Mijoz")


@pytest_asyncio.fixture
async def app():
    return create_app()


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
