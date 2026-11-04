"""FastAPI application.

Run with: `sins serve` or `uvicorn sins.api.main:app`.
Observability: `GET /metrics` (Prometheus), `GET /healthz`, `GET /readyz`.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from ..authz import OwnershipError
from ..config import get_settings
from ..db import get_sessionmaker
from ..middleware import RateLimitMiddleware, RequestContextMiddleware
from ..observability import METRICS, configure_logging
from ..services import scan_service
from ..targets import InvalidTarget
from .routes import scans, targets, tenant

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging()
    app.state.arq = None
    app.state.tasks = set()

    try:
        from arq import create_pool
        from arq.connections import RedisSettings

        app.state.arq = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        log.info("connected to the ARQ queue", extra={"event": "arq.connected"})
    except Exception:  # noqa: BLE001 — Redis may be absent in dev mode
        log.warning(
            "Redis is unavailable — scans run inside the API process (dev mode)",
            extra={"event": "arq.unavailable"},
        )

    try:
        yield
    finally:
        for task in list(app.state.tasks):
            task.cancel()
        if app.state.arq is not None:
            await app.state.arq.aclose()


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(scan_service.NotFound)
    async def _not_found(_: Request, exc: scan_service.NotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(scan_service.VerifyTokenExpired)
    async def _token_expired(_: Request, exc: scan_service.VerifyTokenExpired) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc), "verify_token": exc.token},
        )

    @app.exception_handler(scan_service.TargetNotVerified)
    async def _not_verified(_: Request, exc: scan_service.TargetNotVerified) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(scan_service.ScanBusy)
    async def _busy(_: Request, exc: scan_service.ScanBusy) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(scan_service.NotCancellable)
    async def _not_cancellable(_: Request, exc: scan_service.NotCancellable) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(scan_service.InvalidScanState)
    async def _bad_state(_: Request, exc: scan_service.InvalidScanState) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(scan_service.InvalidEngine)
    async def _bad_engine(_: Request, exc: scan_service.InvalidEngine) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(OwnershipError)
    async def _ownership(_: Request, exc: OwnershipError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(InvalidTarget)
    async def _bad_target(_: Request, exc: InvalidTarget) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(scan_service.ServiceError)
    async def _service(_: Request, exc: scan_service.ServiceError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})


def create_app() -> FastAPI:
    app = FastAPI(
        title="SINS API",
        version="0.2.0",
        description="Attack surface & vulnerability assessment platform",
        lifespan=lifespan,
    )
    # Keep these fields present even if lifespan does not run (tests, ASGI transport).
    app.state.arq = None
    app.state.tasks = set()

    # Order matters: request ID outermost, rate limit next.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(tenant.router)
    _install_error_handlers(app)

    @app.get("/healthz", tags=["system"])
    async def healthz() -> dict[str, str]:
        """Liveness — is the process alive. The DB is not checked (no restart needed)."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["system"])
    async def readyz() -> JSONResponse:
        """Readiness — are all dependencies ready (can we accept traffic)."""
        checks: dict[str, str] = {}

        try:
            async with get_sessionmaker()() as session:
                await session.execute(text("SELECT 1"))
            checks["db"] = "ok"
        except Exception:  # noqa: BLE001
            checks["db"] = "down"

        checks["queue"] = "ok" if app.state.arq is not None else "inline"

        ready = checks["db"] == "ok"
        return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, **checks})

    @app.get("/metrics", response_class=PlainTextResponse, tags=["system"])
    async def metrics() -> PlainTextResponse:
        """Metrics in Prometheus text format."""
        return PlainTextResponse(METRICS.render(), media_type="text/plain; version=0.0.4")

    return app


app = create_app()
