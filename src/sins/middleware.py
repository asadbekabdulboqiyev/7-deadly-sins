"""HTTP middleware: request ID, access log, metrics and rate limiting."""

from __future__ import annotations

import logging
import time

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .config import get_settings
from .observability import (
    METRICS,
    new_request_id,
    sanitize_request_id,
    set_request_id,
)
from .ratelimit import TokenBucketLimiter

access_log = logging.getLogger("sins.access")

# Paths exempt from rate limiting — monitoring and docs.
_EXEMPT_PREFIXES = ("/metrics", "/healthz", "/readyz", "/docs", "/redoc", "/openapi.json")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Request ID, duration and access log for every request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("X-Request-ID")
        rid = sanitize_request_id(incoming) or new_request_id()
        set_request_id(rid)

        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            access_log.exception(
                "request failed",
                extra={
                    "event": "http.request",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration_ms": elapsed_ms,
                },
            )
            METRICS.inc(
                "sins_http_requests_total",
                {"method": request.method, "path": _route_label(request), "status": "500"},
            )
            METRICS.observe("sins_http_request_duration_ms", elapsed_ms, {"method": request.method})
            raise
        else:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            response.headers["X-Request-ID"] = rid
            access_log.info(
                "http",
                extra={
                    "event": "http.request",
                    "method": request.method,
                    "path": _route_label(request),
                    "status_code": status_code,
                    "duration_ms": elapsed_ms,
                },
            )
            METRICS.inc(
                "sins_http_requests_total",
                {
                    "method": request.method,
                    "path": _route_label(request),
                    "status": str(status_code),
                },
            )
            METRICS.observe("sins_http_request_duration_ms", elapsed_ms, {"method": request.method})
            return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Limits requests per key/IP (default: 600/minute)."""

    def __init__(self, app, limiter: TokenBucketLimiter | None = None) -> None:  # noqa: ANN001
        super().__init__(app)
        settings = get_settings()
        self.enabled = settings.rate_limit_enabled
        self.limiter = limiter or TokenBucketLimiter(settings.rate_limit_per_minute)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.enabled or request.url.path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)

        key = TokenBucketLimiter.key_for(
            request.headers.get("X-API-Key"),
            request.client.host if request.client else None,
        )
        allowed, retry_after = await self.limiter.acquire(key)
        if not allowed:
            METRICS.inc("sins_rate_limited_total", {"path": _route_label(request)})
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Request limit exceeded. Please retry later.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
            )
        return await call_next(request)


def _route_label(request: Request) -> str:
    """Low-cardinality label for metrics — the `/{id}` template."""
    route = request.scope.get("route")
    path_format = getattr(route, "path_format", None)
    if isinstance(path_format, str):
        return path_format
    return request.url.path
