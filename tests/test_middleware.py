"""HTTP middleware: request ID, access metrikalari, rate limit."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

import sins.middleware as middleware
from sins.observability import METRICS


@pytest.fixture(autouse=True)
def _reset_metrics():
    METRICS.reset()
    yield
    METRICS.reset()


def _settings(**overrides) -> SimpleNamespace:
    base = {
        "rate_limit_enabled": True,
        "rate_limit_per_minute": 60,
        "database_url": "postgresql+asyncpg://x/y",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _limited_app(monkeypatch, *, capacity: int = 1) -> FastAPI:
    """Rate limit yoqilgan minimal ilova — DB talab qilmaydi."""
    monkeypatch.setattr(
        middleware,
        "get_settings",
        lambda: _settings(rate_limit_per_minute=capacity),
    )

    app = FastAPI()
    app.add_middleware(middleware.RateLimitMiddleware, limiter=None)
    app.add_middleware(middleware.RequestContextMiddleware)

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("portlash")

    return app


@pytest_asyncio.fixture
async def limited_client(monkeypatch):
    app = _limited_app(monkeypatch, capacity=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


@pytest.fixture
def app_client_factory(monkeypatch):
    def _make(capacity: int = 1) -> httpx.AsyncClient:
        app = _limited_app(monkeypatch, capacity=capacity)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    return _make


async def test_request_id_is_echoed(client) -> None:
    resp = await client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert resp.headers["X-Request-ID"] == "abc-123"


async def test_request_id_is_generated_when_absent(client) -> None:
    resp = await client.get("/healthz")
    assert len(resp.headers["X-Request-ID"]) == 16


async def test_request_id_header_is_sanitized(client) -> None:
    resp = await client.get("/healthz", headers={"X-Request-ID": 'ab"c<script>'})
    assert resp.headers["X-Request-ID"] == "abcscript"


async def test_metrics_are_recorded_per_route(client) -> None:
    await client.get("/healthz")
    rendered = METRICS.render()

    assert 'sins_http_requests_total{method="GET",path="/healthz",status="200"} 1' in rendered
    assert "sins_http_request_duration_ms_count" in rendered


async def test_metrics_endpoint_returns_prometheus_text(client) -> None:
    await client.get("/healthz")
    resp = await client.get("/metrics")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "# TYPE sins_http_requests_total counter" in resp.text


async def test_readyz_reports_db_and_queue(client) -> None:
    resp = await client.get("/readyz")
    body = resp.json()

    assert set(body) == {"ready", "db", "queue"}
    assert body["queue"] == "inline"


async def test_rate_limit_blocks_second_request(limited_client) -> None:
    first = await limited_client.get("/ping")
    second = await limited_client.get("/ping")

    assert first.status_code == 200
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) >= 1
    assert second.json()["retry_after_seconds"] > 0


async def test_rate_limited_metric_is_counted(limited_client) -> None:
    await limited_client.get("/ping")
    await limited_client.get("/ping")

    assert 'sins_rate_limited_total{path="/ping"} 1' in METRICS.render()


async def test_exempt_paths_are_not_rate_limited(limited_client) -> None:
    for _ in range(3):
        resp = await limited_client.get("/healthz")
        assert resp.status_code == 200


async def test_server_error_is_logged_and_raised(limited_client) -> None:
    with pytest.raises(RuntimeError, match="portlash"):
        await limited_client.get("/boom")

    assert 'sins_http_requests_total{method="GET",path="/boom",status="500"} 1' in METRICS.render()


async def test_different_keys_have_independent_budgets(app_client_factory) -> None:
    async with app_client_factory(capacity=1) as c:
        first = await c.get("/ping", headers={"X-API-Key": "sins_a"})
        second = await c.get("/ping", headers={"X-API-Key": "sins_b"})
        third = await c.get("/ping", headers={"X-API-Key": "sins_a"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_route_label_falls_back_to_path_without_route_match() -> None:
    from starlette.requests import Request

    from sins.middleware import _route_label

    request = Request({"type": "http", "path": "/targets/1234", "headers": []})
    assert _route_label(request) == "/targets/1234"


def test_route_label_uses_path_template_when_matched() -> None:
    from starlette.requests import Request

    from sins.middleware import _route_label

    class _Route:
        path_format = "/targets/{target_id}"

    request = Request({"type": "http", "path": "/targets/1234", "headers": [], "route": _Route()})
    assert _route_label(request) == "/targets/{target_id}"
