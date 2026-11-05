"""Live-demo guarantees: offline lab mode, CORS, SSE progress, auth.

These are the behaviours a judge actually sees on demo day, so each one is
pinned by a test:

* a lab target must make **zero** outbound calls (no 8 s intel timeout),
* the browser must be allowed to call the API (CORS preflight),
* progress must arrive over SSE and terminate cleanly,
* the SSE query-string fallback must still require a valid key.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
import pytest_asyncio
from fakes import FakeOrchestrator
from sqlalchemy import update

from sins.intel.models import ThreatIntel
from sins.models import Scan, Target
from sins.services import scan_service

ORIGIN = "http://localhost:5173"


@pytest_asyncio.fixture(autouse=True)
async def _drain_inline_scans(app):
    """Let the in-process scan task release its DB connection before teardown.

    httpx's ASGITransport does not run the app lifespan, so nothing cancels
    `app.state.tasks`. A task still finishing its commit when the event loop
    closes leaves a checked-out asyncpg connection behind and pytest prints
    "Event loop is closed" noise after a green run.
    """
    yield
    for task in list(getattr(app.state, "tasks", ())):
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    # One scheduler turn: a task that finished between the poll and teardown
    # returns its connection in its own `finally` block.
    await asyncio.sleep(0)


def _auth(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


async def _finished_scan(client, api_key: str) -> str:
    """Create a lab target, run a fake scan inline, return the scan id."""
    created = await client.post(
        "/targets", json={"value": "http://localhost:8099"}, headers=_auth(api_key)
    )
    assert created.status_code == 201
    resp = await client.post(
        "/scans", json={"target_id": created.json()["id"]}, headers=_auth(api_key)
    )
    assert resp.status_code == 202
    scan_id = resp.json()["id"]

    for _ in range(100):
        status_resp = await client.get(f"/scans/{scan_id}", headers=_auth(api_key))
        if status_resp.json()["status"] == "done":
            return scan_id
        await asyncio.sleep(0.05)
    raise AssertionError("scan did not finish")


# --------------------------------------------------------------------------
# 1. Lab mode is fully offline
# --------------------------------------------------------------------------


async def test_lab_target_never_calls_threat_intel(monkeypatch, client, tenant) -> None:
    """A demo PDF must not wait on KEV/EPSS — no network is touched at all."""
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)

    async def _forbidden(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("lab target reached the public internet")

    monkeypatch.setattr(scan_service, "enrich", _forbidden)
    monkeypatch.setattr(scan_service.get_settings(), "threat_intel_enabled", True)

    scan_id = await _finished_scan(client, api_key)
    report = await client.get(f"/scans/{scan_id}/report.pdf", headers=_auth(api_key))

    assert report.status_code == 200
    assert report.content.startswith(b"%PDF")


async def test_non_lab_target_does_enrich(monkeypatch, client, tenant, session) -> None:
    """Symmetry check: the opt-out is scoped to lab targets only."""
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)

    seen: dict[str, list[str]] = {}

    async def _fake_enrich(cves, **kwargs):
        seen["cves"] = list(cves)
        return ThreatIntel(kev_available=True)

    monkeypatch.setattr(scan_service, "enrich", _fake_enrich)
    monkeypatch.setattr(scan_service.get_settings(), "threat_intel_enabled", True)

    scan_id = await _finished_scan(client, api_key)
    # Turn the lab target into a public one; only the value drives the branch.
    await session.execute(
        update(Target)
        .where(Target.id == (await session.get(Scan, scan_id)).target_id)
        .values(value="example.com")
    )
    await session.commit()

    report = await client.get(f"/scans/{scan_id}/report.pdf", headers=_auth(api_key))

    assert report.status_code == 200
    assert "CVE-2021-44228" in seen.get("cves", [])


# --------------------------------------------------------------------------
# 2. CORS: the site must be able to talk to the API
# --------------------------------------------------------------------------


async def test_cors_preflight_allows_the_site_origin(client) -> None:
    resp = await client.options(
        "/scans",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == ORIGIN
    allowed = resp.headers["access-control-allow-headers"].lower()
    assert "x-api-key" in allowed


async def test_cors_exposes_pdf_filename_to_javascript(client, tenant) -> None:
    _, api_key = tenant

    resp = await client.get("/targets", headers={**_auth(api_key), "Origin": ORIGIN})

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == ORIGIN
    assert "content-disposition" in resp.headers["access-control-expose-headers"].lower()


async def test_unknown_origin_gets_no_cors_header(client, tenant) -> None:
    _, api_key = tenant

    resp = await client.get(
        "/targets", headers={**_auth(api_key), "Origin": "https://evil.example"}
    )

    assert "access-control-allow-origin" not in resp.headers


# --------------------------------------------------------------------------
# 3. SSE progress
# --------------------------------------------------------------------------


async def test_sse_stream_delivers_progress_then_end(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan_id = await _finished_scan(client, api_key)

    events: list[str] = []
    async with client.stream(
        "GET", f"/scans/{scan_id}/events", params={"api_key": api_key}
    ) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers["x-accel-buffering"] == "no"
        async for line in resp.aiter_lines():
            if line.startswith("event:"):
                events.append(line.removeprefix("event:").strip())
            if events and events[-1] == "end":
                break

    assert events[0] == "progress"
    assert events[-1] == "end"


async def test_sse_rejects_missing_key(client, tenant) -> None:
    _, api_key = tenant
    created = await client.post(
        "/targets", json={"value": "http://localhost:8099"}, headers=_auth(api_key)
    )
    scan = await client.post(
        "/scans", json={"target_id": created.json()["id"]}, headers=_auth(api_key)
    )

    resp = await client.get(f"/scans/{scan.json()['id']}/events")

    assert resp.status_code == 401


async def test_sse_rejects_wrong_key(client, tenant) -> None:
    _, api_key = tenant
    created = await client.post(
        "/targets", json={"value": "http://localhost:8099"}, headers=_auth(api_key)
    )
    scan = await client.post(
        "/scans", json={"target_id": created.json()["id"]}, headers=_auth(api_key)
    )

    resp = await client.get(f"/scans/{scan.json()['id']}/events", params={"api_key": "sins_wrong"})

    assert resp.status_code == 401


@pytest.mark.parametrize("path", ["/scans/{id}/events", "/scans/{id}/report.pdf"])
async def test_live_endpoints_are_tenant_scoped(monkeypatch, client, tenant, session, path) -> None:
    """Another tenant's scan must look like it does not exist."""
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan_id = await _finished_scan(client, api_key)

    _, other_key = await scan_service.create_tenant(session, "Raqib mijoz")
    resp = await client.get(
        path.format(id=scan_id), headers=_auth(other_key), params={"api_key": other_key}
    )

    assert resp.status_code == 404
