"""HTTP API: authentication, ownership gate, scan flow, PDF."""

from __future__ import annotations

import asyncio

from fakes import FakeOrchestrator

from sins.services import scan_service


def _auth(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


async def test_healthz_is_liveness_only(client) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_checks_dependencies(client) -> None:
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["db"] == "ok"


async def test_requires_api_key(client) -> None:
    resp = await client.get("/targets")
    assert resp.status_code == 401


async def test_rejects_wrong_api_key(client) -> None:
    resp = await client.get("/targets", headers=_auth("sins_not-a-real-key"))
    assert resp.status_code == 401


async def test_create_external_target_returns_instructions(client, tenant) -> None:
    _, api_key = tenant
    resp = await client.post("/targets", json={"value": "example.com"}, headers=_auth(api_key))
    assert resp.status_code == 201
    body = resp.json()
    assert body["kind"] == "domain"
    assert body["verified_at"] is None
    assert body["instructions"]["dns_record"] == "_sins-verify.example.com"
    assert body["instructions"]["dns_value"] == body["verify_token"]
    assert "/.well-known/sins-verify-" in body["instructions"]["http_url"]


async def test_create_lab_target_is_verified(client, tenant) -> None:
    _, api_key = tenant
    resp = await client.post(
        "/targets", json={"value": "http://localhost:8099"}, headers=_auth(api_key)
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["verified_at"] is not None
    assert body["instructions"] is None


async def test_invalid_target_returns_422(client, tenant) -> None:
    _, api_key = tenant
    resp = await client.post("/targets", json={"value": "-u evil"}, headers=_auth(api_key))
    assert resp.status_code == 422


async def test_scan_requires_verified_target(client, tenant) -> None:
    _, api_key = tenant
    created = await client.post(
        "/targets", json={"value": "unverified-example.com"}, headers=_auth(api_key)
    )
    target_id = created.json()["id"]

    resp = await client.post("/scans", json={"target_id": target_id}, headers=_auth(api_key))
    assert resp.status_code == 409
    assert "not verified" in resp.json()["detail"].lower()


async def test_scan_flow_and_pdf(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)

    created = await client.post(
        "/targets", json={"value": "http://localhost:8099"}, headers=_auth(api_key)
    )
    target_id = created.json()["id"]

    resp = await client.post("/scans", json={"target_id": target_id}, headers=_auth(api_key))
    assert resp.status_code == 202
    scan_id = resp.json()["id"]
    assert resp.json()["status"] == "pending"

    # Inline worker task (Redis-less mode) - wait for it to finish
    for _ in range(100):
        status_resp = await client.get(f"/scans/{scan_id}", headers=_auth(api_key))
        assert status_resp.status_code == 200
        if status_resp.json()["status"] == "done":
            break
        await asyncio.sleep(0.05)
    else:  # pragma: no cover
        raise AssertionError("scan did not finish")

    body = status_resp.json()
    assert body["progress"] == 100
    assert body["finding_count"] == 3

    findings = await client.get(f"/scans/{scan_id}/findings", headers=_auth(api_key))
    assert findings.status_code == 200
    items = findings.json()["items"]
    assert findings.json()["total"] == 3
    assert items[0]["severity"] == "critical"
    assert items[0]["remediation"]["fixed_version"] == "2.17.1"

    report = await client.get(f"/scans/{scan_id}/report.pdf", headers=_auth(api_key))
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert report.content.startswith(b"%PDF")
    assert len(report.content) > 5000


async def test_pdf_rejected_until_scan_done(monkeypatch, client, tenant) -> None:
    _, api_key = tenant

    async def _never(_scan_id) -> None:  # scan never finishes
        return None

    monkeypatch.setattr(scan_service, "execute_scan", _never)

    created = await client.post(
        "/targets", json={"value": "http://127.0.0.1:8099"}, headers=_auth(api_key)
    )
    scan = await client.post(
        "/scans", json={"target_id": created.json()["id"]}, headers=_auth(api_key)
    )
    scan_id = scan.json()["id"]

    report = await client.get(f"/scans/{scan_id}/report.pdf", headers=_auth(api_key))
    assert report.status_code == 409


async def test_scan_isolation_between_tenants(client, tenant, session) -> None:
    _, api_key = tenant
    other_tenant, other_key = await scan_service.create_tenant(session, "Raqib mijoz")

    created = await client.post(
        "/targets", json={"value": "http://localhost:8100"}, headers=_auth(api_key)
    )
    target_id = created.json()["id"]

    # Another tenant cannot see this target and cannot scan it
    assert (await client.get("/targets", headers=_auth(other_key))).json() == []
    resp = await client.post("/scans", json={"target_id": target_id}, headers=_auth(other_key))
    assert resp.status_code == 404
