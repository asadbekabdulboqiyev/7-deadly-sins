"""API qo'shimchalari: idempotentlik, sahifalash, bekor qilish, diff, tenant, metrika."""

from __future__ import annotations

import asyncio

from fakes import FakeOrchestrator

from sins.services import scan_service

LOCAL = "http://localhost:8099"


def _auth(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


async def _target(client, api_key: str, value: str = LOCAL) -> str:
    resp = await client.post("/targets", json={"value": value}, headers=_auth(api_key))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _wait_done(client, api_key: str, scan_id: str) -> dict:
    for _ in range(200):
        resp = await client.get(f"/scans/{scan_id}", headers=_auth(api_key))
        assert resp.status_code == 200
        if resp.json()["status"] in {"done", "failed"}:
            return resp.json()
        await asyncio.sleep(0.02)
    raise AssertionError("skan tugamadi")  # pragma: no cover


async def _done_scan(client, api_key: str, value: str = LOCAL) -> dict:
    target_id = await _target(client, api_key, value)
    created = await client.post("/scans", json={"target_id": target_id}, headers=_auth(api_key))
    assert created.status_code == 202, created.text
    return await _wait_done(client, api_key, created.json()["id"])


def _stall(monkeypatch) -> None:
    """Inline bajarishni to'xtatadi — skan `pending` holatida qoladi."""

    async def _never(_scan_id) -> None:
        return None

    monkeypatch.setattr(scan_service, "execute_scan", _never)


# ---------------------------------------------------------------------------
# Idempotentlik
# ---------------------------------------------------------------------------


async def test_idempotency_key_reuses_scan(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    _stall(monkeypatch)
    target_id = await _target(client, api_key)
    headers = {**_auth(api_key), "Idempotency-Key": "req-42"}

    first = await client.post("/scans", json={"target_id": target_id}, headers=headers)
    second = await client.post("/scans", json={"target_id": target_id}, headers=headers)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["id"] == second.json()["id"]

    listed = await client.get("/scans", headers=_auth(api_key))
    assert len(listed.json()) == 1


async def test_different_idempotency_keys_create_separate_scans(
    monkeypatch, client, tenant
) -> None:
    _, api_key = tenant
    _stall(monkeypatch)
    first_target = await _target(client, api_key, "http://localhost:8091")
    second_target = await _target(client, api_key, "http://localhost:8092")

    first = await client.post(
        "/scans",
        json={"target_id": first_target},
        headers={**_auth(api_key), "Idempotency-Key": "a"},
    )
    second = await client.post(
        "/scans",
        json={"target_id": second_target},
        headers={**_auth(api_key), "Idempotency-Key": "b"},
    )

    assert first.json()["id"] != second.json()["id"]
    assert len((await client.get("/scans", headers=_auth(api_key))).json()) == 2


# ---------------------------------------------------------------------------
# Topilmalar: sahifalash, filtrlar, sonlar
# ---------------------------------------------------------------------------


async def test_findings_pagination_and_counts(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan = await _done_scan(client, api_key)

    page = await client.get(
        f"/scans/{scan['id']}/findings?limit=2&offset=0", headers=_auth(api_key)
    )
    assert page.status_code == 200
    body = page.json()
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["has_more"] is True
    assert len(body["items"]) == 2
    assert body["items"][0]["severity"] == "critical"
    assert body["severity_counts"] == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }

    tail = await client.get(
        f"/scans/{scan['id']}/findings?limit=2&offset=2", headers=_auth(api_key)
    )
    assert tail.json()["has_more"] is False
    assert len(tail.json()["items"]) == 1


async def test_findings_filter_by_severity(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan = await _done_scan(client, api_key, "http://localhost:8093")

    resp = await client.get(
        f"/scans/{scan['id']}/findings?severity=critical,high", headers=_auth(api_key)
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 2
    assert {item["severity"] for item in resp.json()["items"]} == {"critical", "high"}


async def test_findings_filter_by_engine(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan = await _done_scan(client, api_key, "http://localhost:8094")

    resp = await client.get(f"/scans/{scan['id']}/findings?engine=osv", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["source_tools"] == ["osv"]


async def test_findings_reject_zero_limit(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan = await _done_scan(client, api_key, "http://localhost:8095")

    resp = await client.get(f"/scans/{scan['id']}/findings?limit=0", headers=_auth(api_key))
    assert resp.status_code == 422


async def test_scans_reject_zero_limit(client, tenant) -> None:
    _, api_key = tenant
    assert (await client.get("/scans?limit=0", headers=_auth(api_key))).status_code == 422


# ---------------------------------------------------------------------------
# Skanlar ro'yxati: filtr va sahifalash
# ---------------------------------------------------------------------------


async def test_scans_status_filter(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    await _done_scan(client, api_key, "http://localhost:8096")

    done = await client.get("/scans?status=done", headers=_auth(api_key))
    failed = await client.get("/scans?status=failed", headers=_auth(api_key))

    assert [row["status"] for row in done.json()] == ["done"]
    assert failed.json() == []


async def test_scans_pagination(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    await _done_scan(client, api_key, "http://localhost:8097")
    await _done_scan(client, api_key, "http://localhost:8098")

    first = await client.get("/scans?limit=1&offset=0", headers=_auth(api_key))
    second = await client.get("/scans?limit=1&offset=1", headers=_auth(api_key))

    assert len(first.json()) == 1
    assert len(second.json()) == 1
    assert first.json()[0]["id"] != second.json()[0]["id"]


# ---------------------------------------------------------------------------
# Bekor qilish va diff
# ---------------------------------------------------------------------------


async def test_cancel_scan_then_second_cancel_conflicts(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    _stall(monkeypatch)
    target_id = await _target(client, api_key, "http://localhost:8090")
    created = await client.post("/scans", json={"target_id": target_id}, headers=_auth(api_key))
    scan_id = created.json()["id"]

    first = await client.post(f"/scans/{scan_id}/cancel", headers=_auth(api_key))
    assert first.status_code == 200
    assert first.json()["status"] == "cancelled"

    second = await client.post(f"/scans/{scan_id}/cancel", headers=_auth(api_key))
    assert second.status_code == 409


async def test_diff_without_baseline(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    scan = await _done_scan(client, api_key, "http://localhost:8089")

    resp = await client.get(f"/scans/{scan['id']}/diff", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["baseline"] is False
    assert body["against_scan_id"] is None
    assert len(body["new"]) == 3
    assert body["resolved"] == []
    assert body["persisting"] == 0


async def test_diff_against_previous_scan(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    first = await _done_scan(client, api_key, "http://localhost:8088")
    second = await _done_scan(client, api_key, "http://localhost:8088")

    resp = await client.get(f"/scans/{second['id']}/diff", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["baseline"] is True
    assert body["against_scan_id"] == first["id"]
    assert body["new"] == []
    assert body["resolved"] == []
    assert body["persisting"] == 3


async def test_diff_requires_done_scan(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    _stall(monkeypatch)
    target_id = await _target(client, api_key, "http://localhost:8087")
    created = await client.post("/scans", json={"target_id": target_id}, headers=_auth(api_key))

    resp = await client.get(f"/scans/{created.json()['id']}/diff", headers=_auth(api_key))
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------


async def test_tenant_me_returns_profile_without_secret(client, tenant) -> None:
    owner, api_key = tenant

    resp = await client.get("/tenant/me", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(owner.id)
    assert body["name"] == "Test Mijoz"
    assert body["api_key_prefix"].startswith("sins_")
    assert "api_key" not in body


async def test_rotate_key_invalidates_old_one(client, tenant) -> None:
    _, old_key = tenant

    rotated = await client.post("/tenant/rotate-key", headers=_auth(old_key))
    assert rotated.status_code == 200
    body = rotated.json()
    new_key = body["api_key"]
    assert new_key != old_key
    assert new_key.startswith(body["api_key_prefix"])
    assert len(body["api_key_prefix"]) == 12
    assert "warning" in body

    assert (await client.get("/targets", headers=_auth(old_key))).status_code == 401
    assert (await client.get("/targets", headers=_auth(new_key))).status_code == 200


# ---------------------------------------------------------------------------
# Metrika
# ---------------------------------------------------------------------------


async def test_metrics_endpoint_exposes_scan_counters(monkeypatch, client, tenant) -> None:
    _, api_key = tenant
    monkeypatch.setattr(scan_service, "SinsOrchestrator", FakeOrchestrator)
    await _done_scan(client, api_key, "http://localhost:8086")

    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "# TYPE sins_http_requests_total counter" in resp.text
    assert "sins_scans_started_total" in resp.text
    assert 'sins_scans_finished_total{status="done"}' in resp.text
