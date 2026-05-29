"""Tests for the bulk-mitigation API (EPIC-3 UC-3.3)."""

from __future__ import annotations

from httpx import AsyncClient

from tests.helpers import auth_header


async def test_mitigation_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/mitigation", json={"iocs": [{"type": "ip", "value": "45.83.12.7"}]}
    )
    assert resp.status_code in (401, 403)


async def test_mitigation_blocks_public_ip(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/mitigation",
        json={"iocs": [{"type": "ip", "value": "45.83.12.7"}]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["mock_mode"] is True
    plan = out["plan"]
    assert plan["block_count"] == 1
    a = plan["actions"][0]
    assert a["decision"] == "block"
    assert a["tool"] == "panorama"
    assert a["destructive"] is True
    assert a["requires_approval"] is True
    assert "45.83.12.7" in (a["rollback"] or "")


async def test_mitigation_allowlists_private_ip(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/mitigation",
        json={"iocs": [{"type": "ip", "value": "10.1.2.3"}]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()["plan"]
    assert plan["block_count"] == 0
    assert plan["actions"][0]["decision"] == "skip_allowlisted"


async def test_mitigation_mixed_batch_aggregates(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/mitigation",
        json={
            "iocs": [
                {"type": "ip", "value": "45.83.12.7"},
                {"type": "domain", "value": "evil.example"},
                {"type": "ip", "value": "8.8.8.8"},  # allowlisted resolver
                {"type": "cve", "value": "CVE-2024-1"},  # unsupported
            ]
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()["plan"]
    assert plan["block_count"] == 2
    assert plan["skip_count"] == 2
    assert set(plan["tools"]) == {"panorama", "umbrella"}


async def test_mitigation_rejects_bad_ioc_type(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/mitigation",
        json={"iocs": [{"type": "not_a_type", "value": "x"}]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 422
