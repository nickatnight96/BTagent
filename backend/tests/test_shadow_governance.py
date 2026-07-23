"""Tests for the shadow-agent governance registry (#121/#117 Phase C).

Shadow findings (evidence ``shadow_workload=True``) route to governance:
an analyst registers (sanction) or sunsets (decommission) the workload.
One registry row per (org, resource); re-governing updates in place.
"""

from __future__ import annotations

from httpx import AsyncClient

from tests.helpers import auth_header


def _shadow_finding_body(**overrides) -> dict:
    body = {
        "source": "agentic",
        "domain": "agentic",
        "title": "Shadow agentic workload: mcp-shadow",
        "description": "Untagged Cloud Run MCP server",
        "severity": "high",
        "confidence": 0.88,
        "technique_ids": ["T1580"],
        "entities": [{"kind": "agentic_workload", "value": "projects/demo/services/mcp-shadow"}],
        "observables": [
            {"type": "cloud_resource_id", "value": "projects/demo/services/mcp-shadow"}
        ],
        "evidence": {
            "detection": "shadow_agent_workload",
            "shadow_workload": True,
            "kind": "cloud_run_mcp",
            "identity_ref": "shadow-mcp-sa@demo.iam.gserviceaccount.com",
        },
    }
    body.update(overrides)
    return body


async def _create_finding(client: AsyncClient, token: str, body: dict) -> str:
    resp = await client.post("/api/v1/hunt/findings", json=body, headers=auth_header(token))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_govern_registers_then_sunsets_without_duplicating(
    client: AsyncClient, analyst_token: str, admin_token: str
):
    finding_id = await _create_finding(client, analyst_token, _shadow_finding_body())

    reg = await client.post(
        f"/api/v1/hunt/findings/{finding_id}/govern",
        json={"action": "register", "rationale": "Sanctioned by platform team"},
        headers=auth_header(admin_token),
    )
    assert reg.status_code == 200, reg.text
    entry = reg.json()
    assert entry["status"] == "registered"
    assert entry["resource_key"] == "projects/demo/services/mcp-shadow"
    assert entry["kind"] == "cloud_run_mcp"
    assert entry["source_finding_id"] == finding_id
    assert entry["rationale"] == "Sanctioned by platform team"

    # Registry lists the ruling.
    listing = await client.get("/api/v1/hunt/governance", headers=auth_header(analyst_token))
    assert listing.status_code == 200, listing.text
    assert listing.json()["total"] == 1

    # Re-governing the same resource flips the ruling in place.
    second_finding = await _create_finding(client, analyst_token, _shadow_finding_body())
    sunset = await client.post(
        f"/api/v1/hunt/findings/{second_finding}/govern",
        json={"action": "sunset", "rationale": "Decommission by Q4"},
        headers=auth_header(admin_token),
    )
    assert sunset.status_code == 200, sunset.text
    assert sunset.json()["id"] == entry["id"]  # same registry row
    assert sunset.json()["status"] == "sunset"
    assert sunset.json()["source_finding_id"] == second_finding

    listing = await client.get("/api/v1/hunt/governance", headers=auth_header(analyst_token))
    assert listing.json()["total"] == 1
    only = listing.json()["items"][0]
    assert only["status"] == "sunset"

    # Status filter.
    registered = await client.get(
        "/api/v1/hunt/governance?status=registered", headers=auth_header(analyst_token)
    )
    assert registered.json()["total"] == 0


async def test_govern_rejects_non_shadow_finding(
    client: AsyncClient, analyst_token: str, admin_token: str
):
    finding_id = await _create_finding(
        client,
        analyst_token,
        _shadow_finding_body(
            title="Prompt injection detected",
            evidence={"detection": "prompt_injection"},
            observables=[],
            entities=[{"kind": "agent_call_event", "value": "evt_1"}],
        ),
    )
    resp = await client.post(
        f"/api/v1/hunt/findings/{finding_id}/govern",
        json={"action": "register"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422
    assert "shadow_workload" in resp.json()["detail"]


async def test_govern_404_on_unknown_finding(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/hunt/findings/hfnd_DOESNOTEXIST/govern",
        json={"action": "register"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


async def test_govern_requires_senior_permission(client: AsyncClient, analyst_token: str):
    """Plain analysts lack hunt:suppress — governance is a senior ruling."""
    finding_id = await _create_finding(client, analyst_token, _shadow_finding_body())
    resp = await client.post(
        f"/api/v1/hunt/findings/{finding_id}/govern",
        json={"action": "register"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403


async def test_governance_routes_require_auth(client: AsyncClient):
    assert (
        await client.post("/api/v1/hunt/findings/hfnd_x/govern", json={"action": "register"})
    ).status_code in (401, 403)
    assert (await client.get("/api/v1/hunt/governance")).status_code in (401, 403)
