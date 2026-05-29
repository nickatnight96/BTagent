"""Tests for the response-plan API (EPIC-3 UC-3.2)."""

from __future__ import annotations

from httpx import AsyncClient

from tests.helpers import auth_header


async def test_response_plan_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/response-plan", json={"typed_intent": "malware_detected"})
    assert resp.status_code in (401, 403)


async def test_response_plan_malware_isolates_host(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/response-plan",
        json={
            "typed_intent": "malware_detected",
            "severity": "critical",
            "entities": {"host": ["WS-12"]},
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["mock_mode"] is True
    plan = out["plan"]
    assert plan["estimated_containment_minutes"] == 5
    assert "5 minutes" in plan["strategic_goal"]
    steps = plan["tactical_steps"]
    types = {s["action_type"] for s in steps}
    assert "isolate_host" in types
    assert "open_ticket" in types
    isolate = next(s for s in steps if s["action_type"] == "isolate_host")
    assert isolate["target"] == "WS-12"
    assert isolate["destructive"] is True
    assert isolate["requires_approval"] is True
    assert isolate["rollback"] and "WS-12" in isolate["rollback"]


async def test_response_plan_c2_fans_out_block_ips(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/response-plan",
        json={
            "typed_intent": "c2_beaconing",
            "entities": {"ip": ["1.1.1.1", "2.2.2.2"], "host": ["h1"]},
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    steps = resp.json()["plan"]["tactical_steps"]
    block_targets = {s["target"] for s in steps if s["action_type"] == "block_ip"}
    assert block_targets == {"1.1.1.1", "2.2.2.2"}


async def test_response_plan_benign_has_no_destructive_step(
    client: AsyncClient, analyst_token: str
):
    resp = await client.post(
        "/api/v1/response-plan",
        json={"typed_intent": "benign"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    steps = resp.json()["plan"]["tactical_steps"]
    assert all(s["destructive"] is False for s in steps)
    assert all(s["category"] != "contain" for s in steps)


async def test_response_plan_rejects_unknown_intent(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/response-plan",
        json={"typed_intent": "not_a_real_intent"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 422
