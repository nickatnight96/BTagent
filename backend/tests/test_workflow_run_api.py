"""Tests for the workflow execution + run-history API (Phase 2 run API)."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from tests.helpers import auth_header

# A minimal one-node workflow: a manual trigger that echoes its payload.
# ``trigger.manual`` is registered by the engine triggers package, which the
# run service imports. Single node, no edges -> it is the sole entry + leaf.
ECHO_DEF: dict[str, Any] = {
    "name": "echo-wf",
    "version": "1.0",
    "description": "echo trigger payload",
    "trigger": {},
    "nodes": [{"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}}],
    "edges": [],
}

# References a node id that isn't registered in the backend process -> the
# executor fails closed with reason="not registered".
BAD_NODE_DEF: dict[str, Any] = {
    "name": "bad-wf",
    "version": "1.0",
    "nodes": [
        {"step_id": "s1", "node_id": "integration.does.not.exist", "name": "x", "config": {}}
    ],
    "edges": [],
}


async def _create_workflow(client: AsyncClient, admin_token: str, definition: dict) -> str:
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "wf", "description": "", "definition": definition},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_run_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/workflows/wf_x/versions/1/run", json={"trigger_payload": {}})
    assert resp.status_code in (401, 403)


async def test_run_executes_single_node(client: AsyncClient, admin_token: str, analyst_token: str):
    wf_id = await _create_workflow(client, admin_token, ECHO_DEF)
    # Analyst (workflow:run) executes version 1.
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {"payload": {"foo": "bar"}}},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "succeeded"
    assert run["nodes_executed"] == ["t1"]
    assert run["final_output"] == {"payload": {"foo": "bar"}}
    assert run["error"] is None
    assert run["triggered_by"]


async def test_run_records_failure_for_unregistered_node(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    wf_id = await _create_workflow(client, admin_token, BAD_NODE_DEF)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {}},
        headers=auth_header(analyst_token),
    )
    # A failed *execution* is still a recorded run (201), not a 5xx.
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "failed"
    assert "not registered" in (run["error"] or "")


async def test_run_empty_definition_is_422(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    # Default create stores an empty ``{}`` definition (no name/nodes) -> not
    # a runnable graph.
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "empty", "description": ""},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    wf_id = resp.json()["id"]
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {}},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 422, resp.text


async def test_list_and_get_run(client: AsyncClient, admin_token: str, analyst_token: str):
    wf_id = await _create_workflow(client, admin_token, ECHO_DEF)
    run_resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {"payload": {"a": 1}}},
        headers=auth_header(analyst_token),
    )
    run_id = run_resp.json()["id"]

    list_resp = await client.get(
        f"/api/v1/workflows/{wf_id}/runs", headers=auth_header(analyst_token)
    )
    assert list_resp.status_code == 200, list_resp.text
    listing = list_resp.json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == run_id

    get_resp = await client.get(
        f"/api/v1/workflows/{wf_id}/runs/{run_id}", headers=auth_header(analyst_token)
    )
    assert get_resp.status_code == 200, get_resp.text
    assert get_resp.json()["status"] == "succeeded"


async def test_get_run_unknown_is_404(client: AsyncClient, admin_token: str, analyst_token: str):
    wf_id = await _create_workflow(client, admin_token, ECHO_DEF)
    resp = await client.get(
        f"/api/v1/workflows/{wf_id}/runs/wfrun_nope", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404
