"""Tests for the workflow run resume API (Phase-4 follow-up #1)."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from tests.helpers import auth_header

# trigger.manual -> crowdstrike.isolate_host. isolate_host is an integration
# node with manifest hitl_required=True AND maps to host_isolation (L1) in the
# HITL autonomy table, so a default L2 run pauses at it. Mock connectors are
# on by default, so once approved the node succeeds.
PAUSING_DEF: dict[str, Any] = {
    "name": "pause-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "iso",
            "node_id": "integration.crowdstrike.isolate_host",
            "name": "isolate",
            "config": {"hostname": "WS-1"},
        },
    ],
    "edges": [{"source": "t1", "target": "iso", "label": "next"}],
}


async def _seed(client: AsyncClient, admin_token: str, definition: dict) -> str:
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "wf", "description": "", "definition": definition},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _run(client: AsyncClient, token: str, wf_id: str) -> dict:
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {}},
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_run_pauses_and_records_paused_node(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    wf_id = await _seed(client, admin_token, PAUSING_DEF)
    run = await _run(client, analyst_token, wf_id)
    assert run["status"] == "paused"
    assert run["paused_node_id"] == "iso"
    assert run["nodes_executed"] == ["t1"]  # trigger ran, isolate paused before exec
    assert run["approved_steps"] == []


async def test_resume_requires_hitl_approve(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    """Analysts can run but not approve — resume needs hitl:approve (senior)."""
    wf_id = await _seed(client, admin_token, PAUSING_DEF)
    run = await _run(client, analyst_token, wf_id)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403, resp.text


async def test_resume_approves_gate_and_completes(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    wf_id = await _seed(client, admin_token, PAUSING_DEF)
    run = await _run(client, analyst_token, wf_id)
    assert run["status"] == "paused"

    # admin holds hitl:approve (>= senior_analyst).
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text
    resumed = resp.json()
    assert resumed["id"] == run["id"]  # same row, updated in place
    assert resumed["status"] == "succeeded"
    assert resumed["nodes_executed"] == ["t1", "iso"]
    assert resumed["approved_steps"] == ["iso"]
    assert resumed["paused_node_id"] is None
    assert resumed["error"] is None
    # The reused trigger + the now-approved isolate both produced evidence.
    assert len(resumed["evidence_chain"]) >= 1


async def test_resume_non_paused_run_is_409(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    wf_id = await _seed(client, admin_token, PAUSING_DEF)
    run = await _run(client, analyst_token, wf_id)
    # First resume completes the run.
    first = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "succeeded"
    # Second resume on a now-succeeded run -> 409.
    second = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert second.status_code == 409, second.text


async def test_resume_unknown_run_is_404(client: AsyncClient, admin_token: str):
    wf_id = await _seed(client, admin_token, PAUSING_DEF)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/wfrun_nope/resume",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404
