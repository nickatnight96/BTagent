"""Tests for investigation ``autonomy_level`` inheritance (Phase-4 follow-up).

Two surfaces:

* Investigations API — ``autonomy_level`` on create, permission-gated for
  L3/L4 (reduced oversight requires ``hitl:approve``, the same permission
  that approves the gates those levels skip).
* Workflow runs — a run launched from an investigation executes under that
  investigation's autonomy posture; the posture is snapshotted on the run
  row (``agent_autonomy``) so resumes re-execute under it rather than the
  old hardcoded L2 default.

The behavioural probe is ``integration.splunk.search``: its manifest has
``hitl_required=False`` and it maps to ``siem_query`` (L3) in the HITL
autonomy table, so it pauses **only** under an L0 agent — a pause at the
splunk step is direct evidence the investigation's L0 posture reached the
middleware chain.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow
from tests.helpers import auth_header


async def _make_investigation(
    db_session: AsyncSession,
    *,
    owner_id: str,
    autonomy_level: str = "L2",
    tlp_level: str = "green",
    org_id: str = DEFAULT_ORG_ID,
) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title=f"autonomy-binding test ({autonomy_level})",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level=tlp_level,
        autonomy_level=autonomy_level,
        assigned_to=owner_id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    return inv


# trigger -> splunk.search. hitl_required=False + siem_query=L3, so the HITL
# middleware pauses it only when the agent posture is L0.
SPLUNK_DEF: dict[str, Any] = {
    "name": "splunk-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "s1",
            "node_id": "integration.splunk.search",
            "name": "search",
            "config": {"query": "index=authentication action=failure"},
        },
    ],
    "edges": [{"source": "t1", "target": "s1", "label": "next"}],
}

# Two sequential searches: under L0 every integration step pauses, so a
# resume that approves s1 must pause AGAIN at s2 — proving the resume
# re-executed under the snapshotted L0 posture, not the legacy L2 default
# (which would sail straight through s2).
SPLUNK_TWO_STEP_DEF: dict[str, Any] = {
    "name": "splunk-two-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "s1",
            "node_id": "integration.splunk.search",
            "name": "search-1",
            "config": {"query": "index=authentication action=failure"},
        },
        {
            "step_id": "s2",
            "node_id": "integration.splunk.search",
            "name": "search-2",
            "config": {"query": "index=network"},
        },
    ],
    "edges": [
        {"source": "t1", "target": "s1", "label": "next"},
        {"source": "s1", "target": "s2", "label": "next"},
    ],
}


async def _seed_workflow(client: AsyncClient, admin_token: str, definition: dict) -> str:
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "wf", "description": "", "definition": definition},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _launch(
    client: AsyncClient, token: str, wf_id: str, *, investigation_id: str | None = None
) -> dict:
    body: dict[str, Any] = {"trigger_payload": {}}
    if investigation_id is not None:
        body["investigation_id"] = investigation_id
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json=body,
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Investigations API: autonomy_level field + permission gate
# ---------------------------------------------------------------------------


async def test_investigation_defaults_to_l2(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Autonomy default check"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["autonomy_level"] == "L2"


async def test_analyst_can_lower_autonomy(client: AsyncClient, analyst_token: str):
    """L0/L1 mean MORE human oversight — open to any investigation creator."""
    resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Manual-mode investigation", "autonomy_level": "L0"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["autonomy_level"] == "L0"


async def test_analyst_cannot_raise_autonomy_above_l2(client: AsyncClient, analyst_token: str):
    """L3/L4 reduce oversight — require hitl:approve (senior+)."""
    for level in ("L3", "L4"):
        resp = await client.post(
            "/api/v1/investigations",
            json={"title": f"{level} attempt", "autonomy_level": level},
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 403, f"{level}: {resp.status_code} {resp.text}"


async def test_admin_can_set_l3(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Autonomous hunt", "autonomy_level": "L3"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["autonomy_level"] == "L3"


# ---------------------------------------------------------------------------
# Workflow runs: inheritance + snapshot
# ---------------------------------------------------------------------------


async def test_run_inherits_l0_from_investigation_and_pauses(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_token: str,
    analyst_token: str,
    sample_user,
):
    """An L0 investigation pauses the splunk step that L2 runs straight through."""
    inv = await _make_investigation(db_session, owner_id=sample_user.id, autonomy_level="L0")
    wf_id = await _seed_workflow(client, admin_token, SPLUNK_DEF)
    run = await _launch(client, analyst_token, wf_id, investigation_id=inv.id)
    assert run["status"] == "paused"
    assert run["paused_node_id"] == "s1"
    assert run["agent_autonomy"] == "L0"
    assert run["investigation_id"] == inv.id


async def test_run_without_investigation_defaults_to_l2_and_completes(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    """Ad-hoc launches keep the legacy supervised default: no pause at splunk."""
    wf_id = await _seed_workflow(client, admin_token, SPLUNK_DEF)
    run = await _launch(client, analyst_token, wf_id)
    assert run["status"] == "succeeded"
    assert run["agent_autonomy"] == "L2"
    assert run["nodes_executed"] == ["t1", "s1"]


async def test_run_inherits_default_l2_investigation_and_completes(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_token: str,
    analyst_token: str,
    sample_user,
):
    inv = await _make_investigation(db_session, owner_id=sample_user.id, autonomy_level="L2")
    wf_id = await _seed_workflow(client, admin_token, SPLUNK_DEF)
    run = await _launch(client, analyst_token, wf_id, investigation_id=inv.id)
    assert run["status"] == "succeeded"
    assert run["agent_autonomy"] == "L2"


async def test_resume_reexecutes_under_snapshotted_autonomy(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_token: str,
    analyst_token: str,
    sample_user,
):
    """Resume must rehydrate the run's L0 snapshot, not revert to L2.

    Under L0 every integration step pauses. Approving s1 therefore lands
    the run on a SECOND pause at s2; under the legacy hardcoded-L2 resume
    it would have completed instead.
    """
    inv = await _make_investigation(db_session, owner_id=sample_user.id, autonomy_level="L0")
    wf_id = await _seed_workflow(client, admin_token, SPLUNK_TWO_STEP_DEF)
    run = await _launch(client, analyst_token, wf_id, investigation_id=inv.id)
    assert run["status"] == "paused"
    assert run["paused_node_id"] == "s1"

    first = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert first.status_code == 200, first.text
    after_first = first.json()
    assert after_first["status"] == "paused"
    assert after_first["paused_node_id"] == "s2"
    assert after_first["approved_steps"] == ["s1"]
    assert after_first["agent_autonomy"] == "L0"

    second = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert second.status_code == 200, second.text
    final = second.json()
    assert final["status"] == "succeeded"
    assert final["nodes_executed"] == ["t1", "s1", "s2"]
    assert sorted(final["approved_steps"]) == ["s1", "s2"]
    assert final["agent_autonomy"] == "L0"
