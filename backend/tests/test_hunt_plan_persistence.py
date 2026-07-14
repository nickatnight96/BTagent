"""Tests for HuntPlan persistence + accept-hook wiring (#120 Phase C slice 2).

Covers the full accept → compile → read loop under deterministic mock LLM:
- accept creates the plan row and compiles it inline to ``ready``
- accept is idempotent — one plan row per proposal
- ``GET /pattern/proposals/{id}/plan`` surfaces status + plan (404 pre-accept)
- compile failure lands ``failed`` + error on the row without failing accept
- org scoping masks cross-tenant proposals as 404
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_pattern import HuntPlanRow, PatternHuntProposalRow


@pytest.fixture(autouse=True)
def _force_mock_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic engine path — accept compiles inline, no arq needed."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")


def _proposal_row(org_id: str = DEFAULT_ORG_ID) -> PatternHuntProposalRow:
    now = datetime.now(UTC)
    return PatternHuntProposalRow(
        id=generate_id("phpr"),
        org_id=org_id,
        cluster_id=generate_id("cl"),
        score=0.8,
        hunt_input={
            "adversaries": [],
            "ttps": ["T1059.001", "T1071.001"],
            "iocs": [],
            "scope": {
                "environments": [],
                "hosts": [],
                "date_from": None,
                "date_to": None,
                "backends": [],
            },
            # The pattern transformer always stamps these (see
            # shared/btagent_shared/hunt/pattern.py) — Phase C rehydration
            # is strict, so the fixture carries the full HuntInput shape.
            "initiated_by": "usr_pattern_scan",
            "autonomy_level": "L2",
        },
        rationale="Test proposal: recurring weak signals.",
        state="proposed",
        outcome=None,
        created_at=now,
        updated_at=now,
    )


@pytest_asyncio.fixture
async def seeded_proposal(db_session: AsyncSession) -> PatternHuntProposalRow:
    row = _proposal_row()
    db_session.add(row)
    await db_session.commit()
    return row


async def _accept(client, token: str, proposal_id: str):
    return await client.post(
        f"/api/v1/pattern/proposals/{proposal_id}/accept",
        headers=auth_header(token),
        json={"rationale": "run it"},
    )


def _plan_url(proposal_id: str) -> str:
    return f"/api/v1/pattern/proposals/{proposal_id}/plan"


# --------------------------------------------------------------------------- #
# Accept → compile → read loop
# --------------------------------------------------------------------------- #


async def test_accept_compiles_and_persists_plan(
    client, analyst_token, seeded_proposal, db_session: AsyncSession
):
    resp = await _accept(client, analyst_token, seeded_proposal.id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "accepted"

    resp = await client.get(_plan_url(seeded_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["proposal_id"] == seeded_proposal.id
    assert body["org_id"] == DEFAULT_ORG_ID
    assert body["error"] == ""

    plan = body["plan"]
    assert plan is not None
    # The compiled plan is a READY HuntPlan carrying the proposal's HuntInput.
    assert plan["state"] == "ready"
    assert plan["id"].startswith("hunt_")
    assert plan["org_id"] == DEFAULT_ORG_ID
    assert plan["input"]["ttps"] == ["T1059.001", "T1071.001"]
    assert len(plan["hypotheses"]) >= 1


async def test_plan_404_before_accept(client, analyst_token, seeded_proposal):
    resp = await client.get(_plan_url(seeded_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 404


async def test_accept_is_idempotent_one_plan_row(
    client, analyst_token, seeded_proposal, db_session: AsyncSession
):
    first = await _accept(client, analyst_token, seeded_proposal.id)
    assert first.status_code == 200
    second = await _accept(client, analyst_token, seeded_proposal.id)
    assert second.status_code == 200

    count = (
        await db_session.execute(
            select(func.count())
            .select_from(HuntPlanRow)
            .where(HuntPlanRow.proposal_id == seeded_proposal.id)
        )
    ).scalar_one()
    assert count == 1


async def test_unknown_proposal_plan_is_404(client, analyst_token):
    resp = await client.get(_plan_url("phpr_does_not_exist"), headers=auth_header(analyst_token))
    assert resp.status_code == 404


async def test_plan_requires_auth(client, seeded_proposal):
    resp = await client.get(_plan_url(seeded_proposal.id))
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Failure path — compile error lands on the row, accept still succeeds
# --------------------------------------------------------------------------- #


async def test_compile_failure_marks_row_failed_but_accept_succeeds(
    client, analyst_token, seeded_proposal, monkeypatch: pytest.MonkeyPatch
):
    from btagent_backend.services import proposal_huntplan

    async def _boom(proposal, *, backends=None):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(proposal_huntplan, "compile_proposal_to_huntplan", _boom)

    resp = await _accept(client, analyst_token, seeded_proposal.id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "accepted"

    resp = await client.get(_plan_url(seeded_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "engine exploded" in body["error"]
    assert body["plan"] is None


# --------------------------------------------------------------------------- #
# Org scoping
# --------------------------------------------------------------------------- #


async def test_cross_org_proposal_plan_is_masked_404(
    client, analyst_token, db_session: AsyncSession
):
    from btagent_backend.db.models import OrganizationRow

    other_org = "org_huntplan_other"
    if await db_session.get(OrganizationRow, other_org) is None:
        db_session.add(OrganizationRow(id=other_org, name="HuntPlan Other Tenant"))
        await db_session.flush()
    row = _proposal_row(org_id=other_org)
    db_session.add(row)
    await db_session.commit()

    resp = await client.get(_plan_url(row.id), headers=auth_header(analyst_token))
    assert resp.status_code == 404
    resp = await _accept(client, analyst_token, row.id)
    assert resp.status_code == 404
