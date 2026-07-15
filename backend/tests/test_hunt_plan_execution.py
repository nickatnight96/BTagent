"""Tests for HuntPlan execution + findings ingest (#120 Phase C slice 3).

Deterministic end-to-end under mock LLM + mock connectors:
- accept → compile → execute lands cross_investigation findings in the
  triage inbox, flips the stored plan to ``completed`` with a ``last_run``
  summary, and writes the proposal's closed-loop outcome back
- execute is re-runnable (the ``last_run`` extra is popped on rehydrate)
- 404 pre-accept, 409 when the compile failed, 401 unauthenticated
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.db.models_pattern import PatternHuntProposalRow


@pytest.fixture(autouse=True)
def _force_mock_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic engine paths — inline compile AND inline execute."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")


def _proposal_row() -> PatternHuntProposalRow:
    now = datetime.now(UTC)
    return PatternHuntProposalRow(
        id=generate_id("phpr"),
        org_id=DEFAULT_ORG_ID,
        cluster_id=generate_id("cl"),
        score=0.8,
        hunt_input={
            "adversaries": [],
            "ttps": ["T1059.001"],
            "iocs": [],
            "scope": {
                "environments": [],
                "hosts": [],
                "date_from": None,
                "date_to": None,
                "backends": [],
            },
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
async def accepted_proposal(client, analyst_token, db_session: AsyncSession):
    """A proposal accepted through the API — plan compiled inline (mock LLM)."""
    row = _proposal_row()
    db_session.add(row)
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/pattern/proposals/{row.id}/accept",
        headers=auth_header(analyst_token),
        json={},
    )
    assert resp.status_code == 200, resp.text
    return row


def _execute_url(proposal_id: str) -> str:
    return f"/api/v1/pattern/proposals/{proposal_id}/plan/execute"


def _plan_url(proposal_id: str) -> str:
    return f"/api/v1/pattern/proposals/{proposal_id}/plan"


# --------------------------------------------------------------------------- #
# Happy path: execute → findings + last_run + outcome write-back
# --------------------------------------------------------------------------- #


async def test_execute_ingests_findings_and_completes_plan(
    client, analyst_token, accepted_proposal, db_session: AsyncSession
):
    resp = await client.post(_execute_url(accepted_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["queued"] is False
    assert isinstance(body["findings_created"], int)

    plan_json = body["plan"]["plan"]
    assert plan_json["state"] == "completed"
    last_run = plan_json["last_run"]
    assert last_run["findings_created"] == body["findings_created"]
    assert set(last_run["per_ttp"].keys()) == {"T1059.001"}

    # Every created finding is a cross_investigation-domain inbox row carrying
    # plan provenance in its evidence.
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain == "cross_investigation",
                )
            )
        )
        .scalars()
        .all()
    )
    # Scope to this test's proposal — other suites land cross_investigation
    # findings in the shared session DB too.
    plan_rows = [r for r in rows if (r.evidence or {}).get("proposal_id") == accepted_proposal.id]
    assert len(plan_rows) >= body["findings_created"]
    if body["findings_created"]:
        sample = plan_rows[0]
        assert sample.source == "cross_investigation"
        assert sample.technique_ids == ["T1059.001"]
        assert sample.evidence["plan_run_id"] == last_run["run_id"]

    # Closed-loop outcome write-back on the proposal.
    await db_session.refresh(accepted_proposal)
    expected = "hit" if body["findings_created"] else "clean"
    assert accepted_proposal.outcome == expected


async def test_execute_is_rerunnable(client, analyst_token, accepted_proposal):
    first = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    assert first.status_code == 200
    # The stored plan now carries the extra ``last_run`` key — a re-execute
    # must rehydrate cleanly (the service pops it) and refresh the summary.
    second = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    assert second.status_code == 200, second.text
    assert (
        second.json()["plan"]["plan"]["last_run"]["run_id"]
        != first.json()["plan"]["plan"]["last_run"]["run_id"]
    )


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


async def test_execute_before_accept_is_404(client, analyst_token, db_session: AsyncSession):
    row = _proposal_row()
    db_session.add(row)
    await db_session.commit()
    resp = await client.post(_execute_url(row.id), headers=auth_header(analyst_token))
    assert resp.status_code == 404


async def test_execute_failed_compile_is_409(
    client, analyst_token, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    from btagent_backend.services import proposal_huntplan

    async def _boom(proposal, *, backends=None):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(proposal_huntplan, "compile_proposal_to_huntplan", _boom)

    row = _proposal_row()
    db_session.add(row)
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/pattern/proposals/{row.id}/accept",
        headers=auth_header(analyst_token),
        json={},
    )
    assert resp.status_code == 200

    resp = await client.post(_execute_url(row.id), headers=auth_header(analyst_token))
    assert resp.status_code == 409


async def test_execute_requires_auth(client, accepted_proposal):
    resp = await client.post(_execute_url(accepted_proposal.id))
    assert resp.status_code == 401
