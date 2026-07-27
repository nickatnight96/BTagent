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

    async def _boom(
        proposal, *, backends=None, adversary_resolver=None, deployed_technique_ids=None
    ):
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


# --------------------------------------------------------------------------- #
# #120 Task C: a confirmed HIT files a recurring #112 hunt-pack suggestion
# --------------------------------------------------------------------------- #


def _fake_hit_run_plan(ttp_id: str = "T1059.001"):
    """Build a deterministic ``run_plan`` stub that returns one hit for ``ttp_id``."""

    async def _run(plan, ctx, *, lookback_hours=24, max_hits_per_query=100):
        from btagent_engine.hunting.plan_runner import (
            PlanBackendResult,
            PlanHit,
            PlanRunResult,
            TTPRunResult,
        )

        now = datetime.now(UTC)
        run_id = generate_id("hrun")
        return PlanRunResult(
            run_id=run_id,
            plan_id=plan.id,
            org_id=ctx.org_id,
            started_at=now,
            completed_at=now,
            ttp_results=[
                TTPRunResult(
                    ttp_id=ttp_id,
                    ttp_name="PowerShell",
                    backend_results=[PlanBackendResult(backend="sigma", query="q", hit_count=1)],
                    hits=[
                        PlanHit(
                            source_run_id=run_id,
                            plan_id=plan.id,
                            ttp_id=ttp_id,
                            ttp_name="PowerShell",
                            backend="sigma",
                            summary="matched live telemetry",
                            raw={"host": "alice-pc"},
                        )
                    ],
                )
            ],
        )

    return _run


async def _seed_ready_plan(db_session: AsyncSession) -> tuple[PatternHuntProposalRow, str]:
    """A proposal + a ``ready`` HuntPlanRow with one Sigma-backed TTP entry."""
    from btagent_shared.types.hunt import (
        Backend,
        HuntInput,
        HuntPlan,
        Query,
        TTPRunbookEntry,
    )

    from btagent_backend.db.models_pattern import HuntPlanRow

    proposal = _proposal_row()
    db_session.add(proposal)
    await db_session.flush()

    plan = HuntPlan(
        id=generate_id("hunt"),
        org_id=DEFAULT_ORG_ID,
        input=HuntInput(ttps=["T1059.001"], initiated_by="usr_pattern_scan"),
        ttp_entries=[
            TTPRunbookEntry(
                ttp_id="T1059.001",
                ttp_name="PowerShell",
                rationale="recurring cross-case signal",
                behavioral_description="suspicious powershell",
                queries={
                    Backend.SIGMA: Query(
                        backend=Backend.SIGMA,
                        query="title: PS\ndetection:\n  sel: {}\n  condition: sel\n",
                    )
                },
            )
        ],
    )
    now = datetime.now(UTC)
    db_session.add(
        HuntPlanRow(
            id=plan.id,
            org_id=DEFAULT_ORG_ID,
            proposal_id=proposal.id,
            status="ready",
            plan=plan.model_dump(mode="json"),
            error="",
            created_at=now,
            updated_at=now,
        )
    )
    await db_session.flush()
    return proposal, plan.id


async def test_confirmed_hit_files_recurring_hunt_pack_suggestion(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    from btagent_backend.db.models_pattern import HuntPackSuggestionRow
    from btagent_backend.services import hunt_plan_service

    proposal, plan_id = await _seed_ready_plan(db_session)
    monkeypatch.setattr(
        "btagent_engine.hunting.plan_runner.run_plan", _fake_hit_run_plan("T1059.001")
    )

    _, findings_created = await hunt_plan_service.execute_plan_and_ingest(
        db_session, plan_row_id=plan_id
    )
    assert findings_created >= 1

    # Closed-loop outcome write-back marked the proposal a HIT...
    await db_session.refresh(proposal)
    assert proposal.outcome == "hit"

    # ...and a recurring #112 hunt-pack suggestion was filed from that path.
    suggestion = (
        await db_session.execute(
            select(HuntPackSuggestionRow).where(HuntPackSuggestionRow.proposal_id == proposal.id)
        )
    ).scalar_one()
    assert suggestion.state == "suggested"
    assert suggestion.hit_count == 1
    assert suggestion.plan_id == plan_id
    assert "T1059.001" in suggestion.technique_ids
    # The manifest draft carries one Sigma rule per hitting technique, sourced
    # from the runbook's own query (not a placeholder skeleton).
    rules = suggestion.manifest["rules"]
    assert len(rules) == 1
    assert rules[0]["mitre_techniques"] == ["T1059.001"]
    assert "title: PS" in rules[0]["sigma_yaml"]


async def test_repeated_hit_upserts_suggestion_without_duplicating(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    from btagent_backend.db.models_pattern import HuntPackSuggestionRow
    from btagent_backend.services import hunt_plan_service

    proposal, plan_id = await _seed_ready_plan(db_session)
    monkeypatch.setattr(
        "btagent_engine.hunting.plan_runner.run_plan", _fake_hit_run_plan("T1059.001")
    )

    await hunt_plan_service.execute_plan_and_ingest(db_session, plan_row_id=plan_id)
    await hunt_plan_service.execute_plan_and_ingest(db_session, plan_row_id=plan_id)

    rows = (
        (
            await db_session.execute(
                select(HuntPackSuggestionRow).where(
                    HuntPackSuggestionRow.proposal_id == proposal.id
                )
            )
        )
        .scalars()
        .all()
    )
    # One row (unique on org+proposal), reinforced to hit_count == 2.
    assert len(rows) == 1
    assert rows[0].hit_count == 2
