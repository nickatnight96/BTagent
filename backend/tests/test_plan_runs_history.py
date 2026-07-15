"""Tests for the plan_runs execution-history table (#120 follow-up).

Mirrors the hunt_pack_runs pattern for HuntPlan executions:
- executing a compiled plan records one ``PlanRunRow`` per invocation —
  repeated executions accumulate history instead of overwriting each other
  (the plan JSON's ``last_run`` blob stays the backward-compatible summary)
- ``GET /pattern/proposals/{id}/plan/runs`` serves the history newest-first,
  404 pre-accept, empty pre-execute, 401 unauthenticated
- run status derivation matches hunt_pack_runs semantics
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
from btagent_backend.db.models_pattern import PatternHuntProposalRow, PlanRunRow
from btagent_backend.services.hunt_plan_service import _derive_plan_run_status


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
        rationale="Test proposal: plan-run history.",
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


def _runs_url(proposal_id: str) -> str:
    return f"/api/v1/pattern/proposals/{proposal_id}/plan/runs"


# --------------------------------------------------------------------------- #
# Run rows accumulate per execution
# --------------------------------------------------------------------------- #


async def test_execute_records_run_row(
    client, analyst_token, accepted_proposal, db_session: AsyncSession
):
    resp = await client.post(_execute_url(accepted_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    last_run = body["plan"]["plan"]["last_run"]

    rows = (
        (
            await db_session.execute(
                select(PlanRunRow).where(PlanRunRow.proposal_id == accepted_proposal.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.org_id == DEFAULT_ORG_ID
    assert row.run_id == last_run["run_id"]
    assert row.findings_created == body["findings_created"]
    assert row.ttp_stats == last_run["per_ttp"]
    assert row.plan_id == body["plan"]["plan"]["id"]
    assert row.status in {"completed", "completed_with_errors"}
    assert row.started_at is not None


async def test_reexecution_appends_history(
    client, analyst_token, accepted_proposal, db_session: AsyncSession
):
    first = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    second = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    assert first.status_code == 200 and second.status_code == 200

    rows = (
        (
            await db_session.execute(
                select(PlanRunRow).where(PlanRunRow.proposal_id == accepted_proposal.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2
    run_ids = {r.run_id for r in rows}
    assert run_ids == {
        first.json()["plan"]["plan"]["last_run"]["run_id"],
        second.json()["plan"]["plan"]["last_run"]["run_id"],
    }


# --------------------------------------------------------------------------- #
# History endpoint
# --------------------------------------------------------------------------- #


async def test_runs_endpoint_lists_newest_first(client, analyst_token, accepted_proposal):
    first = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    second = await client.post(
        _execute_url(accepted_proposal.id), headers=auth_header(analyst_token)
    )
    assert first.status_code == 200 and second.status_code == 200

    resp = await client.get(_runs_url(accepted_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    assert [r["run_id"] for r in body["items"]] == [
        second.json()["plan"]["plan"]["last_run"]["run_id"],
        first.json()["plan"]["plan"]["last_run"]["run_id"],
    ]
    assert body["items"][0]["proposal_id"] == accepted_proposal.id


async def test_runs_endpoint_empty_before_any_execution(client, analyst_token, accepted_proposal):
    resp = await client.get(_runs_url(accepted_proposal.id), headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"items": [], "total": 0}


async def test_runs_endpoint_404_before_accept(client, analyst_token, db_session: AsyncSession):
    row = _proposal_row()
    db_session.add(row)
    await db_session.commit()
    resp = await client.get(_runs_url(row.id), headers=auth_header(analyst_token))
    assert resp.status_code == 404


async def test_runs_endpoint_requires_auth(client, accepted_proposal):
    resp = await client.get(_runs_url(accepted_proposal.id))
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Status derivation (pure)
# --------------------------------------------------------------------------- #


def _result_with(errors_per_ttp: list[list[str | None]]):
    """Build a minimal PlanRunResult-shaped object for status derivation."""

    class _Backend:
        def __init__(self, error: str | None):
            self.error = error

    class _TTP:
        def __init__(self, errors: list[str | None]):
            self.backend_results = [_Backend(e) for e in errors]

    class _Result:
        def __init__(self):
            self.ttp_results = [_TTP(errs) for errs in errors_per_ttp]

    return _Result()


def test_derive_status_completed():
    assert _derive_plan_run_status(_result_with([[None, None]])) == "completed"


def test_derive_status_empty_runbook_is_completed():
    assert _derive_plan_run_status(_result_with([])) == "completed"


def test_derive_status_partial_errors():
    assert _derive_plan_run_status(_result_with([[None, "boom"]])) == "completed_with_errors"


def test_derive_status_all_errored_is_failed():
    assert _derive_plan_run_status(_result_with([["boom"], ["kaput"]])) == "failed"
