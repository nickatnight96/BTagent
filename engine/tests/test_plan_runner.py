"""Tests for the HuntPlan executor (#120 Phase C slice 3).

Runs against the integration nodes' deterministic mock fixtures
(``BTAGENT_MOCK_CONNECTORS=true``): hits are collected per TTP per backend,
unsupported backends and empty queries degrade to per-entry errors / skips
without aborting the run.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.hunt import (
    Backend,
    HuntInput,
    HuntPlan,
    Query,
    TTPRunbookEntry,
)

from btagent_engine.hunting.plan_runner import run_plan
from btagent_engine.node import NodeContext


@pytest.fixture(autouse=True)
def _mock_connectors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")


def _plan(entries: list[TTPRunbookEntry]) -> HuntPlan:
    return HuntPlan(
        id="hunt_test01",
        org_id="org_default",
        input=HuntInput(ttps=[e.ttp_id for e in entries], initiated_by="usr_test"),
        hypotheses=[],
        ttp_entries=entries,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _entry(ttp_id: str, queries: dict[Backend, str]) -> TTPRunbookEntry:
    return TTPRunbookEntry(
        ttp_id=ttp_id,
        ttp_name=f"Technique {ttp_id}",
        rationale="test",
        behavioral_description="test behaviour",
        queries={b: Query(backend=b, query=q) for b, q in queries.items()},
    )


def _ctx() -> NodeContext:
    return NodeContext(run_id="hrun_test01", org_id="org_default")


async def test_run_plan_collects_hits_per_ttp_and_backend() -> None:
    plan = _plan(
        [
            _entry("T1059.001", {Backend.SPLUNK: "index=main powershell"}),
            _entry("T1071.001", {Backend.CROWDSTRIKE: "event_simpleName=DnsRequest"}),
        ]
    )
    result = await run_plan(plan, _ctx())

    assert result.plan_id == "hunt_test01"
    assert result.completed_at is not None
    assert {t.ttp_id for t in result.ttp_results} == {"T1059.001", "T1071.001"}
    # Mock fixtures return events — every hit is tagged with its TTP + backend.
    assert result.all_hits
    for ttp in result.ttp_results:
        for hit in ttp.hits:
            assert hit.ttp_id == ttp.ttp_id
            assert hit.plan_id == "hunt_test01"
            assert hit.source_run_id == result.run_id
    assert result.error_count == 0


async def test_unsupported_backend_is_isolated_error() -> None:
    plan = _plan(
        [
            _entry(
                "T1078",
                {
                    Backend.SIGMA: "title: canonical rule",  # no execution adapter
                    Backend.SPLUNK: "index=auth action=failure",
                },
            )
        ]
    )
    result = await run_plan(plan, _ctx())

    (ttp,) = result.ttp_results
    errors = [br for br in ttp.backend_results if br.error]
    assert len(errors) == 1
    assert errors[0].backend == "sigma"
    assert "no execution adapter" in errors[0].error
    # The Splunk half of the entry still ran and produced hits.
    ok = [br for br in ttp.backend_results if br.error is None]
    assert ok and ok[0].backend == "splunk"
    assert ttp.hits


async def test_empty_query_is_skipped() -> None:
    plan = _plan([_entry("T1059.001", {Backend.SPLUNK: "   "})])
    result = await run_plan(plan, _ctx())

    (ttp,) = result.ttp_results
    assert ttp.backend_results == []
    assert ttp.hits == []
    assert result.error_count == 0
