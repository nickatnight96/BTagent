"""Unit tests for the proposal → HuntPlan compiler (#120 Phase C slice 1).

Deterministic under ``BTAGENT_MOCK_LLM=true`` — the engine nodes
(HypothesisGen / QuerySynth / NoiseBaseline / RunbookCompiler) all fall back
to their deterministic mock generators, so the compiler produces a stable
HuntPlan without any real LLM or network call.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import Backend, HuntInput, HuntPlanState, HuntScope, TTPState
from btagent_shared.types.pattern_hunt import PatternHuntProposal, ProposalState

from btagent_backend.services.proposal_huntplan import (
    _DEFAULT_BACKENDS,
    compile_proposal_to_huntplan,
)


@pytest.fixture(autouse=True)
def _force_mock_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test in this module runs the engine nodes in deterministic mode."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")


def _proposal(
    *,
    adversaries: list[str] | None = None,
    ttps: list[str] | None = None,
    scope: HuntScope | None = None,
    autonomy: AutonomyLevel = AutonomyLevel.L2_SUPERVISED,
    initiated_by: str = "usr_test",
    org_id: str = "org_test",
) -> PatternHuntProposal:
    now = datetime.now(UTC)
    return PatternHuntProposal(
        id="phprop_test",
        org_id=org_id,
        cluster_id="wsc_1",
        hunt_input=HuntInput(
            adversaries=adversaries or ["APT29"],
            ttps=ttps or [],
            scope=scope or HuntScope(),
            initiated_by=initiated_by,
            autonomy_level=autonomy,
        ),
        rationale="weak-signal cluster across 3 investigations",
        state=ProposalState.ACCEPTED,
        outcome=None,
        created_at=now,
        updated_at=now,
    )


# --------------------------------------------------------------------------- #
# Core: a proposal compiles into a READY, tenant-scoped plan
# --------------------------------------------------------------------------- #


async def test_compiles_to_ready_plan() -> None:
    plan = await compile_proposal_to_huntplan(_proposal())
    assert plan.state is HuntPlanState.READY
    assert plan.id.startswith("hunt_")
    assert plan.org_id == "org_test"
    # APT29 stock set yields 3 hypotheses → 3 runbook entries.
    assert len(plan.hypotheses) == 3
    assert len(plan.ttp_entries) == 3


async def test_plan_carries_proposal_hunt_input_verbatim() -> None:
    proposal = _proposal(autonomy=AutonomyLevel.L1_ASSISTED, initiated_by="usr_alice")
    plan = await compile_proposal_to_huntplan(proposal)
    # The HuntInput (and thus autonomy + initiator) flows through unchanged —
    # the orchestrator must honour the analyst's autonomy choice.
    assert plan.input == proposal.hunt_input
    assert plan.input.autonomy_level is AutonomyLevel.L1_ASSISTED
    assert plan.input.initiated_by == "usr_alice"


async def test_org_scope_comes_from_proposal_not_hunt_input() -> None:
    plan = await compile_proposal_to_huntplan(_proposal(org_id="org_acme"))
    assert plan.org_id == "org_acme"


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #


async def test_default_backends_synthesised_when_scope_unpinned() -> None:
    plan = await compile_proposal_to_huntplan(_proposal(scope=HuntScope()))
    for entry in plan.ttp_entries:
        assert set(entry.queries) == set(_DEFAULT_BACKENDS)


async def test_scope_backends_win_over_default() -> None:
    plan = await compile_proposal_to_huntplan(_proposal(scope=HuntScope(backends=[Backend.SPLUNK])))
    for entry in plan.ttp_entries:
        assert set(entry.queries) == {Backend.SPLUNK}


async def test_explicit_backends_override_used_when_scope_empty() -> None:
    plan = await compile_proposal_to_huntplan(
        _proposal(scope=HuntScope()), backends=[Backend.ELASTIC]
    )
    for entry in plan.ttp_entries:
        assert set(entry.queries) == {Backend.ELASTIC}


# --------------------------------------------------------------------------- #
# Enrichment: queries + noise + Phase-A scaffolding all present
# --------------------------------------------------------------------------- #


async def test_entries_have_queries_noise_pivots_and_checklist() -> None:
    plan = await compile_proposal_to_huntplan(_proposal())
    for entry in plan.ttp_entries:
        assert entry.queries, f"{entry.ttp_id} has no synthesised queries"
        assert entry.expected_noise.expected_hits_per_day is not None
        assert entry.expected_noise.expected_hits_per_day >= 1
        assert entry.pivot_questions
        assert entry.evidence_checklist
        assert entry.state is TTPState.NOT_STARTED


async def test_entries_track_their_hypotheses() -> None:
    plan = await compile_proposal_to_huntplan(_proposal())
    hyp_ttps = {h.ttp_id for h in plan.hypotheses}
    entry_ttps = {e.ttp_id for e in plan.ttp_entries}
    assert entry_ttps == hyp_ttps


# --------------------------------------------------------------------------- #
# Determinism + distinct ids
# --------------------------------------------------------------------------- #


async def test_compilation_is_deterministic_modulo_ids() -> None:
    """Two compiles of the same proposal yield structurally identical plans
    (the deterministic mock path), differing only in generated ids/timestamps.
    """
    proposal = _proposal(adversaries=["FIN7"])
    a = await compile_proposal_to_huntplan(proposal)
    b = await compile_proposal_to_huntplan(proposal)

    assert [h.ttp_id for h in a.hypotheses] == [h.ttp_id for h in b.hypotheses]
    assert [e.ttp_id for e in a.ttp_entries] == [e.ttp_id for e in b.ttp_entries]
    assert {bk for e in a.ttp_entries for bk in e.queries} == {
        bk for e in b.ttp_entries for bk in e.queries
    }


async def test_distinct_compiles_get_distinct_plan_ids() -> None:
    a = await compile_proposal_to_huntplan(_proposal())
    b = await compile_proposal_to_huntplan(_proposal())
    assert a.id != b.id


# --------------------------------------------------------------------------- #
# TTP-driven proposals (not just adversary-driven)
# --------------------------------------------------------------------------- #


async def test_ttp_only_proposal_compiles() -> None:
    plan = await compile_proposal_to_huntplan(
        _proposal(adversaries=[], ttps=["T1059.001", "T1078.004"])
    )
    assert plan.state is HuntPlanState.READY
    assert plan.ttp_entries
    compiled_ttps = {e.ttp_id for e in plan.ttp_entries}
    # The requested techniques should surface as runbook entries.
    assert {"T1059.001", "T1078.004"} & compiled_ttps
