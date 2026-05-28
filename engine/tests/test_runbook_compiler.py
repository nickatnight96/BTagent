"""Tests for RunbookCompilerNode (#99 Phase A)."""

from __future__ import annotations

import pytest
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import (
    Backend,
    HuntInput,
    HuntPlanState,
    HuntScope,
    Hypothesis,
    NoiseProfile,
    Query,
    TTPState,
)

from btagent_engine import NodeContext
from btagent_engine.data import (
    RunbookCompilerInput,
    RunbookCompilerNode,
    RunbookCompilerOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_runbook", org_id="org_test")


def _hi() -> HuntInput:
    return HuntInput(
        adversaries=["APT29"],
        initiated_by="usr_test",
        autonomy_level=AutonomyLevel.L2_SUPERVISED,
        scope=HuntScope(),
    )


def _hyp(ttp_id: str = "T1059.001", name: str = "PowerShell") -> Hypothesis:
    return Hypothesis(
        id="h_001",
        ttp_id=ttp_id,
        ttp_name=name,
        rationale="APT29 has used this technique.",
        behavioral_description=f"Look for {name}.",
        priority=0.85,
        sources=["adversary:APT29"],
    )


# --------------------------------------------------------------------------- #
# Smoke: empty hypotheses still produces a valid plan
# --------------------------------------------------------------------------- #


async def test_empty_hypotheses_produces_empty_plan():
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[],
        ),
        _ctx(),
    )
    assert isinstance(out, RunbookCompilerOutput)
    plan = out.plan
    assert plan.state == HuntPlanState.READY
    assert plan.ttp_entries == []
    assert plan.hypotheses == []
    # Correlation rules + post-actions ship as defaults regardless.
    assert len(plan.correlation_rules) >= 1
    assert len(plan.post_actions) >= 1
    assert plan.executive_summary.estimated_effort_hours == 0.0


# --------------------------------------------------------------------------- #
# Per-hypothesis entry shape
# --------------------------------------------------------------------------- #


async def test_entry_pulls_pivots_and_evidence_from_library():
    hyp = _hyp("T1059.001", "PowerShell")
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
        ),
        _ctx(),
    )
    entry = out.plan.ttp_entries[0]
    assert entry.ttp_id == "T1059.001"
    assert entry.state == TTPState.NOT_STARTED
    # The T1059.001 pivot library has at least one PowerShell-specific question.
    assert any("-EncodedCommand" in q or "PowerShell" in q for q in entry.pivot_questions)
    assert any("process tree" in e.lower() for e in entry.evidence_checklist)


async def test_unknown_ttp_falls_back_to_generic_pivots():
    hyp = _hyp("T9999.999", "Made up technique")
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
        ),
        _ctx(),
    )
    entry = out.plan.ttp_entries[0]
    # Fallback library is in runbook_compiler._PIVOTS_FALLBACK; check
    # that it produced *some* pivot / evidence content rather than
    # asserting exact text (which would couple this test to wording).
    assert len(entry.pivot_questions) >= 1
    assert len(entry.evidence_checklist) >= 1


# --------------------------------------------------------------------------- #
# Per-TTP enrichments propagate
# --------------------------------------------------------------------------- #


async def test_per_ttp_queries_propagate_to_entry():
    hyp = _hyp("T1059.001")
    queries = {
        Backend.SPLUNK: Query(backend=Backend.SPLUNK, query="index=endpoint EventCode=4688"),
        Backend.SENTINEL: Query(backend=Backend.SENTINEL, query="DeviceProcessEvents | take 10"),
    }
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
            per_ttp_queries={"T1059.001": queries},
        ),
        _ctx(),
    )
    entry = out.plan.ttp_entries[0]
    assert entry.queries[Backend.SPLUNK].query.startswith("index=endpoint")
    assert entry.queries[Backend.SENTINEL].query.startswith("DeviceProcessEvents")


async def test_per_ttp_noise_propagates_to_entry():
    hyp = _hyp("T1059.001")
    noise = NoiseProfile(expected_hits_per_day=42.0, sample_window_days=30)
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
            per_ttp_noise={"T1059.001": noise},
        ),
        _ctx(),
    )
    assert out.plan.ttp_entries[0].expected_noise.expected_hits_per_day == 42.0


# --------------------------------------------------------------------------- #
# Effort estimate heuristic
# --------------------------------------------------------------------------- #


async def test_effort_estimate_lower_when_queries_synthed():
    hyp = _hyp("T1059.001")
    out_with = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
            per_ttp_queries={
                "T1059.001": {
                    Backend.SPLUNK: Query(backend=Backend.SPLUNK, query="x"),
                },
            },
        ),
        _ctx(),
    )
    out_without = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[hyp],
        ),
        _ctx(),
    )
    assert (
        out_with.plan.executive_summary.estimated_effort_hours
        < out_without.plan.executive_summary.estimated_effort_hours
    )


# --------------------------------------------------------------------------- #
# Plan id
# --------------------------------------------------------------------------- #


async def test_explicit_plan_id_is_respected():
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            plan_id="hunt_custom_id",
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[],
        ),
        _ctx(),
    )
    assert out.plan.id == "hunt_custom_id"


async def test_plan_id_auto_generated_when_omitted():
    out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=_hi(),
            hypotheses=[],
        ),
        _ctx(),
    )
    assert out.plan.id.startswith("hunt_")
    assert len(out.plan.id) > len("hunt_")
