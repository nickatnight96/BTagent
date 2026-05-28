"""Full hunt-pipeline integration test (#99 Phase A + B).

Exercises the complete chain that the Hunter plugin composes:

    HuntInput
      -> HypothesisGenNode      (adversary/TTP/IOC -> hypotheses)
      -> QuerySynthNode          (per hypothesis -> per-backend queries)
      -> NoiseBaselineNode       (per query -> expected hit volume)
      -> RunbookCompilerNode     (assemble -> HuntPlan)

Confirms the per-TTP queries + noise profiles land in the final
runbook entries — i.e. the Phase A RunbookCompiler slots that were
empty now get filled by the Phase B nodes.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import Backend, HuntInput, HuntPlanState, HuntScope, TTPState

from btagent_engine import NodeContext
from btagent_engine.data import (
    NoiseBaselineInput,
    NoiseBaselineNode,
    RunbookCompilerInput,
    RunbookCompilerNode,
)
from btagent_engine.reasoning import (
    HypothesisGenInput,
    HypothesisGenNode,
    QuerySynthInput,
    QuerySynthNode,
)


async def test_full_apt29_hunt_pipeline(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")

    ctx = NodeContext(run_id="r_pipe", org_id="org_test")
    backends = [Backend.SPLUNK, Backend.SENTINEL]
    hunt_input = HuntInput(
        adversaries=["APT29"],
        initiated_by="usr_test",
        autonomy_level=AutonomyLevel.L2_SUPERVISED,
        scope=HuntScope(backends=backends),
    )

    # 1. Hypotheses
    hyp_out = await HypothesisGenNode().run(HypothesisGenInput(hunt_input=hunt_input), ctx)
    assert len(hyp_out.hypotheses) == 3  # APT29 stock set

    # 2 + 3. Per-hypothesis: synth queries, baseline each query
    per_ttp_queries = {}
    per_ttp_noise = {}
    for h in hyp_out.hypotheses:
        qs_out = await QuerySynthNode().run(
            QuerySynthInput(
                ttp_id=h.ttp_id,
                behavioral_description=h.behavioral_description,
                backends=backends,
            ),
            ctx,
        )
        per_ttp_queries[h.ttp_id] = qs_out.queries

        # Baseline the first backend's query for the noise profile.
        nb_out = await NoiseBaselineNode().run(
            NoiseBaselineInput(ttp_id=h.ttp_id, backend=backends[0]),
            ctx,
        )
        per_ttp_noise[h.ttp_id] = nb_out.profile

    # 4. Compile the runbook with the Phase B enrichments
    plan_out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            org_id="org_test",
            hunt_input=hunt_input,
            hypotheses=hyp_out.hypotheses,
            per_ttp_queries=per_ttp_queries,
            per_ttp_noise=per_ttp_noise,
        ),
        ctx,
    )
    plan = plan_out.plan

    # --- Assertions on the assembled plan ---------------------------------
    assert plan.state == HuntPlanState.READY
    assert len(plan.ttp_entries) == 3

    for entry in plan.ttp_entries:
        # Phase B filled the queries slot (Phase A left it empty)
        assert set(entry.queries) == {Backend.SPLUNK, Backend.SENTINEL}
        # Phase B filled the noise slot
        assert entry.expected_noise.expected_hits_per_day is not None
        assert entry.expected_noise.expected_hits_per_day >= 1
        # Phase A still provides pivots + evidence + state
        assert len(entry.pivot_questions) >= 1
        assert len(entry.evidence_checklist) >= 1
        assert entry.state == TTPState.NOT_STARTED

    # Effort estimate should reflect that queries are synthesised (cheaper)
    # rather than analyst-authored from scratch.
    assert plan.executive_summary.estimated_effort_hours is not None
    # 3 entries, all with queries -> 0.25h each = 0.75h
    assert plan.executive_summary.estimated_effort_hours == pytest.approx(0.75)
