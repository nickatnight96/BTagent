"""Tests for CoverageGapNode (UC-4.2, #107)."""

from __future__ import annotations

from btagent_engine import NodeContext
from btagent_engine.data import (
    CoverageGapInput,
    CoverageGapNode,
    CoverageGapOutput,
    TechniqueRef,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_cov", org_id="org_test")


async def test_default_universe_with_partial_coverage():
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=["T1059.001", "T1110"]),
        _ctx(),
    )
    assert isinstance(out, CoverageGapOutput)
    r = out.report
    assert r.coverage_map.total_techniques == 10  # default universe size
    assert r.coverage_map.covered_techniques == 2
    # 8 uncovered -> in the flat list + sigma drafts
    assert len(r.uncovered_technique_ids) == 8
    assert "T1059.001" not in r.uncovered_technique_ids
    assert "T1486" in r.uncovered_technique_ids


async def test_full_coverage_yields_no_gaps():
    universe = [
        TechniqueRef(technique_id="T1", tactic="execution"),
        TechniqueRef(technique_id="T2", tactic="impact"),
    ]
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=["T1", "T2"], universe=universe),
        _ctx(),
    )
    assert out.report.uncovered_technique_ids == []
    assert out.report.gaps == []
    assert out.report.sigma_drafts == []
    assert out.report.coverage_map.covered_techniques == 2


async def test_gaps_grouped_by_tactic():
    universe = [
        TechniqueRef(technique_id="T1", tactic="execution"),
        TechniqueRef(technique_id="T2", tactic="execution"),
        TechniqueRef(technique_id="T3", tactic="impact"),
    ]
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=[], universe=universe),
        _ctx(),
    )
    by_tactic = {g.tactic: g.techniques_without_detection for g in out.report.gaps}
    assert set(by_tactic["execution"]) == {"T1", "T2"}
    assert by_tactic["impact"] == ["T3"]


async def test_sigma_drafts_generated_for_gaps():
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=[]),  # nothing covered
        _ctx(),
    )
    # default universe has 10 techniques, draft cap is 10
    assert len(out.report.sigma_drafts) == 10
    draft = out.report.sigma_drafts[0]
    assert draft.technique_id
    assert "attack." in draft.sigma_yaml
    assert "no detection" in draft.rationale


async def test_sigma_drafts_suppressible():
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=[], draft_sigma=False),
        _ctx(),
    )
    assert out.report.sigma_drafts == []
    # gaps still reported even without drafts
    assert len(out.report.uncovered_technique_ids) == 10


async def test_window_days_propagates():
    out = await CoverageGapNode().run(
        CoverageGapInput(covered_technique_ids=[], window_days=90), _ctx()
    )
    assert out.report.window_days == 90
