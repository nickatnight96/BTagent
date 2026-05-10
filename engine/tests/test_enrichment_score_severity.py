"""Tests for the enrichment.score_severity Node."""

from __future__ import annotations

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.enrichment import (
    ScoreSeverityInput,
    ScoreSeverityNode,
    ScoreSeverityOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_score", org_id="org_default", investigation_id="inv_t")


async def test_score_ransomware_text_is_critical() -> None:
    out: ScoreSeverityOutput = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text="Ransomware encrypting files across finance share, ransom note dropped",
        ),
        _ctx(),
    )
    assert out.severity == "critical"
    assert out.score >= 0.5
    assert out.rationale, "ransomware-laden text must produce non-empty rationale"


async def test_score_benign_text_is_low() -> None:
    out = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text="Nightly backup completed successfully, all checksums verified.",
        ),
        _ctx(),
    )
    assert out.severity == "low"
    assert out.score < 0.25


async def test_score_t1486_forces_critical_regardless_of_text() -> None:
    """Audit-strengthening: confirmed T1486 short-circuits to critical even
    if the analyst note is calm (e.g. early IR phase). The legacy heuristic
    missed this entirely -- text-only scoring."""
    out = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text="Investigating sample, no observable behaviours yet.",
            confirmed_techniques=["T1486"],
        ),
        _ctx(),
    )
    assert out.severity == "critical"
    assert out.score >= 0.95
    assert any("T1486" in r for r in out.rationale)
    assert any("FORCE_CRITICAL" in r for r in out.rationale)


async def test_score_rationale_non_empty_when_score_above_zero() -> None:
    out = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text="Suspicious phishing attempt observed against finance team",
        ),
        _ctx(),
    )
    assert out.score > 0.0
    assert len(out.rationale) >= 1
    # Each rationale entry should encode a sign + value + reason.
    assert all(r and (":" in r) for r in out.rationale)


async def test_score_iocs_increase_score_via_capped_multiplier() -> None:
    """3 IOCs adds ~0.12; 50 IOCs hits the cap at 0.20."""
    base_text = "phishing observed"
    few = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(text=base_text, iocs=[{"type": "ipv4", "value": "1.1.1.1"}]),
        _ctx(),
    )
    many = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text=base_text,
            iocs=[{"type": "ipv4", "value": f"1.1.1.{i}"} for i in range(50)],
        ),
        _ctx(),
    )
    assert many.score > few.score
    # The cap means a 50-IOC dump cannot single-handedly push a 'phishing'
    # alert beyond high.
    assert many.severity in {"medium", "high"}


async def test_score_unknown_technique_does_not_force_critical() -> None:
    out = await Runner().execute(
        ScoreSeverityNode(),
        ScoreSeverityInput(
            text="Routine reconnaissance scan from a known partner",
            confirmed_techniques=["T1595"],  # Active Scanning -- not in force-critical set
        ),
        _ctx(),
    )
    assert out.severity != "critical"


def test_score_severity_node_is_registered() -> None:
    assert NodeRegistry.get("enrichment.score_severity") is ScoreSeverityNode
