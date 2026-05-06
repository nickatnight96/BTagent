"""Tests for MitreMapperNode -- keyword -> ATT&CK technique suggester.

Covers:

* Known-keyword match returns the right technique id (PowerShell -> T1059.001).
* Word-boundary matching: ``"collateral damage"`` does **not** trigger
  ``"lateral movement"`` -- the regression the agents-side substring matcher
  shipped.
* ``min_confidence`` filters low-signal matches.
* Empty input returns no techniques and zero coverage.
* Output ordering is deterministic (confidence desc, id asc) across runs.
* Coverage is > 0 when at least one keyword matches.
* Multiple keywords for the same technique deduplicate to one row with the
  highest-confidence keyword winning.
"""

from __future__ import annotations

from btagent_engine import NodeContext, Runner
from btagent_engine.data import (
    MitreMapperInput,
    MitreMapperNode,
    MitreMapperOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_mitre", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_powershell_text_maps_to_t1059_001():
    out = await MitreMapperNode().run(
        MitreMapperInput(text="Suspicious PowerShell process spawned by office.exe"),
        _ctx(),
    )
    assert isinstance(out, MitreMapperOutput)
    ids = [t.technique_id for t in out.techniques]
    assert "T1059.001" in ids
    match = next(t for t in out.techniques if t.technique_id == "T1059.001")
    assert match.name == "PowerShell"
    assert match.confidence >= 0.9
    assert "powershell" in match.matched_keywords


async def test_coverage_positive_when_any_match():
    out = await MitreMapperNode().run(
        MitreMapperInput(text="ransomware encrypted user files on host"),
        _ctx(),
    )
    assert out.coverage > 0.0
    assert out.coverage <= 1.0
    assert any(t.technique_id == "T1486" for t in out.techniques)


# --------------------------------------------------------------------------- #
# Word-boundary correctness (audit regression)
# --------------------------------------------------------------------------- #


async def test_collateral_does_not_match_lateral_movement():
    """``"lateral movement"`` is a keyword for T1021 -- but ``"collateral"``
    must not trigger it. The agents-side substring matcher fired here; the
    engine port uses word-boundary matching to fix it."""
    out = await MitreMapperNode().run(
        MitreMapperInput(
            text="Some collateral damage but no actual movement detected.",
        ),
        _ctx(),
    )
    ids = [t.technique_id for t in out.techniques]
    assert "T1021" not in ids


async def test_substring_within_token_does_not_match():
    """``"rdp"`` must not fire on ``"wordprdpacked"`` or similar gibberish
    that happens to contain the letters."""
    out = await MitreMapperNode().run(
        MitreMapperInput(text="The word grdpa appears but not the protocol."),
        _ctx(),
    )
    ids = [t.technique_id for t in out.techniques]
    assert "T1021.001" not in ids


# --------------------------------------------------------------------------- #
# Filter / edge cases
# --------------------------------------------------------------------------- #


async def test_min_confidence_filters_low_signal_matches():
    """Bumping ``min_confidence`` above the keyword's confidence drops it."""
    text = "command shell launched by the parent process"
    permissive = await MitreMapperNode().run(
        MitreMapperInput(text=text, min_confidence=0.5),
        _ctx(),
    )
    strict = await MitreMapperNode().run(
        MitreMapperInput(text=text, min_confidence=0.85),
        _ctx(),
    )
    permissive_ids = {t.technique_id for t in permissive.techniques}
    strict_ids = {t.technique_id for t in strict.techniques}
    # "command shell" is keyworded at 0.7, so the strict run drops T1059.003
    assert "T1059.003" in permissive_ids
    assert "T1059.003" not in strict_ids


async def test_empty_text_returns_empty_techniques():
    out = await MitreMapperNode().run(
        MitreMapperInput(text=""),
        _ctx(),
    )
    assert out.techniques == []
    assert out.coverage == 0.0


async def test_no_match_returns_empty_techniques():
    out = await MitreMapperNode().run(
        MitreMapperInput(text="The quick brown fox jumps over the lazy dog."),
        _ctx(),
    )
    assert out.techniques == []
    assert out.coverage == 0.0


# --------------------------------------------------------------------------- #
# Ordering + dedup
# --------------------------------------------------------------------------- #


async def test_output_ordering_is_deterministic():
    """Same input twice must produce the same ordering. The contract is
    confidence desc, then technique_id asc as the tiebreaker."""
    text = (
        "Attacker dropped mimikatz to dump credentials, then used "
        "powershell for lateral movement and scheduled task persistence."
    )
    a = await MitreMapperNode().run(MitreMapperInput(text=text), _ctx())
    b = await MitreMapperNode().run(MitreMapperInput(text=text), _ctx())
    assert [t.technique_id for t in a.techniques] == [
        t.technique_id for t in b.techniques
    ]
    confidences = [t.confidence for t in a.techniques]
    assert confidences == sorted(confidences, reverse=True)


async def test_multiple_keywords_for_same_technique_dedupe():
    """``mimikatz`` (0.95) and ``credential dump`` (0.85) both map to T1003;
    one row should be returned with the higher confidence."""
    out = await MitreMapperNode().run(
        MitreMapperInput(text="mimikatz performed a credential dump on the host"),
        _ctx(),
    )
    t1003 = [t for t in out.techniques if t.technique_id == "T1003"]
    assert len(t1003) == 1
    assert t1003[0].confidence == 0.95
    assert set(t1003[0].matched_keywords) >= {"mimikatz", "credential dump"}


# --------------------------------------------------------------------------- #
# End-to-end through the Runner
# --------------------------------------------------------------------------- #


async def test_dict_payload_through_runner():
    runner = Runner()
    out = await runner.execute(
        MitreMapperNode(),
        {"text": "RDP brute force attempt detected"},
        _ctx(),
    )
    assert isinstance(out, MitreMapperOutput)
    ids = {t.technique_id for t in out.techniques}
    assert "T1021.001" in ids
    assert "T1110" in ids
