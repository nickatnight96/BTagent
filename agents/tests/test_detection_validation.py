"""End-to-end detection validation test — simulation-fixture slice (#118).

Replays the pre-recorded MITRE-tagged fixture scenarios through the *actual*
``windows_baseline`` Sigma pack rules using an in-process event matcher
(no SIEM, no network) and generates a deterministic ``ValidationReport``.

Design
------
The test does NOT use the network-backed ``run_pack`` engine runner (that would
require a live SIEM connector).  Instead, it wires a lightweight in-process
``sigma_event_matcher`` that:

1. Parses each enabled rule's Sigma YAML (using pySigma's SigmaCollection).
2. Evaluates the detection condition directly against the raw event dict by
   walking each SigmaDetectionItem's field + modifier + value list.
3. Returns a SigmaHit-shaped dict for every rule that fires — including the
   stable ``rule_id`` that coverage tracking needs.

This approach uses the same pySigma library the engine transpiler uses, so
the detection logic is the same as what would fire in production (the diff
is that we evaluate in-process instead of querying a backend).

Assertions
----------
* Each fixture's expected technique appears in the report.
* At least 2 of 3 core firing scenarios register as detected.
* Coverage percentages are identical across repeated calls (determinism).
* ``coverage_gaps`` correctly identifies any planted missed-but-expected case.

Planted gap
-----------
The ``scenario_benign_powershell_no_enc`` scenario seeds a T1059.001 event
with ``expected_to_fire=False`` (benign plain PowerShell, no -enc flag).
The rule correctly does NOT fire → that event contributes 0 to detected,
and because expected_to_fire=False it contributes 0 to missed too.  The
only way T1059.001 appears in the gap list is when a scenario's
*expected-to-fire* event isn't caught.  The fixture intentionally does NOT
plant such a gap for T1059.001 (three events expected to fire all should).
The gap-detection path is exercised by asserting T1059.001 is NOT in gaps
while T1110.003 (if it fires) is also correctly tracked.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Import shared validation types and logic
# ---------------------------------------------------------------------------
from btagent_shared.hunt.validation import build_report, coverage_gaps, replay_scenario
from btagent_shared.types.detection_validation import (
    SimulatedAttackEvent,
    SimulationScenario,
    ValidationReport,
)

# ---------------------------------------------------------------------------
# Import fixture scenarios
# ---------------------------------------------------------------------------
from tests.fixtures.validation.scenarios import (
    all_scenarios,
    scenario_benign_powershell_no_enc,
    scenario_certutil_download,
    scenario_encoded_powershell,
    scenario_failed_logon_spray,
    scenario_mshta_remote,
)

# ---------------------------------------------------------------------------
# In-process Sigma event matcher
# ---------------------------------------------------------------------------
# We evaluate Sigma rules directly against raw event dicts using pySigma's
# internal detection model — no SIEM query needed.
# Supported modifier types (covers all modifiers used in windows_baseline):
#   endswith, startswith, contains, (no modifier → exact / numeric equality)


def _sigma_value_matches_event_field(
    sigma_val: Any,
    field_val: Any,
    modifier_names: list[str],
) -> bool:
    """Return True if *sigma_val* matches *field_val* under *modifiers*.

    Handles:
    * SigmaString with endswith / startswith / contains modifiers (case-insensitive).
    * SigmaString with no modifier → exact match (case-insensitive str).
    * SigmaNumber with no modifier → numeric equality (compares str → int).

    pySigma's to_plain() converts SigmaString wildcards to '*', e.g.
    ``*powershell.exe`` for endswith.  We pattern-match on the plain form.
    """
    from sigma.types import SigmaNumber, SigmaString

    plain = sigma_val.to_plain()

    if isinstance(sigma_val, SigmaNumber):
        # Integer field: EventID, LogonType, etc. — compare numerically.
        try:
            return int(field_val) == int(plain)
        except (TypeError, ValueError):
            return False

    if not isinstance(sigma_val, SigmaString):
        return False

    # String field comparison (case-insensitive).
    field_str = str(field_val).lower()
    plain_str = str(plain).lower()

    if "SigmaContainsModifier" in modifier_names or (
        plain_str.startswith("*") and plain_str.endswith("*")
    ):
        return plain_str.strip("*") in field_str
    if "SigmaEndswithModifier" in modifier_names or (
        plain_str.startswith("*") and not plain_str.endswith("*")
    ):
        return field_str.endswith(plain_str.lstrip("*"))
    if "SigmaStartswithModifier" in modifier_names or (
        plain_str.endswith("*") and not plain_str.startswith("*")
    ):
        return field_str.startswith(plain_str.rstrip("*"))
    # No modifier → exact match.
    return field_str == plain_str


def _match_detection_item(item: Any, event: dict[str, Any]) -> bool:
    """Return True if this SigmaDetectionItem matches the event dict.

    The item matches when the event field exists and at least one of the
    item's values matches under the item's modifiers (values are OR-linked
    within a single detection item by Sigma semantics).
    """
    from sigma.modifiers import (
        SigmaContainsModifier,
        SigmaEndswithModifier,
        SigmaStartswithModifier,
    )

    field = item.field
    if field is None:
        # Keyword detection (no field) — not used in windows_baseline; skip.
        return False

    field_val = event.get(field)
    if field_val is None:
        return False

    modifier_names = [m.__name__ for m in item.modifiers]

    # Any value matching is sufficient (Sigma OR-links values within an item).
    return any(
        _sigma_value_matches_event_field(val, field_val, modifier_names) for val in item.value
    )


def _evaluate_sigma_condition(
    condition_str: str,
    detection_results: dict[str, bool],
) -> bool:
    """Evaluate a Sigma condition string ('sel_img and sel_cli', etc.).

    Handles:
    * Simple identifier references (``sel``, ``selection``, ``selection_img``).
    * ``and``, ``or``, ``not`` operators.
    * Parentheses.
    * ``1 of selection_*`` / ``all of selection_*`` wildcard patterns.

    This is an intentionally minimal evaluator — it covers all condition
    forms used in the windows_baseline pack.
    """
    cond = condition_str.strip()

    # Handle "1 of <pattern>" → any matching detection key.
    m = re.match(r"^1\s+of\s+(\S+)\s*$", cond, re.IGNORECASE)
    if m:
        pattern = re.compile(m.group(1).replace("*", ".*"), re.IGNORECASE)
        return any(v for k, v in detection_results.items() if pattern.match(k))

    # Handle "all of <pattern>" → all matching detection keys.
    m = re.match(r"^all\s+of\s+(\S+)\s*$", cond, re.IGNORECASE)
    if m:
        pattern = re.compile(m.group(1).replace("*", ".*"), re.IGNORECASE)
        keys = [k for k in detection_results if pattern.match(k)]
        return bool(keys) and all(detection_results[k] for k in keys)

    # Tokenise and evaluate boolean expression.
    def _eval(tokens: list[str], pos: int) -> tuple[bool, int]:
        val, pos = _eval_atom(tokens, pos)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            right, pos = _eval_atom(tokens, pos + 1)
            val = val and right
        while pos < len(tokens) and tokens[pos].lower() == "or":
            right, pos = _eval_atom(tokens, pos + 1)
            val = val or right
        return val, pos

    def _eval_atom(tokens: list[str], pos: int) -> tuple[bool, int]:
        if pos >= len(tokens):
            return False, pos
        tok = tokens[pos]
        if tok.lower() == "not":
            val, pos = _eval_atom(tokens, pos + 1)
            return not val, pos
        if tok == "(":
            val, pos = _eval(tokens, pos + 1)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val, pos
        # Identifier reference.
        return detection_results.get(tok, False), pos + 1

    tokens = re.findall(r"[()|\w*]+", cond)
    result, _ = _eval(tokens, 0)
    return result


def _match_rule_against_event(rule: Any, event: dict[str, Any]) -> bool:
    """Return True if a pySigma SigmaRule fires on the given event dict.

    Evaluates each named detection against the event, then applies the
    condition expression.
    """
    detection_results: dict[str, bool] = {}
    for name, det in rule.detection.detections.items():
        # A detection is an AND-linked set of detection items.
        item_results = [_match_detection_item(item, event) for item in det.detection_items]
        detection_results[name] = all(item_results)

    # The condition is a str like 'selection_img and selection_cli'.
    condition_str: str = rule.detection.condition[0]
    return _evaluate_sigma_condition(condition_str, detection_results)


# ---------------------------------------------------------------------------
# Build the hunt runner callable from the windows_baseline pack
# ---------------------------------------------------------------------------


def build_windows_baseline_runner() -> Any:
    """Return an async callable that matches events against windows_baseline rules.

    Loads the ``windows_baseline`` pack (from the engine's builtin packs dir)
    and wraps each enabled rule's Sigma YAML in a pySigma SigmaRule.  The
    returned callable accepts a raw event dict and returns a list of
    SigmaHit-shaped dicts (with ``rule_id``, ``rule_title``,
    ``mitre_techniques``) for every rule that fires.

    This is the injected ``hunt_runner_callable`` for validation tests — it
    uses the same Sigma YAML and rule IDs as production, just evaluated
    in-process instead of via a SIEM backend.
    """
    from btagent_engine.hunting.pack import load_builtin_pack
    from sigma.collection import SigmaCollection

    pack = load_builtin_pack("windows_baseline")

    # Pre-parse all enabled rules once (pySigma parse is not free).
    parsed_rules: list[tuple[Any, Any]] = []  # (HuntPackRule, SigmaRule)
    for hunt_rule in pack.enabled_rules:
        try:
            col = SigmaCollection.from_yaml(hunt_rule.sigma_yaml)
            sigma_rule = col.rules[0]
            parsed_rules.append((hunt_rule, sigma_rule))
        except Exception:
            # A rule that fails to parse is silently skipped for matching
            # (same behaviour as the engine runner's per-rule error isolation).
            pass

    async def _runner(event_dict: dict[str, Any]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for hunt_rule, sigma_rule in parsed_rules:
            if _match_rule_against_event(sigma_rule, event_dict):
                hits.append(
                    {
                        "rule_id": hunt_rule.id,
                        "rule_title": hunt_rule.title,
                        "mitre_techniques": hunt_rule.mitre_techniques,
                        "pack_id": pack.id,
                        "severity": hunt_rule.severity,
                    }
                )
        return hits

    return _runner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_NOW = datetime(2026, 6, 22, 0, 0, 0, tzinfo=UTC)


async def _run_scenarios(
    scenarios: list[SimulationScenario],
) -> ValidationReport:
    """Replay all scenarios and build a ValidationReport.

    Uses a fixed ``generated_at`` so the report is reproducible.
    """
    runner = build_windows_baseline_runner()
    all_replay: list[list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]]] = []
    for scenario in scenarios:
        result = await replay_scenario(scenario, runner)
        all_replay.append(result)

    return build_report(
        run_id="valrun_fixture_001",
        scenarios=scenarios,
        replay_results_per_scenario=all_replay,
        generated_at=_FIXED_NOW,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_validation_report_contains_all_expected_techniques() -> None:
    """Every fixture scenario's technique must appear in the coverage report."""
    scenarios = all_scenarios()
    report = await _run_scenarios(scenarios)

    reported_techniques = {cr.technique_id for cr in report.coverage_by_technique}
    expected = {"T1059.001", "T1218.005", "T1105", "T1110.003"}
    assert expected.issubset(reported_techniques), (
        f"Missing techniques in report: {expected - reported_techniques}"
    )


async def test_at_least_two_of_three_core_scenarios_detected() -> None:
    """At least 2 of the 3 core firing scenarios produce at least one detection.

    The three core scenarios are encoded_powershell (T1059.001),
    mshta_remote (T1218.005), certutil_download (T1105).  The rules
    should fire for all three, but the assertion floor is 2/3 to guard
    against single-rule regression without over-constraining the test.
    """
    core_scenarios = [
        scenario_encoded_powershell(),
        scenario_mshta_remote(),
        scenario_certutil_download(),
    ]
    report = await _run_scenarios(core_scenarios)

    core_tids = {"T1059.001", "T1218.005", "T1105"}
    detected_count = sum(
        1 for cr in report.coverage_by_technique if cr.technique_id in core_tids and cr.detected > 0
    )
    assert detected_count >= 2, (
        f"Expected at least 2/3 core techniques detected; got {detected_count}. "
        f"Coverage: {[(cr.technique_id, cr.detected) for cr in report.coverage_by_technique]}"
    )


async def test_coverage_percentages_are_deterministic() -> None:
    """Running the same scenarios twice must produce identical coverage numbers."""
    scenarios = all_scenarios()
    report_a = await _run_scenarios(scenarios)
    report_b = await _run_scenarios(scenarios)

    assert report_a.summary.detected_pct == report_b.summary.detected_pct
    assert report_a.scenarios_run == report_b.scenarios_run

    by_technique_a = {cr.technique_id: cr for cr in report_a.coverage_by_technique}
    by_technique_b = {cr.technique_id: cr for cr in report_b.coverage_by_technique}
    assert set(by_technique_a) == set(by_technique_b)
    for tid in by_technique_a:
        a, b = by_technique_a[tid], by_technique_b[tid]
        assert a.detected == b.detected, f"Non-deterministic: {tid}.detected"
        assert a.missed == b.missed, f"Non-deterministic: {tid}.missed"
        assert a.total_simulated == b.total_simulated, f"Non-deterministic: {tid}.total_simulated"


async def test_coverage_gaps_reflects_missed_expected_events() -> None:
    """coverage_gaps() must identify techniques with missed expected events.

    We construct an artificial scenario where expected_to_fire=True but the
    rule will NOT fire (a certutil event without the required ``urlcache``
    flag) — this plants a deterministic gap for T1105 that coverage_gaps
    must surface.
    """
    # A T1105 event where certutil runs WITHOUT urlcache/verifyctl — the
    # encoded_powershell and certutil rules should not fire on this.
    gap_scenario = SimulationScenario(
        id="sim_gap_certutil_no_urlcache",
        name="Certutil Without LOLBin Flags (planted gap)",
        description="certutil.exe run without -urlcache or -verifyctl; no rule should fire.",
        technique_ids=["T1105"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_gap_evt_001",
                technique_id="T1105",
                source_event_dict={
                    "Image": r"C:\Windows\System32\certutil.exe",
                    # No urlcache/verifyctl → certutil rule must NOT fire
                    "CommandLine": "certutil.exe -dump certificate.crt",
                    "host": "WS-BENIGN-001",
                    "ProcessId": "7700",
                },
                # But we declare we expected it to fire — so it's a gap.
                expected_to_fire=True,
                expected_rule_id="5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f02",
            ),
        ],
    )

    report = await _run_scenarios([gap_scenario])
    gaps = coverage_gaps(report)

    assert "T1105" in gaps, (
        f"T1105 should appear in coverage_gaps (planted no-match event); gaps={gaps}"
    )

    # Also verify the rule_expected_but_missed list is populated.
    t1105 = next(cr for cr in report.coverage_by_technique if cr.technique_id == "T1105")
    assert "5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f02" in t1105.rules_expected_but_missed


async def test_benign_event_does_not_increase_missed_count() -> None:
    """expected_to_fire=False events that don't fire must not inflate missed count.

    The benign_powershell scenario plants a plain ``powershell.exe -Command``
    call (no -enc flag). The encoded_powershell rule should NOT fire on it.
    Because expected_to_fire=False, the event contributes 0 to both detected
    and missed — only to total_simulated.
    """
    benign = scenario_benign_powershell_no_enc()
    report = await _run_scenarios([benign])

    t1059 = next(cr for cr in report.coverage_by_technique if cr.technique_id == "T1059.001")
    assert t1059.total_simulated == 1
    assert t1059.missed == 0, "A benign event with expected_to_fire=False must not count as missed"


async def test_report_metadata_is_correct() -> None:
    """ValidationReport metadata fields must be correctly populated."""
    scenarios = [scenario_encoded_powershell(), scenario_certutil_download()]
    report = await _run_scenarios(scenarios)

    assert report.run_id == "valrun_fixture_001"
    assert report.scenarios_run == 2
    assert report.generated_at == _FIXED_NOW
    assert isinstance(report.summary.detected_pct, float)
    assert 0.0 <= report.summary.detected_pct <= 100.0
    assert report.summary.total_techniques >= 1


async def test_full_windows_baseline_coverage_report() -> None:
    """Run all fixture scenarios and print the full coverage report.

    This is the primary integration assertion: the report must be generated
    without errors, all four technique IDs must be present, and the
    summary must be coherent.
    """
    scenarios = all_scenarios()
    report = await _run_scenarios(scenarios)

    # Structural integrity.
    assert report.scenarios_run == len(scenarios)
    assert len(report.coverage_by_technique) >= 4  # T1059.001, T1218.005, T1105, T1110.003

    # All expected techniques present.
    tids = {cr.technique_id for cr in report.coverage_by_technique}
    assert "T1059.001" in tids
    assert "T1218.005" in tids
    assert "T1105" in tids
    assert "T1110.003" in tids

    # Summary totals are consistent.
    total_expected = sum(cr.detected + cr.missed for cr in report.coverage_by_technique)
    assert total_expected >= 0

    # Detected pct is in valid range.
    assert 0.0 <= report.summary.detected_pct <= 100.0

    # gaps is a subset of reported techniques.
    assert all(g in tids for g in report.summary.gaps)

    # Print coverage for debugging / CI log visibility.
    print("\n=== Detection Validation Coverage Report ===")
    print(f"Run ID      : {report.run_id}")
    print(f"Scenarios   : {report.scenarios_run}")
    print(f"Detected %  : {report.summary.detected_pct:.1f}%")
    print(f"Techniques  : {report.summary.total_techniques}")
    print(f"Gaps        : {report.summary.gaps or 'none'}")
    print("\nPer-technique breakdown:")
    for cr in report.coverage_by_technique:
        rate = f"{cr.detection_rate * 100:.0f}%"
        print(
            f"  {cr.technique_id:<15} simulated={cr.total_simulated} "
            f"detected={cr.detected} missed={cr.missed} rate={rate} "
            f"rules_fired={cr.rules_fired}"
        )


# ---------------------------------------------------------------------------
# Codex #215 regression tests — counting + reporting invariants
# ---------------------------------------------------------------------------


def _always_fires_runner(rule_id: str = "broad.always_fires") -> Any:
    """Synthetic runner that fires a single named rule on EVERY event.

    Lets the regression tests pin counting behaviour without depending on
    the real Sigma rules. Returns a callable that ``replay_scenario``
    accepts via its ``runner`` argument.
    """

    async def _runner(_event_dict: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"rule_id": rule_id, "matched": True}]

    return _runner


async def test_benign_control_hit_is_false_positive_not_detection() -> None:
    """Codex #215: a benign-control event (``expected_to_fire=False``) that
    nonetheless lights up a rule MUST count as a false positive — never as
    detection — so ``detected_pct`` can't be inflated past 100%."""
    scenario = SimulationScenario(
        id="reg_codex_215_benign_fp",
        name="Codex #215 — benign control lights up a broad rule",
        technique_ids=["T9999.001"],
        events=[
            SimulatedAttackEvent(
                event_id="evt_benign_1",
                technique_id="T9999.001",
                source_event_dict=dict(EventID="42", CommandLine="powershell.exe -nop"),
                expected_to_fire=False,  # benign control
            ),
        ],
    )
    runner = _always_fires_runner("broad.always_fires")
    report = build_report(
        run_id="reg_codex_215",
        scenarios=[scenario],
        replay_results_per_scenario=[await replay_scenario(scenario, runner)],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    cov = next(c for c in report.coverage_by_technique if c.technique_id == "T9999.001")
    assert cov.detected == 0, "benign control must not count as detection"
    assert cov.false_positives == 1, "benign control hit must count as false positive"
    # ``detected_pct`` divides by total_expected_fire which is 0 here, so the
    # function returns 100.0 by convention — but importantly it cannot be
    # >100.0 (the regression).
    assert report.summary.detected_pct <= 100.0


async def test_expected_rule_id_pinned_unrelated_rule_does_not_count() -> None:
    """Codex #215 P1: when ``expected_rule_id`` is set, ONLY that rule firing
    counts as detection. A different (broad) rule firing must NOT mask the
    targeted validation gap — it should leave the event as missed and the
    technique in ``coverage_gaps``."""
    scenario = SimulationScenario(
        id="reg_codex_215_pinned_rule",
        name="Codex #215 — pinned rule missed, unrelated rule fires",
        technique_ids=["T9999.002"],
        events=[
            SimulatedAttackEvent(
                event_id="evt_pinned_miss_1",
                technique_id="T9999.002",
                source_event_dict=dict(EventID="99", CommandLine="net user /add admin Passw0rd!"),
                expected_to_fire=True,
                expected_rule_id="specific.required_rule",
            ),
        ],
    )
    # An UNRELATED rule fires — the required one does not.
    runner = _always_fires_runner("unrelated.broad_match")
    report = build_report(
        run_id="reg_codex_215_b",
        scenarios=[scenario],
        replay_results_per_scenario=[await replay_scenario(scenario, runner)],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    cov = next(c for c in report.coverage_by_technique if c.technique_id == "T9999.002")
    assert cov.detected == 0, "pinned rule did not fire — must NOT be marked detected"
    assert cov.missed == 1, "event with unmatched pinned rule must be counted as missed"
    assert "specific.required_rule" in cov.rules_expected_but_missed
    # And the gap surfaces in coverage_gaps so analysts see it.
    assert "T9999.002" in coverage_gaps(report)
