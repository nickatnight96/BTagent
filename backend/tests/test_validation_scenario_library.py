"""Tests for the expanded #118 validation scenario library.

Three things are asserted here:

* **Breadth** — the library covers >= 20 distinct ATT&CK techniques (the
  coverage heat-map's reason to exist) and every technique it claims is
  referenced by at least one rule in the packs it is replayed against.
* **Fidelity** — replaying the library through the real pySigma matcher fires a
  rule for every ``expected_to_fire`` event and fires NOTHING for the
  false-positive control events.
* **Matcher correctness** — the condition evaluator handles parentheses,
  precedence and ``N of`` selectors, and a list-of-mappings detection (the cloud
  packs' shape) no longer raises.

Fully in-process and synthetic — zero network egress.
"""

from __future__ import annotations

import pytest

from btagent_backend.services.validation_scenarios import (
    default_validation_packs,
    default_validation_scenarios,
    scenario_technique_ids,
)
from btagent_backend.services.validation_service import (
    _build_sigma_event_runner,
    _evaluate_condition,
    run_validation,
)

MIN_TECHNIQUES = 20


def test_library_covers_at_least_twenty_techniques() -> None:
    techniques = scenario_technique_ids()
    assert len(techniques) >= MIN_TECHNIQUES, techniques
    # Every id is a well-formed ATT&CK technique / sub-technique.
    for technique in techniques:
        assert technique.startswith("T")
        assert technique[1:].replace(".", "").isdigit(), technique


def test_scenarios_are_well_formed_and_unique() -> None:
    scenarios = default_validation_scenarios()
    assert len(scenarios) >= MIN_TECHNIQUES
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "scenario ids must be unique"
    event_ids = [e.event_id for s in scenarios for e in s.events]
    assert len(event_ids) == len(set(event_ids)), "event ids must be unique"
    for scenario in scenarios:
        assert scenario.events, scenario.id
        for event in scenario.events:
            assert event.source_event_dict, event.event_id

    # The library deliberately carries false-positive controls.
    controls = [e for s in scenarios for e in s.events if not e.expected_to_fire]
    assert len(controls) >= 3


@pytest.mark.asyncio
async def test_library_techniques_are_referenced_by_the_replay_packs() -> None:
    """Every technique the library claims is one our own packs actually cover."""
    pack_techniques: set[str] = set()
    for pack_name in default_validation_packs():
        from btagent_engine.hunting.pack import load_builtin_pack

        for rule in load_builtin_pack(pack_name).enabled_rules:
            pack_techniques.update(rule.mitre_techniques or [])

    missing = sorted(set(scenario_technique_ids()) - pack_techniques)
    assert not missing, f"scenarios reference techniques no enabled pack rule covers: {missing}"


@pytest.mark.asyncio
async def test_full_replay_detects_every_expected_event_and_no_controls() -> None:
    scenarios = default_validation_scenarios()
    report = await run_validation(scenarios, default_validation_packs())

    assert report.scenarios_run == len(scenarios)
    assert report.summary.total_techniques >= MIN_TECHNIQUES
    # Every expected-to-fire event is detected → no coverage gaps, and no
    # benign control event fired a rule (false_positives stays at zero).
    assert report.summary.gaps == []
    assert report.summary.detected_pct == 100.0
    assert all(c.false_positives == 0 for c in report.coverage_by_technique)
    assert all(c.missed == 0 for c in report.coverage_by_technique)


@pytest.mark.asyncio
async def test_control_events_fire_nothing_through_the_real_runner() -> None:
    runners = [_build_sigma_event_runner(p) for p in default_validation_packs()]
    controls = [
        event
        for scenario in default_validation_scenarios()
        for event in scenario.events
        if not event.expected_to_fire
    ]
    assert controls
    for event in controls:
        for runner in runners:
            hits = await runner(event.source_event_dict)
            assert hits == [], f"control {event.event_id} fired {hits}"


class TestConditionEvaluator:
    """Regression cover for the Sigma condition parser."""

    def test_parenthesised_group_is_not_glued_to_its_identifier(self) -> None:
        # Was the bug: the tokenizer produced "(sel_b" and every parenthesised
        # condition silently evaluated to False.
        results = {"sel_a": True, "sel_b": False, "sel_c": True}
        assert _evaluate_condition("sel_a and (sel_b or sel_c)", results) is True
        assert _evaluate_condition("sel_a and (sel_b or not sel_c)", results) is False

    def test_precedence_not_over_and_over_or(self) -> None:
        results = {"a": True, "b": False, "c": True}
        assert _evaluate_condition("a and b or c", results) is True
        assert _evaluate_condition("b or a and c", results) is True
        assert _evaluate_condition("not b and a", results) is True

    def test_selector_forms(self) -> None:
        results = {"selection_x": False, "selection_y": True, "filter_z": False}
        assert _evaluate_condition("1 of selection_*", results) is True
        assert _evaluate_condition("all of selection_*", results) is False
        assert _evaluate_condition("1 of them", results) is True
        assert _evaluate_condition("1 of selection_* and not filter_z", results) is True

    def test_unknown_identifier_is_false_not_an_error(self) -> None:
        assert _evaluate_condition("nope", {}) is False


@pytest.mark.asyncio
async def test_list_of_mappings_detection_does_not_raise() -> None:
    """A cloud rule whose detection is a list of mappings (OR-linked) matches.

    Previously raised ``AttributeError: 'SigmaDetection' object has no attribute
    'field'`` and sank the entire replay run.
    """
    runner = _build_sigma_event_runner("credential_access_cloud")
    hits = await runner(
        {
            "eventSource": "iam.amazonaws.com",
            "eventName": "UpdateAccountPasswordPolicy",
            "requestParameters.requireSymbols": False,
        }
    )
    assert any("T1556" in (h.get("mitre_techniques") or []) for h in hits), hits
