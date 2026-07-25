"""Tests for the STIX -> Sigma pipeline's defensive handling of malformed input (#408).

The shared ``btagent_shared.hunt.cti_to_detection`` module lives outside any
package test dir; the engine test suite already puts ``shared`` on ``sys.path``
(see ``engine/tests/conftest.py``), so the pipeline is exercised here.

Focus: a malformed ``confidence`` (non-int) previously raised TypeError and a
malformed ``kill_chain_phases`` (not a list of objects) raised AttributeError —
both unhandled, surfacing as HTTP 500. They must now yield a normal proposal
(coerced / skipped values), never an exception.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.hunt.cti_to_detection import process_stix_bundle
from btagent_shared.types.config import TLP


def _bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "bundle", "id": "bundle--test-408", "objects": objects}


def _indicator(**over: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--408-default",
        "name": "Test IP",
        "pattern": "[ipv4-addr:value = '198.51.100.5']",
        "pattern_type": "stix",
    }
    obj.update(over)
    return obj


# ---------------------------------------------------------------------------
# Positive control
# ---------------------------------------------------------------------------


def test_valid_indicator_still_processed() -> None:
    bundle = _bundle(
        [
            _indicator(
                id="indicator--408-valid",
                confidence=85,
                kill_chain_phases=[
                    {"kill_chain_name": "mitre-attack", "phase_name": "T1071.001"},
                ],
            )
        ]
    )
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(resp.proposals) == 1
    prop = resp.proposals[0]
    assert prop.confidence == 0.85
    assert "T1071.001" in prop.technique_ids


# ---------------------------------------------------------------------------
# #408 -- malformed confidence must not 500
# ---------------------------------------------------------------------------


def test_malformed_confidence_string_defaults_and_does_not_raise() -> None:
    bundle = _bundle([_indicator(id="indicator--408-conf", confidence="high")])
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(resp.proposals) == 1
    # 'high' can't be coerced -> neutral 50 -> 0.5
    assert resp.proposals[0].confidence == 0.5


def test_malformed_confidence_various_types_do_not_raise() -> None:
    for i, bad in enumerate((None, [1, 2], {"x": 1}, "not-a-number")):
        bundle = _bundle([_indicator(id=f"indicator--408-conf-{i}", confidence=bad)])
        resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
        assert len(resp.proposals) == 1, f"confidence={bad!r} produced no proposal"
        assert 0.0 <= resp.proposals[0].confidence <= 1.0


def test_numeric_string_confidence_is_still_coerced() -> None:
    bundle = _bundle([_indicator(id="indicator--408-conf-str", confidence="80")])
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert resp.proposals[0].confidence == 0.8


# ---------------------------------------------------------------------------
# #408 -- malformed kill_chain_phases must not 500
# ---------------------------------------------------------------------------


def test_kill_chain_phases_not_a_list_does_not_raise() -> None:
    bundle = _bundle([_indicator(id="indicator--408-kcp1", kill_chain_phases="mitre-attack")])
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(resp.proposals) == 1  # no crash; phases ignored


def test_kill_chain_phases_with_non_dict_items_does_not_raise() -> None:
    bundle = _bundle(
        [_indicator(id="indicator--408-kcp2", kill_chain_phases=["execution", 42, None])]
    )
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(resp.proposals) == 1  # non-dict phases skipped, no AttributeError


def test_both_fields_malformed_together_does_not_raise() -> None:
    bundle = _bundle(
        [
            _indicator(
                id="indicator--408-both",
                confidence=["not", "intable"],  # int([...]) raises TypeError
                kill_chain_phases={"not": "a list"},
            )
        ]
    )
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(resp.proposals) == 1
    assert 0.0 <= resp.proposals[0].confidence <= 1.0
