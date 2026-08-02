"""TLP marking-generation handling on STIX import/export.

Regression cover for the fail-open found in the 2026-07 review: only the four
TLP 1.0 marking definitions were recognised, so a TLP:RED indicator from a
TLP 2.0 feed (what most commercial/ISAC TAXII 2.1 servers emit) was ingested as
``green`` and the RED egress gate never engaged.
"""

from __future__ import annotations

import pytest
from btagent_shared.stix_tlp import (
    TLP_V1_MARKINGS,
    TLP_V2_MARKINGS,
    bundle_has_red_marking,
    marking_refs_to_tlp,
    tlp_to_marking_ref,
)
from btagent_shared.types.config import TLP

from btagent_backend.services.stix_service import ioc_to_stix_indicator, stix_to_iocs

TLP_V2_RED = "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"
TLP_V2_AMBER_STRICT = "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
TLP_V1_RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
TLP_V1_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


def _bundle(*marking_refs: str) -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1e0c2b1a-0000-4000-8000-000000000001",
                "pattern": "[ipv4-addr:value = '198.51.100.7']",
                "pattern_type": "stix",
                "object_marking_refs": list(marking_refs),
            }
        ],
    }


@pytest.mark.parametrize("ref", sorted(TLP_V2_MARKINGS))
def test_every_tlp_v2_marking_is_recognised(ref: str) -> None:
    assert marking_refs_to_tlp([ref]) is TLP_V2_MARKINGS[ref]


@pytest.mark.parametrize("ref", sorted(TLP_V1_MARKINGS))
def test_every_tlp_v1_marking_is_still_recognised(ref: str) -> None:
    assert marking_refs_to_tlp([ref]) is TLP_V1_MARKINGS[ref]


def test_tlp_v2_red_indicator_imports_as_red_not_green() -> None:
    """The exact fail-open: a modern feed's RED indicator must not become green."""
    iocs = stix_to_iocs(_bundle(TLP_V2_RED))
    assert len(iocs) == 1
    assert iocs[0]["tlp_level"] == "red"


def test_tlp_v2_amber_strict_indicator_imports_as_amber_strict() -> None:
    iocs = stix_to_iocs(_bundle(TLP_V2_AMBER_STRICT))
    assert iocs[0]["tlp_level"] == "amber_strict"


def test_strictest_marking_wins_regardless_of_order() -> None:
    """A bundle carrying several markings resolves to the strictest, not the first."""
    assert marking_refs_to_tlp([TLP_V1_GREEN, TLP_V2_RED]) is TLP.RED
    assert marking_refs_to_tlp([TLP_V2_RED, TLP_V1_GREEN]) is TLP.RED


def test_unrecognised_marking_uses_the_caller_supplied_default() -> None:
    iocs = stix_to_iocs(_bundle("marking-definition--deadbeef-0000-4000-8000-000000000000"))
    assert iocs[0]["tlp_level"] == "green"

    strict = stix_to_iocs(
        _bundle("marking-definition--deadbeef-0000-4000-8000-000000000000"),
        default_tlp="amber",
    )
    assert strict[0]["tlp_level"] == "amber"


def test_amber_strict_export_is_not_downgraded_to_amber() -> None:
    """TLP 1.0 has no AMBER+STRICT; exporting it as plain AMBER was a downgrade."""
    ref = tlp_to_marking_ref(TLP.AMBER_STRICT)
    assert ref == TLP_V2_AMBER_STRICT
    assert ref != tlp_to_marking_ref(TLP.AMBER)

    indicator = ioc_to_stix_indicator(
        {"type": "ip", "value": "198.51.100.7", "confidence": 0.5},
        tlp_level="amber_strict",
    )
    assert indicator["object_marking_refs"] == [TLP_V2_AMBER_STRICT]


def test_export_refuses_rather_than_downgrades_when_generation_cannot_express_level() -> None:
    """Asking TLP 1.0 for AMBER+STRICT yields no marking, never a weaker one."""
    assert tlp_to_marking_ref(TLP.AMBER_STRICT, version="1.0") is None
    assert tlp_to_marking_ref(TLP.RED, version="1.0") == TLP_V1_RED


def test_export_marking_round_trips_through_import() -> None:
    for level in (TLP.WHITE, TLP.GREEN, TLP.AMBER, TLP.AMBER_STRICT, TLP.RED):
        ref = tlp_to_marking_ref(level)
        assert ref is not None
        assert marking_refs_to_tlp([ref]) is level


def test_red_bundle_gate_catches_both_generations() -> None:
    assert bundle_has_red_marking(_bundle(TLP_V2_RED)) is True
    assert bundle_has_red_marking(_bundle(TLP_V1_RED)) is True
    assert bundle_has_red_marking(_bundle(TLP_V1_GREEN)) is False
    assert bundle_has_red_marking(_bundle()) is False
