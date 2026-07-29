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


# ---------------------------------------------------------------------------
# Unstructured report → synthetic bundle (#113 back half)
# ---------------------------------------------------------------------------

_REPORT = """
APT Frostline phishing campaign: spearphishing emails from
billing[at]invoice-portal[.]net delivered a macro dropper (sha256
9f2b4c1a8d3e5f60718293a4b5c6d7e8f9012345678901234567890abcdef012 ) which
spawned powershell with an encoded command beaconing to
hxxps://cdn-metrics[.]net/api and 203.0.113.77. Lateral movement via
pass-the-hash and psexec followed. Internal host 10.0.0.5 was patient zero.
"""


def test_report_text_extracts_defanged_iocs() -> None:
    """Defanged hxxps:// / [.] / [at] forms are refanged and extracted."""
    from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text

    bundle = stix_bundle_from_report_text(_REPORT, report_name="Frostline")
    patterns = {o["pattern"] for o in bundle["objects"]}
    assert (
        "[file:hashes.'SHA-256' = "
        "'9f2b4c1a8d3e5f60718293a4b5c6d7e8f9012345678901234567890abcdef012']" in patterns
    )
    assert "[url:value = 'https://cdn-metrics.net/api']" in patterns
    assert "[email-addr:value = 'billing@invoice-portal.net']" in patterns
    assert "[ipv4-addr:value = '203.0.113.77']" in patterns


def test_report_text_skips_internal_ips_and_shadowed_domains() -> None:
    """RFC1918 victim addressing and URL-host/email-domain shadows are not
    independent indicators."""
    from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text

    bundle = stix_bundle_from_report_text(_REPORT)
    patterns = "\n".join(o["pattern"] for o in bundle["objects"])
    assert "10.0.0.5" not in patterns
    # cdn-metrics.net appears only as the URL's host; invoice-portal.net only
    # as the email's domain — neither becomes a standalone domain indicator.
    assert "[domain-name:value = 'cdn-metrics.net']" not in patterns
    assert "[domain-name:value = 'invoice-portal.net']" not in patterns


def test_report_text_bundle_is_deterministic() -> None:
    """Same text → same bundle id and indicator ids (re-submit upserts)."""
    from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text

    assert stix_bundle_from_report_text(_REPORT) == stix_bundle_from_report_text(_REPORT)


def test_report_text_no_iocs_raises() -> None:
    """Prose with nothing actionable must raise, not yield an empty bundle."""
    import pytest as _pytest
    from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text

    with _pytest.raises(ValueError, match="No supported IOCs"):
        stix_bundle_from_report_text("The quarterly threat landscape remained calm.")


def test_report_text_end_to_end_proposals_with_context_techniques() -> None:
    """The synthetic bundle runs the normal pipeline and each proposal picks
    up ATT&CK techniques from the prose surrounding its IOC."""
    from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text

    bundle = stix_bundle_from_report_text(_REPORT, report_name="Frostline")
    response = process_stix_bundle(bundle, active_tlp=TLP.GREEN)
    assert len(response.proposals) == 4
    email = next(p for p in response.proposals if "Email" in p.title)
    # The email sits in spearphishing prose — the keyword mapper should tag it.
    assert "T1566.001" in email.technique_ids
