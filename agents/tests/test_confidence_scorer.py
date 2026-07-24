"""Unit tests for the enrichment confidence-scoring tool.

Exercises the ``score_confidence`` ``@tool`` wrapper, focusing on the #403 fix:
JSON that parses to a *non-object* root (array, string, number, bool, null) must
be handled gracefully instead of crashing on ``.get`` on a non-dict.
"""

from __future__ import annotations

import json

from btagent_agents.plugins.enrichment.tools.confidence_scorer import score_confidence

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_scores_object_input() -> None:
    payload = {
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
        "source_results": [
            {
                "source": "virustotal",
                "verdict": "malicious",
                "details": {"detection_ratio": "40/70"},
            },
            {
                "source": "abuseipdb",
                "verdict": "malicious",
                "details": {"abuse_confidence_score": 90},
            },
        ],
    }
    out = score_confidence.invoke({"enrichment_json": json.dumps(payload)})
    assert "error" not in out
    assert 0.0 <= out["confidence"] <= 1.0
    assert out["sources_evaluated"] == 2
    assert out["recommended_action"] in {"block", "investigate", "monitor", "dismiss"}


# ---------------------------------------------------------------------------
# #403 -- non-object JSON must not crash
# ---------------------------------------------------------------------------


def test_json_array_input_is_handled_gracefully() -> None:
    out = score_confidence.invoke({"enrichment_json": "[1, 2, 3]"})
    assert out["confidence"] == 0.0
    assert "error" in out
    assert "object" in out["error"].lower()


def test_json_string_input_is_handled_gracefully() -> None:
    out = score_confidence.invoke({"enrichment_json": '"just a string"'})
    assert out["confidence"] == 0.0
    assert "error" in out


def test_json_number_input_is_handled_gracefully() -> None:
    out = score_confidence.invoke({"enrichment_json": "42"})
    assert out["confidence"] == 0.0
    assert "error" in out


def test_json_null_input_is_handled_gracefully() -> None:
    out = score_confidence.invoke({"enrichment_json": "null"})
    assert out["confidence"] == 0.0
    assert "error" in out


def test_invalid_json_still_reports_decode_error() -> None:
    """Regression: the pre-existing JSONDecodeError path must be untouched."""
    out = score_confidence.invoke({"enrichment_json": "{not json"})
    assert out["confidence"] == 0.0
    assert "error" in out
