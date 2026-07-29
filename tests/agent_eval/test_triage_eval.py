"""Eval: triage tools vs the golden alert corpus (#382).

Evaluates the two deterministic triage tools the TriagePlugin exposes to the
LLM. In mock mode these ARE the triage verdicts, and in live mode the LLM's
answer is anchored on their output — so their aggregate accuracy on golden
alerts is the floor of triage quality either way.

The tools are LangChain ``@tool`` objects; ``.func`` is the undecorated
callable.
"""

from __future__ import annotations

from conftest import format_cases, load_golden  # type: ignore[import-not-found]

from btagent_agents.plugins.triage.tools.alert_classifier import alert_classifier
from btagent_agents.plugins.triage.tools.severity_scorer import severity_scorer

# Current performance is 1.0 across the board; thresholds leave headroom for
# legitimate borderline churn as heuristics evolve (see conftest docstring).
MIN_CATEGORY_ACCURACY = 0.90
MIN_SEVERITY_ACCURACY = 0.80  # classifier severity: exact match
MIN_SCORER_ACCURACY = 0.80  # scorer level: exact match

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def test_classifier_category_accuracy() -> None:
    golden = load_golden("triage_alerts.yaml")

    rows: list[tuple[str, bool, str]] = []
    correct = 0
    for case in golden["classifier"]:
        got = alert_classifier.func(case["text"])["classification"]["category"]
        ok = got == case["category"]
        correct += ok
        rows.append((case["id"], ok, f"got {got}, want {case['category']}"))

    accuracy = correct / len(rows)
    assert accuracy >= MIN_CATEGORY_ACCURACY, (
        f"alert_classifier category accuracy {accuracy:.3f} < {MIN_CATEGORY_ACCURACY}:\n"
        + format_cases(rows)
    )


def test_classifier_severity_accuracy() -> None:
    golden = load_golden("triage_alerts.yaml")

    rows: list[tuple[str, bool, str]] = []
    correct = 0
    adjacent_or_better = 0
    for case in golden["classifier"]:
        got = alert_classifier.func(case["text"])["classification"]["severity"]
        ok = got == case["severity"]
        correct += ok
        distance = abs(_SEVERITY_ORDER.index(got) - _SEVERITY_ORDER.index(case["severity"]))
        adjacent_or_better += distance <= 1
        rows.append((case["id"], ok, f"got {got}, want {case['severity']}"))

    accuracy = correct / len(rows)
    assert accuracy >= MIN_SEVERITY_ACCURACY, (
        f"alert_classifier severity accuracy {accuracy:.3f} < {MIN_SEVERITY_ACCURACY}:\n"
        + format_cases(rows)
    )
    # A miss by more than one severity band is never acceptable churn — a
    # "critical" alert triaged "low" is a paging failure, not a borderline.
    assert adjacent_or_better == len(rows), (
        "alert_classifier severity missed by more than one band:\n" + format_cases(rows)
    )


def test_scorer_level_accuracy() -> None:
    golden = load_golden("triage_alerts.yaml")

    rows: list[tuple[str, bool, str]] = []
    correct = 0
    adjacent_or_better = 0
    for case in golden["scorer"]:
        result = severity_scorer.func(case["details"])
        got = result["severity"]
        ok = got == case["severity"]
        correct += ok
        distance = abs(_SEVERITY_ORDER.index(got) - _SEVERITY_ORDER.index(case["severity"]))
        adjacent_or_better += distance <= 1
        rows.append((case["id"], ok, f"got {got}, want {case['severity']} ({result['scores']})"))

    accuracy = correct / len(rows)
    assert accuracy >= MIN_SCORER_ACCURACY, (
        f"severity_scorer level accuracy {accuracy:.3f} < {MIN_SCORER_ACCURACY}:\n"
        + format_cases(rows)
    )
    assert adjacent_or_better == len(rows), (
        "severity_scorer missed by more than one band:\n" + format_cases(rows)
    )


def test_classifier_output_contract() -> None:
    """The structured contract the plugin prompt and stores rely on."""
    golden = load_golden("triage_alerts.yaml")
    result = alert_classifier.func(golden["classifier"][0]["text"])
    assert set(result) >= {"classification", "iocs", "ioc_count", "mitre_techniques", "summary"}
    assert set(result["classification"]) == {"category", "confidence", "severity"}
    assert result["ioc_count"] == len(result["iocs"])
