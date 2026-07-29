"""Eval: MITRE keyword mapper vs the golden alert corpus (#382).

Guards the ``mitre_keywords.yaml`` table (245+ entries) and the mapper's
matching behaviour. The failure modes this catches:

* a keyword row deleted or its technique_id typo'd → recall drops;
* matching made overly aggressive (e.g. reverting word-boundary decisions
  or adding low-quality keywords) → benign texts start firing
  high-confidence techniques.
"""

from __future__ import annotations

from conftest import format_cases, load_golden  # type: ignore[import-not-found]

from btagent_agents.mitre.mapper import MitreMapper

# Aggregate thresholds. Current performance is 1.0 on both sides; the gap
# down to the threshold is headroom for legitimate borderline churn as the
# keyword table evolves, not an accuracy target.
MIN_MEAN_RECALL = 0.90
# Confidence at which downstream consumers (triage hints, coverage analysis)
# treat a suggestion as a real signal — benign text must stay below it.
HIGH_CONFIDENCE = 0.80


def test_golden_recall() -> None:
    """Mean per-case recall of expected techniques must clear the threshold."""
    golden = load_golden("mitre_mapping.yaml")
    mapper = MitreMapper()

    rows: list[tuple[str, bool, str]] = []
    recalls: list[float] = []
    for case in golden["positive"]:
        suggested = {s.technique_id for s in mapper.suggest_techniques(case["text"])}
        expected = set(case["expected"])
        found = expected & suggested
        recall = len(found) / len(expected)
        recalls.append(recall)
        rows.append(
            (
                case["id"],
                recall == 1.0,
                f"recall {recall:.2f}"
                + (f", missing {sorted(expected - suggested)}" if expected - suggested else ""),
            )
        )

    mean_recall = sum(recalls) / len(recalls)
    assert mean_recall >= MIN_MEAN_RECALL, (
        f"MITRE mapper mean recall {mean_recall:.3f} < {MIN_MEAN_RECALL} "
        f"over {len(recalls)} golden cases:\n" + format_cases(rows)
    )


def test_benign_text_stays_quiet() -> None:
    """No benign golden text may fire a high-confidence technique."""
    golden = load_golden("mitre_mapping.yaml")
    mapper = MitreMapper()

    rows: list[tuple[str, bool, str]] = []
    clean = True
    for case in golden["negative"]:
        hits = [
            (s.technique_id, s.keyword_matched, s.confidence)
            for s in mapper.suggest_techniques(case["text"])
            if s.confidence >= HIGH_CONFIDENCE
        ]
        ok = not hits
        clean = clean and ok
        rows.append((case["id"], ok, "clean" if ok else f"fired {hits}"))

    assert clean, (
        f"Benign text fired technique suggestions at confidence >= {HIGH_CONFIDENCE}:\n"
        + format_cases(rows)
    )


def test_suggestions_are_deterministic() -> None:
    """Same input → identical ordered output; the UI and stores rely on it."""
    golden = load_golden("mitre_mapping.yaml")
    mapper = MitreMapper()
    for case in golden["positive"]:
        first = mapper.suggest_techniques(case["text"])
        second = mapper.suggest_techniques(case["text"])
        assert first == second, f"non-deterministic suggestions for {case['id']}"
