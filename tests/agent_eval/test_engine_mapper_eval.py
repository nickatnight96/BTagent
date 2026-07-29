"""Eval: engine MitreMapperNode vs its golden corpus (#382 / #498).

The engine mapper's keyword table is now team-editable YAML (#498). This
eval is the aggregate gate on those edits: recall over realistic alert
texts must hold, and the word-boundary property — the reason this mapper
exists at all — tolerates zero hits on the trap corpus.
"""

from __future__ import annotations

import asyncio

from btagent_engine import NodeContext
from btagent_engine.data import MitreMapperInput, MitreMapperNode
from conftest import format_cases, load_golden  # type: ignore[import-not-found]

MIN_MEAN_RECALL = 0.90


def _suggest(text: str) -> list[str]:
    out = asyncio.run(
        MitreMapperNode().run(
            MitreMapperInput(text=text, min_confidence=0.5),
            NodeContext(run_id="r_eval", org_id="org_eval"),
        )
    )
    return [t.technique_id for t in out.techniques]


def test_engine_mapper_golden_recall() -> None:
    golden = load_golden("engine_mapper.yaml")
    rows: list[tuple[str, bool, str]] = []
    recalls: list[float] = []
    for case in golden["positive"]:
        got = set(_suggest(case["text"]))
        expected = set(case["expected"])
        recall = len(expected & got) / len(expected)
        recalls.append(recall)
        rows.append(
            (
                case["id"],
                recall == 1.0,
                f"recall {recall:.2f}"
                + (f", missing {sorted(expected - got)}" if expected - got else ""),
            )
        )
    mean_recall = sum(recalls) / len(recalls)
    assert mean_recall >= MIN_MEAN_RECALL, (
        f"engine mapper mean recall {mean_recall:.3f} < {MIN_MEAN_RECALL}:\n"
        + format_cases(rows)
    )


def test_engine_mapper_boundary_traps_stay_silent() -> None:
    """Zero tolerance: a trap firing means the word-boundary property broke."""
    golden = load_golden("engine_mapper.yaml")
    rows: list[tuple[str, bool, str]] = []
    clean = True
    for case in golden["boundary_traps"]:
        got = _suggest(case["text"])
        ok = not got
        clean = clean and ok
        rows.append((case["id"], ok, "silent" if ok else f"fired {got}"))
    assert clean, "Word-boundary regression — traps fired:\n" + format_cases(rows)


def test_engine_mapper_deterministic_ordering() -> None:
    golden = load_golden("engine_mapper.yaml")
    for case in golden["positive"]:
        assert _suggest(case["text"]) == _suggest(case["text"]), case["id"]
