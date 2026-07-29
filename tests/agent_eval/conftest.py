"""Shared helpers for the agent evaluation suite (#382).

Design notes
------------
This suite evaluates the *deterministic* agent components (keyword MITRE
mapper, triage classifier, severity scorer) against golden datasets with
aggregate-metric thresholds — eval semantics, not unit-test semantics:

* A unit test pins one input to one output and fails on any deviation.
* An eval runs a golden set through a component, computes accuracy-style
  metrics, and fails only when the aggregate drops below a threshold. Adding
  a keyword that shifts one borderline case doesn't break the build; gutting
  the keyword table does.

Everything here runs with BTAGENT_MOCK_LLM semantics — no network, no LLM
calls — so the CI job is deterministic and fast. When live-LLM evaluation
lands (DeepEval + golden investigation transcripts), it belongs beside this,
behind an explicit opt-in env var, not instead of this.

Failure output: each metric assert carries the full per-case breakdown, so
a threshold failure in CI reads as "which cases regressed", not just a
number.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def load_golden(name: str) -> dict[str, Any]:
    """Load a golden dataset YAML by file name."""
    path = GOLDEN_DIR / name
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict), f"golden file {name} must parse to a mapping"
    return data


def format_cases(rows: list[tuple[str, bool, str]]) -> str:
    """Render per-case results for assertion messages: ✓/✗ id — detail."""
    return "\n".join(f"  {'✓' if ok else '✗'} {cid} — {detail}" for cid, ok, detail in rows)
