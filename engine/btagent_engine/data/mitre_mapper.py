"""MitreMapperNode -- keyword-based MITRE ATT&CK technique suggester.

A re-implementation in the engine of the keyword mapper that ships in
``btagent_agents/mitre/mapper.py``. The agents-side implementation
loads its keyword table from ``mitre_keywords.yaml`` and uses
``substring in lower(text)`` matching, which the audit flagged as
having high false-positive rates -- ``"lateral"`` matched ``"collateral"``
and similar near-misses.

This engine port:

* loads its curated high-confidence mapping from the packaged
  ``mitre_techniques.yaml`` next to this module -- extend coverage by
  editing the YAML, no code change (validated loud at import).
* uses **word-boundary** matching (``re``) so ``lateral`` no longer
  matches ``collateral``, ``script`` no longer matches ``manuscript``,
  etc.
* deduplicates by ``technique_id`` (highest-confidence match wins) and
  returns a deterministic ordering: confidence desc, then id asc.

The ``coverage`` output field is a coarse 0.0-1.0 score: the fraction
of the input text length covered by the *spans* of matched keywords.
It's intended as a "did we actually understand any of this?" signal,
not as a precision metric.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import yaml
from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


class _TechniqueSpec(BaseModel):
    """Internal: one row of the embedded technique table."""

    technique_id: str
    name: str
    keywords: list[tuple[str, float]]
    # Each (keyword, confidence) pair. A technique can be matched by any of
    # its keywords; the highest-confidence keyword that fires wins.


# The keyword table ships as ``mitre_techniques.yaml`` next to this module
# (the Sprint-4A TODO, now done): security teams extend coverage by editing
# the YAML — no code change. The full 80+-technique mapping still lives in
# agents/btagent_agents/mitre/data (the engine must not import from agents);
# this file remains the engine's own curated high-confidence set.
_TECHNIQUES_YAML_PATH: Final = Path(__file__).resolve().parent / "mitre_techniques.yaml"


def _load_techniques(path: Path = _TECHNIQUES_YAML_PATH) -> tuple[_TechniqueSpec, ...]:
    """Load and validate the packaged keyword table.

    Fails LOUD at import time on a missing or malformed file: a silently
    empty mapper would make every downstream consumer (triage hints,
    coverage analysis) look like "no technique matched" — the worst failure
    mode is the quiet one.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise RuntimeError(f"MITRE technique table {path} must be a non-empty list")
    specs: list[_TechniqueSpec] = []
    for entry in raw:
        specs.append(
            _TechniqueSpec(
                technique_id=entry["technique_id"],
                name=entry["name"],
                keywords=[(str(kw), float(conf)) for kw, conf in entry["keywords"]],
            )
        )
    return tuple(specs)


# Kept under the original name — the compiled-regex cache and tests key off it.
_EMBEDDED_TECHNIQUES: Final[tuple[_TechniqueSpec, ...]] = _load_techniques()


# Pre-compile a regex per keyword once at import time. ``\b`` only treats
# alphanumerics + underscore as word characters, which is too narrow for our
# tokens (``cmd.exe``, ``c2 over http``). We hand-roll a "boundary" using
# negative lookarounds for letters / digits on either side of the keyword.
def _compile_keyword(keyword: str) -> re.Pattern[str]:
    escaped = re.escape(keyword)
    return re.compile(
        rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


_COMPILED: Final[
    tuple[tuple[_TechniqueSpec, tuple[tuple[str, float, re.Pattern[str]], ...]], ...]
] = tuple(
    (
        spec,
        tuple((kw, conf, _compile_keyword(kw)) for kw, conf in spec.keywords),
    )
    for spec in _EMBEDDED_TECHNIQUES
)


class MitreMapperInput(BaseModel):
    text: str = Field(
        ...,
        description="Free-form text (alert summary, IOC context, investigation "
        "notes) to scan for MITRE ATT&CK technique keywords.",
    )
    min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Drop matches below this confidence. Default 0.5 keeps the "
        "node from spamming low-signal techniques into the workflow state.",
    )


class MitreMappedTechnique(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK technique id, e.g. 'T1059.001'.")
    name: str = Field(..., description="Human-readable technique name.")
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_keywords: list[str] = Field(
        default_factory=list,
        description="Keywords from the embedded table that fired against the input text.",
    )


class MitreMapperOutput(BaseModel):
    techniques: list[MitreMappedTechnique] = Field(
        default_factory=list,
        description="Matched techniques, deduplicated by id; ordered confidence desc, id asc.",
    )
    coverage: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Fraction of the input text length covered by matched-keyword spans. "
        "Coarse 'did we understand any of this?' signal; not a precision metric.",
    )


def _coverage(text: str, spans: list[tuple[int, int]]) -> float:
    """Fraction of ``text`` length covered by the (start, end) ``spans``.

    Spans are merged so overlapping matches are not double-counted.
    """
    if not text or not spans:
        return 0.0
    spans = sorted(spans)
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    covered = sum(end - start for start, end in merged)
    return min(1.0, covered / len(text))


@NodeRegistry.register
class MitreMapperNode(Node[MitreMapperInput, MitreMapperOutput]):
    """Map free-form text to MITRE ATT&CK techniques via keyword matching."""

    meta = NodeMeta(
        id="data.map_mitre",
        name="Data: MITRE ATT&CK Mapper",
        version="0.1.0",
        category=NodeCategory.DATA,
        description="Suggest MITRE ATT&CK techniques from alert / IOC / investigation "
        "text using a small embedded keyword table with word-boundary matching. "
        "Deterministic ordering (confidence desc, id asc).",
    )
    input_schema = MitreMapperInput
    output_schema = MitreMapperOutput

    async def run(
        self,
        input: MitreMapperInput,
        ctx: NodeContext,
    ) -> MitreMapperOutput:
        text = input.text
        if not text:
            return MitreMapperOutput(techniques=[], coverage=0.0)

        matched: list[MitreMappedTechnique] = []
        all_spans: list[tuple[int, int]] = []

        for spec, compiled in _COMPILED:
            best_confidence = 0.0
            firing_keywords: list[str] = []
            for keyword, confidence, pattern in compiled:
                hits = list(pattern.finditer(text))
                if not hits:
                    continue
                firing_keywords.append(keyword)
                if confidence > best_confidence:
                    best_confidence = confidence
                for h in hits:
                    all_spans.append(h.span())

            if not firing_keywords:
                continue
            if best_confidence < input.min_confidence:
                continue

            matched.append(
                MitreMappedTechnique(
                    technique_id=spec.technique_id,
                    name=spec.name,
                    confidence=best_confidence,
                    matched_keywords=sorted(set(firing_keywords)),
                )
            )

        # Deterministic ordering: confidence desc, then technique_id asc.
        matched.sort(key=lambda t: (-t.confidence, t.technique_id))

        return MitreMapperOutput(
            techniques=matched,
            coverage=_coverage(text, all_spans),
        )
