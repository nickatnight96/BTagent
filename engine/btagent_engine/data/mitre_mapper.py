"""MitreMapperNode -- keyword-based MITRE ATT&CK technique suggester.

A re-implementation in the engine of the keyword mapper that ships in
``btagent_agents/mitre/mapper.py``. The agents-side implementation
loads its keyword table from ``mitre_keywords.yaml`` and uses
``substring in lower(text)`` matching, which the audit flagged as
having high false-positive rates -- ``"lateral"`` matched ``"collateral"``
and similar near-misses.

This engine port:

* ships an embedded minimal mapping (~10 high-confidence techniques as
  a hardcoded Python dict). Loading from a config file is on the Phase 2
  backlog -- see TODO below.
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
from typing import Final

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


# TODO(sprint-future): externalise this table to a YAML config file shipped
# with the engine package so security teams can extend it without a code
# change. For Sprint 4A we hardcode a small high-confidence set; the full
# 80+-technique mapping currently lives in agents/btagent_agents/mitre/data
# but the engine must not import from agents.
_EMBEDDED_TECHNIQUES: Final[tuple[_TechniqueSpec, ...]] = (
    _TechniqueSpec(
        technique_id="T1059.001",
        name="PowerShell",
        keywords=[("powershell", 0.95), ("pwsh", 0.85), ("powershell.exe", 0.95)],
    ),
    _TechniqueSpec(
        technique_id="T1059.003",
        name="Windows Command Shell",
        keywords=[("cmd.exe", 0.9), ("command shell", 0.7)],
    ),
    _TechniqueSpec(
        technique_id="T1021",
        name="Remote Services",
        keywords=[("lateral movement", 0.85), ("remote service", 0.7)],
    ),
    _TechniqueSpec(
        technique_id="T1021.001",
        name="Remote Desktop Protocol",
        keywords=[("rdp", 0.9), ("remote desktop", 0.85)],
    ),
    _TechniqueSpec(
        technique_id="T1110",
        name="Brute Force",
        keywords=[("brute force", 0.9), ("password spray", 0.85), ("credential stuffing", 0.85)],
    ),
    _TechniqueSpec(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        keywords=[("ransomware", 0.95), ("file encryption", 0.7)],
    ),
    _TechniqueSpec(
        technique_id="T1071.001",
        name="Web Protocols",
        keywords=[("c2 over http", 0.9), ("http beacon", 0.85), ("https beacon", 0.85)],
    ),
    _TechniqueSpec(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        keywords=[("spearphishing attachment", 0.95), ("phishing attachment", 0.85)],
    ),
    _TechniqueSpec(
        technique_id="T1003",
        name="OS Credential Dumping",
        keywords=[("mimikatz", 0.95), ("credential dump", 0.85), ("lsass dump", 0.9)],
    ),
    _TechniqueSpec(
        technique_id="T1053.005",
        name="Scheduled Task",
        keywords=[("scheduled task", 0.85), ("schtasks", 0.9)],
    ),
)


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
