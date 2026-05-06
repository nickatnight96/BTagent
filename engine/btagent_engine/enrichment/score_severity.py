"""Severity scoring Node -- keyword + IOC-count + MITRE heuristic.

Ports ``_score_severity_heuristic`` from
``agents/btagent_agents/orchestrator/nodes.py``. Re-implemented as a
standalone Node with a richer return shape (numeric score + rationale)
that the legacy helper threw away.

What the legacy version did:
* Scanned text for hard-coded keyword sets ("ransomware" -> CRITICAL,
  "lateral movement" -> HIGH, "phishing" -> MEDIUM, etc.) and returned
  a single Severity enum value.
* Bumped to MEDIUM if ``len(iocs) >= 3``.
* No score, no rationale, no MITRE awareness, no way for downstream
  to inspect *why* a score landed where it did.

What this Node adds:
* A numeric **0.0-1.0 score** so analysts can sort by severity within
  a bucket and downstream nodes (e.g. an LLM summariser) can quote the
  exact figure.
* A **rationale list** -- one entry per contributing factor, formatted
  like ``"+0.30: keyword 'ransomware' matched"``. Audit trail and UI
  tooltip fodder.
* **MITRE technique boosts**. T1486 (Data Encrypted for Impact) and
  similarly impactful techniques force CRITICAL even on text that
  reads benign -- the legacy heuristic missed this entire signal.
* **IOC-count multiplier** that scales smoothly instead of the legacy
  binary >=3 cliff.

Sprint 4B; bumps a TODO from Sprint 3D's enrichment workflow template.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------
# Tuples are (keyword, score-contribution). Higher = more severe.
# Ordered by descending weight inside each bucket so the rationale
# reads "biggest factor first" when sorted.

_CRITICAL_KEYWORDS: tuple[tuple[str, float], ...] = (
    ("ransomware", 0.80),
    ("wiper", 0.80),
    ("data exfiltration confirmed", 0.80),
    ("active breach", 0.80),
    ("encrypted shell", 0.80),
    ("nation state", 0.55),
    ("zero-day", 0.55),
    ("0-day", 0.55),
    ("domain admin compromise", 0.75),
    ("dc compromise", 0.75),
    ("apt", 0.40),
)

_HIGH_KEYWORDS: tuple[tuple[str, float], ...] = (
    ("data exfiltration", 0.30),
    ("lateral movement", 0.25),
    ("privilege escalation", 0.25),
    ("c2 beacon", 0.25),
    ("command and control", 0.25),
    ("credential dump", 0.25),
    ("mimikatz", 0.25),
    ("cobalt strike", 0.25),
    ("bloodhound", 0.20),
)

_MEDIUM_KEYWORDS: tuple[tuple[str, float], ...] = (
    ("phishing", 0.15),
    ("reconnaissance", 0.15),
    ("brute force", 0.15),
    ("malware", 0.15),
    ("trojan", 0.15),
    ("suspicious", 0.10),
    ("anomalous", 0.10),
    ("failed login", 0.10),
)

_LOW_KEYWORDS: tuple[tuple[str, float], ...] = (
    ("informational", -0.10),
    ("policy violation", -0.05),
    ("false positive", -0.20),
    ("benign", -0.15),
    ("test", -0.10),
)

# MITRE techniques that on their own justify a CRITICAL score regardless
# of keyword soup. Curated from the ATT&CK matrix's high-impact set.
_FORCE_CRITICAL_TECHNIQUES: frozenset[str] = frozenset(
    {
        "T1486",  # Data Encrypted for Impact
        "T1485",  # Data Destruction
        "T1490",  # Inhibit System Recovery
        "T1561",  # Disk Wipe
        "T1499",  # Endpoint DoS (high-impact form)
        "T1561.001",  # Disk Content Wipe
        "T1561.002",  # Disk Structure Wipe
    }
)

# Per-IOC additive contribution, capped to keep huge dumps from
# dominating the score on their own.
_PER_IOC_WEIGHT: float = 0.04
_MAX_IOC_CONTRIBUTION: float = 0.20


def _bucket(score: float) -> str:
    """Map a 0..1 score to one of the four severity strings."""
    if score >= 0.75:
        return "critical"
    if score >= 0.50:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ScoreSeverityInput(BaseModel):
    text: str = Field(..., description="Free-form text to score (alert body, IR notes, etc.)")
    iocs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="IOCs already extracted from this incident -- shape "
        "matches ``ExtractIOCsNode`` output (``type`` + ``value`` keys).",
    )
    confirmed_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. 'T1486') confirmed "
        "for this incident. Some techniques force CRITICAL.",
    )


class ScoreSeverityOutput(BaseModel):
    severity: str = Field(
        ...,
        description="Bucketed severity: 'low' / 'medium' / 'high' / 'critical'.",
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Continuous score, 0..1.",
    )
    rationale: list[str] = Field(
        ...,
        description="Per-contribution audit trail, e.g. \"+0.30: keyword "
        "'ransomware' matched\" or \"FORCE_CRITICAL: technique T1486\".",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class ScoreSeverityNode(Node[ScoreSeverityInput, ScoreSeverityOutput]):
    """Heuristic severity scorer (keyword + IOC count + MITRE boosts)."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="enrichment.score_severity",
        name="Enrichment: Score Severity",
        version="0.1.0",
        # TODO(post-sprint4B): see ExtractIOCsNode for the ENRICHMENT
        # category candidate; DATA stands in until the enum is extended.
        category=NodeCategory.DATA,
        description="Score incident severity 0..1 from text keywords, IOC "
        "count, and confirmed MITRE techniques. Returns severity bucket, "
        "raw score, and per-factor rationale.",
    )
    input_schema: ClassVar[type[BaseModel]] = ScoreSeverityInput
    output_schema: ClassVar[type[BaseModel]] = ScoreSeverityOutput

    async def run(
        self,
        input: ScoreSeverityInput,
        ctx: NodeContext,
    ) -> ScoreSeverityOutput:
        rationale: list[str] = []

        # MITRE force-critical short-circuit. Still build the rationale so
        # the analyst can see *which* technique tripped the override.
        forced_critical = False
        for tid in input.confirmed_techniques:
            if tid in _FORCE_CRITICAL_TECHNIQUES:
                forced_critical = True
                rationale.append(
                    f"FORCE_CRITICAL: confirmed MITRE technique {tid} "
                    f"is in the high-impact set"
                )

        lower = input.text.lower()
        score = 0.0

        for table_name, table in (
            ("critical", _CRITICAL_KEYWORDS),
            ("high", _HIGH_KEYWORDS),
            ("medium", _MEDIUM_KEYWORDS),
            ("low", _LOW_KEYWORDS),
        ):
            for keyword, weight in table:
                if keyword in lower:
                    score += weight
                    sign = "+" if weight >= 0 else ""
                    rationale.append(
                        f"{sign}{weight:.2f}: {table_name} keyword "
                        f"'{keyword}' matched"
                    )

        # IOC count contribution (capped).
        ioc_count = len(input.iocs)
        if ioc_count > 0:
            ioc_contrib = min(ioc_count * _PER_IOC_WEIGHT, _MAX_IOC_CONTRIBUTION)
            score += ioc_contrib
            rationale.append(
                f"+{ioc_contrib:.2f}: {ioc_count} IOC(s) extracted "
                f"({_PER_IOC_WEIGHT:.2f}/IOC, capped at "
                f"{_MAX_IOC_CONTRIBUTION:.2f})"
            )

        # Floor and ceiling.
        score = max(0.0, min(1.0, score))

        if forced_critical:
            severity = "critical"
            score = max(score, 0.95)
        else:
            severity = _bucket(score)

        return ScoreSeverityOutput(
            severity=severity,
            score=round(score, 4),
            rationale=rationale,
        )
