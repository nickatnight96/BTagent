"""CoverageGapNode — ATT&CK coverage matrix + gap analysis + Sigma drafts (UC-4.2).

The headline detection-engineering output (#107, also [#98 Bet 1]): given
the set of techniques that have a deployed detection (or that fired in the
window) and the org's in-scope technique universe, compute:

  * a CoverageMap (tactic -> covered techniques),
  * the uncovered techniques (gaps), and
  * draft Sigma rules for the top-N gaps so the detection engineer has a
    starting point rather than a blank page.

Pure data — no LLM, no network. The Sigma drafts are deliberately
skeletal stubs keyed by technique; turning them into tuned rules is a
QueryTranslate / LLM follow-up. The value here is *surfacing the gap with
a head-start*, which is exactly the acceptance criterion.
"""

from __future__ import annotations

from typing import ClassVar

from btagent_shared.types.detection import CoverageGapReport, SigmaDraft
from btagent_shared.types.mitre import CoverageMap, DetectionGap, TechniqueCoverage
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


class TechniqueRef(BaseModel):
    """One technique in the in-scope universe."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    name: str = ""
    tactic: str = Field(default="unknown", description="ATT&CK tactic shortname.")


# A small default universe so the node is usable standalone; callers
# should pass their real in-scope set (the org's ATT&CK Navigator layer).
_DEFAULT_UNIVERSE: list[TechniqueRef] = [
    TechniqueRef(technique_id="T1059.001", name="PowerShell", tactic="execution"),
    TechniqueRef(technique_id="T1059.003", name="Windows Command Shell", tactic="execution"),
    TechniqueRef(technique_id="T1078.004", name="Cloud Accounts", tactic="defense-evasion"),
    TechniqueRef(technique_id="T1110", name="Brute Force", tactic="credential-access"),
    TechniqueRef(
        technique_id="T1566.001", name="Spearphishing Attachment", tactic="initial-access"
    ),
    TechniqueRef(technique_id="T1486", name="Data Encrypted for Impact", tactic="impact"),
    TechniqueRef(technique_id="T1071.001", name="Web Protocols", tactic="command-and-control"),
    TechniqueRef(technique_id="T1053.005", name="Scheduled Task", tactic="persistence"),
    TechniqueRef(technique_id="T1003", name="OS Credential Dumping", tactic="credential-access"),
    TechniqueRef(technique_id="T1021", name="Remote Services", tactic="lateral-movement"),
]

_MAX_SIGMA_DRAFTS = 10


def _sigma_stub(ref: TechniqueRef) -> SigmaDraft:
    yaml = (
        f"title: TODO detection for {ref.name or ref.technique_id}\n"
        f"status: experimental\n"
        f"tags:\n  - attack.{ref.technique_id.lower().replace('.', '_')}\n"
        f"logsource:\n  category: TODO  # map {ref.technique_id} to a telemetry source\n"
        f"detection:\n  selection:\n    TODO: REPLACE_ME\n  condition: selection\n"
        f"level: medium"
    )
    return SigmaDraft(
        technique_id=ref.technique_id,
        title=f"TODO detection for {ref.name or ref.technique_id}",
        sigma_yaml=yaml,
        rationale=(
            f"{ref.technique_id} ({ref.name}) in tactic {ref.tactic!r} has no "
            "detection in the window — drafted a stub to close the gap."
        ),
    )


class CoverageGapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    covered_technique_ids: list[str] = Field(
        default_factory=list,
        description="Techniques with a deployed detection or that fired in the window.",
    )
    universe: list[TechniqueRef] = Field(
        default_factory=list,
        description="In-scope technique universe. Empty == built-in default set.",
    )
    window_days: int = Field(default=30, ge=1, le=365)
    draft_sigma: bool = Field(
        default=True, description="Emit Sigma stubs for the top uncovered techniques."
    )


class CoverageGapOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report: CoverageGapReport


class CoverageGapNode(Node[CoverageGapInput, CoverageGapOutput]):
    """Compute the ATT&CK coverage matrix + gaps + Sigma drafts."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.coverage_gap",
        name="Coverage Gap Analyzer",
        version="0.1.0",
        category=NodeCategory.DATA,
        description=(
            "Compute an ATT&CK coverage matrix from deployed/fired detections "
            "vs the in-scope technique universe, surface gaps, and draft Sigma "
            "rules for the top uncovered techniques."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = CoverageGapInput
    output_schema: ClassVar[type[BaseModel]] = CoverageGapOutput

    async def run(
        self,
        input: CoverageGapInput,
        ctx: NodeContext,
    ) -> CoverageGapOutput:
        universe = input.universe or _DEFAULT_UNIVERSE
        covered = set(input.covered_technique_ids)

        # Build CoverageMap grouped by tactic + collect gaps per tactic.
        tactics: dict[str, list[TechniqueCoverage]] = {}
        gaps_by_tactic: dict[str, list[str]] = {}
        uncovered_flat: list[str] = []

        for ref in universe:
            is_covered = ref.technique_id in covered
            tactics.setdefault(ref.tactic, []).append(
                TechniqueCoverage(
                    technique_id=ref.technique_id,
                    technique_name=ref.name,
                    count=1 if is_covered else 0,
                )
            )
            if not is_covered:
                gaps_by_tactic.setdefault(ref.tactic, []).append(ref.technique_id)
                uncovered_flat.append(ref.technique_id)

        coverage_map = CoverageMap(
            tactics=tactics,
            total_techniques=len(universe),
            covered_techniques=sum(1 for r in universe if r.technique_id in covered),
        )

        gaps = [
            DetectionGap(tactic=tactic, techniques_without_detection=tids)
            for tactic, tids in sorted(gaps_by_tactic.items())
        ]

        sigma_drafts: list[SigmaDraft] = []
        if input.draft_sigma:
            uncovered_refs = [r for r in universe if r.technique_id not in covered]
            sigma_drafts = [_sigma_stub(r) for r in uncovered_refs[:_MAX_SIGMA_DRAFTS]]

        report = CoverageGapReport(
            coverage_map=coverage_map,
            gaps=gaps,
            uncovered_technique_ids=uncovered_flat,
            sigma_drafts=sigma_drafts,
            window_days=input.window_days,
        )
        return CoverageGapOutput(report=report)


NodeRegistry.register(CoverageGapNode)


__all__ = [
    "CoverageGapInput",
    "CoverageGapNode",
    "CoverageGapOutput",
    "TechniqueRef",
]
