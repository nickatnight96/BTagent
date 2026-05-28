"""HuntPackageNode — advisory text -> actionable hunt package (UC-2.2, #105).

The compound generator that turns a TI advisory into a ready-to-act
package. Composes existing nodes:

    advisory text
      -> IOCExtractorNode      (extract + defang + dedup indicators)
      -> RetroHuntNode          (were these already sighted? 90-day check)
      -> QuerySynthNode         (pre-built hunt queries per derived TTP)
      -> Sigma drafts           (one per derived technique)

Mock-first (BTAGENT_MOCK_CONNECTORS gate, matching RetroHunt). The
PDF/CSV -> text decode step is the dep-needing follow-up; this node
takes text. The case-notebook attachment (UC-5.2 lineage) is a backend
concern once the notebook surface lands.
"""

from __future__ import annotations

import os
from typing import ClassVar

from btagent_shared.types.detection import SigmaDraft
from btagent_shared.types.hunt import Backend, HuntInput, HuntScope
from btagent_shared.types.hunt_package import HuntPackage
from btagent_shared.types.investigation import IOC
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.data.ioc_extractor import IOCExtractorInput, IOCExtractorNode
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.reasoning.hypothesis_gen import (
    HypothesisGenInput,
    HypothesisGenNode,
)
from btagent_engine.reasoning.query_synth import QuerySynthInput, QuerySynthNode
from btagent_engine.reasoning.retro_hunt import RetroHuntInput, RetroHuntNode


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


_DEFAULT_BACKENDS = [Backend.SPLUNK, Backend.SENTINEL, Backend.SIGMA]


def _sigma_for(ttp_id: str, ttp_name: str) -> SigmaDraft:
    yaml = (
        f"title: Hunt — {ttp_name or ttp_id}\n"
        f"status: experimental\n"
        f"tags:\n  - attack.{ttp_id.lower().replace('.', '_')}\n"
        f"logsource:\n  category: TODO\n"
        f"detection:\n  selection:\n    TODO: REPLACE_ME\n  condition: selection\n"
        f"level: medium"
    )
    return SigmaDraft(
        technique_id=ttp_id,
        title=f"Hunt — {ttp_name or ttp_id}",
        sigma_yaml=yaml,
        rationale=f"Derived from advisory indicators mapping to {ttp_id}.",
    )


class HuntPackageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="Advisory text (decoded from PDF/CSV).")
    source_label: str = Field(default="advisory", description="Advisory title / filename.")
    initiated_by: str = Field(default="usr_unknown")
    window_days: int = Field(default=90, ge=1, le=730)
    backends: list[Backend] = Field(default_factory=list)


class HuntPackageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: HuntPackage


class HuntPackageNode(Node[HuntPackageInput, HuntPackageOutput]):
    """Advisory text -> extracted IOCs + sightings + queries + Sigma drafts."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.hunt_package",
        name="Hunt Package Generator",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Turn a TI advisory into a hunt package: extracted indicators, "
            "90-day sighting check, pre-built per-backend queries, and Sigma "
            "rule drafts."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = HuntPackageInput
    output_schema: ClassVar[type[BaseModel]] = HuntPackageOutput

    async def run(
        self,
        input: HuntPackageInput,
        ctx: NodeContext,
    ) -> HuntPackageOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "Live hunt-package generation (real 90-day sighting queries) "
                "lands with connector live-wiring. Set BTAGENT_MOCK_CONNECTORS=true."
            )

        backends = input.backends or _DEFAULT_BACKENDS

        # 1. Extract indicators.
        extract = await IOCExtractorNode().run(IOCExtractorInput(text=input.text), ctx)
        iocs = [
            IOC(
                id=f"ioc_pkg_{i}",
                investigation_id="inv_advisory",
                type=e.type,
                value=e.value,
                confidence=0.7,
                source=input.source_label,
                tlp="amber",
            )
            for i, e in enumerate(extract.iocs)
        ]

        # 2. Derive techniques (reuse HypothesisGen for IOC->TTP mapping).
        hunt_input = HuntInput(
            iocs=iocs,
            initiated_by=input.initiated_by,
            scope=HuntScope(backends=backends),
        )
        hyp_out = await HypothesisGenNode().run(HypothesisGenInput(hunt_input=hunt_input), ctx)
        techniques = {h.ttp_id: h.ttp_name for h in hyp_out.hypotheses}

        # 3. Retro-hunt: were these indicators already sighted?
        retro = await RetroHuntNode().run(
            RetroHuntInput(hunt_input=hunt_input, window_days=input.window_days),
            ctx,
        )

        # 4. Pre-built queries per derived technique.
        queries: dict[str, dict[Backend, object]] = {}
        for ttp_id in techniques:
            qs = await QuerySynthNode().run(QuerySynthInput(ttp_id=ttp_id, backends=backends), ctx)
            queries[ttp_id] = qs.queries

        # 5. Sigma drafts, one per derived technique.
        sigma_drafts = [_sigma_for(t, n) for t, n in techniques.items()]

        package = HuntPackage(
            source_label=input.source_label,
            extracted_ioc_count=len(extract.iocs),
            deduped_count=extract.deduped_count,
            derived_techniques=sorted(techniques),
            retro_report=retro.report,
            queries=queries,
            sigma_drafts=sigma_drafts,
            mock_mode=True,
        )
        return HuntPackageOutput(package=package)


NodeRegistry.register(HuntPackageNode)


__all__ = [
    "HuntPackageInput",
    "HuntPackageNode",
    "HuntPackageOutput",
]
