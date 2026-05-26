"""PivotSuggestNode — suggest next investigative pivots from a timeline (UC-1.2).

After the correlation workbench assembles a normalized timeline, the
analyst wants "what should I look at next?". This node extracts the
distinct entities that co-occur with the queried entity, ranks them by
frequency, and proposes 3–5 pivots with rationale.

Mock-first (matches QuerySynthNode / NLQueryNode): the deterministic
rule-based strategy below is the mock path; LLM-backed pivot reasoning
(which can weigh TTP context + temporal proximity) raises
``NotImplementedError`` until the router lands.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.correlation import NormalizedEvent, PivotSuggestion
from btagent_shared.types.enums import IOCType

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").lower() == "true"


_MAX_PIVOTS = 5
_MIN_PIVOTS = 3

# Which canonical NormalizedEvent field maps to which IOCType + which
# connectors are worth pivoting into for that entity kind.
_FIELD_TO_PIVOT: list[tuple[str, IOCType, list[str]]] = [
    ("dest_ip", IOCType.IP, ["firewall", "splunk", "elastic"]),
    ("source_ip", IOCType.IP, ["firewall", "splunk", "elastic"]),
    ("user", IOCType.OTHER, ["sentinel", "splunk"]),
    ("host", IOCType.OTHER, ["crowdstrike", "splunk"]),
    ("domain", IOCType.DOMAIN, ["elastic", "splunk"]),
    ("file_hash", IOCType.HASH_SHA256, ["crowdstrike", "virustotal"]),
]


class PivotSuggestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_value: str = Field(..., description="The entity the timeline was built around.")
    events: list[NormalizedEvent] = Field(default_factory=list)


class PivotSuggestOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pivots: list[PivotSuggestion] = Field(default_factory=list)
    mock_mode: bool


class PivotSuggestNode(Node[PivotSuggestInput, PivotSuggestOutput]):
    """Suggest 3–5 next pivots from a correlated timeline."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.pivot_suggest",
        name="Pivot Suggester",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Suggest next investigative pivots from a correlation timeline by "
            "ranking co-occurring entities and templating rationale."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = PivotSuggestInput
    output_schema: ClassVar[type[BaseModel]] = PivotSuggestOutput

    async def run(
        self,
        input: PivotSuggestInput,
        ctx: NodeContext,
    ) -> PivotSuggestOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "LLM-backed pivot reasoning lands with the router. Set "
                "BTAGENT_MOCK_LLM=true for the deterministic rule-based path."
            )

        queried = input.entity_value.lower()

        # Count occurrences of every candidate pivot entity (value -> (count,
        # field, ioc_type, connectors)). Never suggest the queried entity.
        counts: Counter[tuple[str, str, IOCType]] = Counter()
        connectors_for: dict[tuple[str, str, IOCType], list[str]] = {}
        for ev in input.events:
            for field, ioc_type, connectors in _FIELD_TO_PIVOT:
                val = getattr(ev, field, None)
                if not val or val.lower() == queried:
                    continue
                key = (val, field, ioc_type)
                counts[key] += 1
                connectors_for.setdefault(key, connectors)

        # Rank by frequency, then stable by value for determinism.
        ranked = sorted(
            counts.items(), key=lambda kv: (-kv[1], kv[0][0])
        )

        pivots: list[PivotSuggestion] = []
        for (value, field, ioc_type), count in ranked[:_MAX_PIVOTS]:
            human_field = field.replace("_", " ")
            pivots.append(
                PivotSuggestion(
                    entity_type=ioc_type,
                    entity_value=value,
                    rationale=(
                        f"{count} event(s) reference {human_field} {value!r} "
                        f"alongside {input.entity_value!r} — pivot to see its "
                        "full activity."
                    ),
                    suggested_connectors=connectors_for[(value, field, ioc_type)],
                )
            )

        # If the timeline was too sparse to yield _MIN_PIVOTS, top up with
        # generic temporal/scope pivots so the analyst always has a next step.
        if len(pivots) < _MIN_PIVOTS:
            generic = [
                PivotSuggestion(
                    entity_type=IOCType.OTHER,
                    entity_value=input.entity_value,
                    rationale="Widen the time window to ±24h around the observed activity.",
                    suggested_connectors=["splunk", "elastic"],
                ),
                PivotSuggestion(
                    entity_type=IOCType.OTHER,
                    entity_value=input.entity_value,
                    rationale="Check identity/auth logs for sessions involving this entity.",
                    suggested_connectors=["sentinel"],
                ),
                PivotSuggestion(
                    entity_type=IOCType.OTHER,
                    entity_value=input.entity_value,
                    rationale="Run an endpoint process-tree review on any involved hosts.",
                    suggested_connectors=["crowdstrike"],
                ),
            ]
            for g in generic:
                if len(pivots) >= _MIN_PIVOTS:
                    break
                pivots.append(g)

        return PivotSuggestOutput(pivots=pivots, mock_mode=True)


NodeRegistry.register(PivotSuggestNode)


__all__ = [
    "PivotSuggestInput",
    "PivotSuggestNode",
    "PivotSuggestOutput",
]
