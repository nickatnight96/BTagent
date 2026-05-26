"""PatternClusterNode — cluster telemetry events into candidate detections (UC-4.2).

The "continuous pattern detection" core (minus the scheduler, which is a
trigger-system concern — see #107 follow-up). Takes a list of
MITRE-tagged NormalizedEvents (e.g. from the correlation workbench) and
clusters them into candidate detections: events sharing an ATT&CK
technique + an overlapping affected-entity set become one cluster with a
confidence score and an entity rollup.

Deterministic — no LLM. Clustering is a straightforward group-by on
(technique_id, primary_host); the confidence is the max tag confidence
in the cluster. A future LLM-backed pass can do sequence-aware
technique-chain detection, but the group-by gives a usable signal now.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.correlation import NormalizedEvent
from btagent_shared.types.detection import DetectionCluster

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").lower() == "true"


def _primary_host(ev: NormalizedEvent) -> str:
    """Cluster key host: prefer host, then source_ip, then 'unknown'."""
    return ev.host or ev.source_ip or "unknown"


class PatternClusterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[NormalizedEvent] = Field(default_factory=list)
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class PatternClusterOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clusters: list[DetectionCluster] = Field(default_factory=list)
    mock_mode: bool


class PatternClusterNode(Node[PatternClusterInput, PatternClusterOutput]):
    """Cluster MITRE-tagged events into candidate detections."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.pattern_cluster",
        name="Pattern Cluster Detector",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Cluster MITRE-tagged telemetry events into candidate detections "
            "by (technique, affected host) with confidence + entity rollup."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = PatternClusterInput
    output_schema: ClassVar[type[BaseModel]] = PatternClusterOutput

    async def run(
        self,
        input: PatternClusterInput,
        ctx: NodeContext,
    ) -> PatternClusterOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "Sequence-aware LLM pattern clustering lands with the router. "
                "Set BTAGENT_MOCK_LLM=true for the deterministic group-by path."
            )

        # group events by (technique_id, primary_host)
        groups: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for ev in input.events:
            for tag in ev.mitre_techniques:
                if tag.confidence < input.min_confidence:
                    continue
                groups[(tag.technique_id, _primary_host(ev))].append(ev)

        clusters: list[DetectionCluster] = []
        # deterministic ordering: technique id, then host
        for (technique_id, host), evs in sorted(groups.items()):
            # roll up affected entities + max confidence + technique name
            entities: dict[str, set[str]] = defaultdict(set)
            max_conf = 0.0
            tname = ""
            for ev in evs:
                for kind, val in (
                    ("host", ev.host),
                    ("user", ev.user),
                    ("source_ip", ev.source_ip),
                    ("dest_ip", ev.dest_ip),
                ):
                    if val:
                        entities[kind].add(val)
                for tag in ev.mitre_techniques:
                    if tag.technique_id == technique_id:
                        max_conf = max(max_conf, tag.confidence)
                        tname = tname or tag.name
            clusters.append(
                DetectionCluster(
                    id=f"cluster_{technique_id}_{host}".replace(".", "_"),
                    technique_id=technique_id,
                    technique_name=tname,
                    confidence=round(max_conf, 3),
                    affected_entities={k: sorted(v) for k, v in entities.items()},
                    event_ids=[e.event_id for e in evs],
                    summary=(
                        f"{len(evs)} event(s) on {host} consistent with "
                        f"{tname or technique_id} ({technique_id})."
                    ),
                )
            )

        return PatternClusterOutput(clusters=clusters, mock_mode=True)


NodeRegistry.register(PatternClusterNode)


__all__ = [
    "PatternClusterInput",
    "PatternClusterNode",
    "PatternClusterOutput",
]
