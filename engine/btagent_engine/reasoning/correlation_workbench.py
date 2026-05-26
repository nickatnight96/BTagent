"""CorrelationWorkbenchNode — entity -> cross-platform correlated timeline (UC-1.2).

The integrating step. Given an entity (IP / host / user / hash), it:

  1. Selects which connectors to query (manifest introspection where a
     manifest exists; static fallback otherwise).
  2. Fans out to those connectors (mock: pulls the entity-keyed fixture;
     live: real connector queries — raises until wired).
  3. Normalizes each connector's raw events via OCSFMapperNode into the
     canonical NormalizedEvent shape (the "no manual rekeying" payoff).
  4. Merges + sorts the events by UTC timestamp.
  5. Auto-tags each event with ATT&CK techniques (MitreMapperNode),
     gated by a confidence threshold.
  6. Suggests next pivots (PivotSuggestNode).
  7. Records a full audit trail (one entry per connector queried) and
     writes it to ctx.metadata for the lineage requirement.

Compound node (not a workflow) because the fan-out set is dynamic per
entity type — see the UC-1.2 plan. Mock-first: BTAGENT_MOCK_CONNECTORS
gates the data source.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.security.correlation_fixtures import get_fixture
from btagent_shared.security.ocsf_map import OCSF_MAPS
from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.types.correlation import (
    AuditEntry,
    CorrelationTimeline,
    MitreTag,
    NormalizedEvent,
)
from btagent_shared.types.enums import IOCType

from btagent_engine.data.mitre_mapper import MitreMapperInput, MitreMapperNode
from btagent_engine.data.ocsf_mapper import OCSFMapperInput, OCSFMapperNode
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.reasoning.pivot_suggest import (
    PivotSuggestInput,
    PivotSuggestNode,
)

AUDIT_METADATA_KEY = "uc12.audit_trail"


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# Which OCSF classes matter for each entity type (drives manifest-based
# connector selection in the live path).
_ENTITY_OCSF_INTEREST: dict[IOCType, list[OCSFEventClass]] = {
    IOCType.IP: [
        OCSFEventClass.NETWORK_ACTIVITY,
        OCSFEventClass.DNS_ACTIVITY,
        OCSFEventClass.AUTHENTICATION,
    ],
    IOCType.DOMAIN: [OCSFEventClass.DNS_ACTIVITY, OCSFEventClass.NETWORK_ACTIVITY],
    IOCType.HASH_SHA256: [
        OCSFEventClass.PROCESS_ACTIVITY,
        OCSFEventClass.FILE_ACTIVITY,
    ],
    IOCType.HASH_MD5: [OCSFEventClass.PROCESS_ACTIVITY, OCSFEventClass.FILE_ACTIVITY],
    IOCType.OTHER: [OCSFEventClass.AUTHENTICATION, OCSFEventClass.NETWORK_ACTIVITY],
}

# Static fallback while most connectors lack manifests (#100 Phase 4
# closes this). Maps entity type -> connectors worth querying.
_ENTITY_CONNECTOR_FALLBACK: dict[IOCType, list[str]] = {
    IOCType.IP: ["splunk", "elastic", "firewall", "crowdstrike", "sentinel"],
    IOCType.DOMAIN: ["splunk", "elastic"],
    IOCType.HASH_SHA256: ["crowdstrike", "splunk"],
    IOCType.HASH_MD5: ["crowdstrike", "splunk"],
    IOCType.OTHER: ["sentinel", "splunk", "crowdstrike"],
}


class CorrelationWorkbenchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: IOCType
    entity_value: str
    mitre_confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    max_events_per_source: int = Field(default=100, ge=1, le=10000)


class CorrelationWorkbenchOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeline: CorrelationTimeline


class CorrelationWorkbenchNode(
    Node[CorrelationWorkbenchInput, CorrelationWorkbenchOutput]
):
    """Correlate an entity across multiple security tools into one timeline."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.correlation_workbench",
        name="Correlation Workbench",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Fan out a single entity (IP/host/user/hash) across SIEM/EDR/"
            "firewall/identity, normalize into one OCSF-aligned timeline, "
            "auto-tag MITRE techniques, and suggest next pivots."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = CorrelationWorkbenchInput
    output_schema: ClassVar[type[BaseModel]] = CorrelationWorkbenchOutput

    async def run(
        self,
        input: CorrelationWorkbenchInput,
        ctx: NodeContext,
    ) -> CorrelationWorkbenchOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "Live cross-platform correlation (real connector queries) lands "
                "with the connector live-wiring follow-up. Set "
                "BTAGENT_MOCK_CONNECTORS=true for the deterministic fixture path."
            )

        fixture = get_fixture(input.entity_value)
        connectors = self._select_connectors(input.entity_type, fixture)

        mapper = OCSFMapperNode()
        all_events: list[NormalizedEvent] = []
        audit: list[AuditEntry] = []
        sources_queried: list[str] = []

        for connector in connectors:
            raw_events = fixture.get(connector, [])[: input.max_events_per_source]
            # Only connectors we have a normalization map for can contribute.
            if connector not in OCSF_MAPS:
                continue
            sources_queried.append(connector)
            try:
                mapped = await mapper.run(
                    OCSFMapperInput(
                        connector=connector,
                        raw_events=raw_events,
                        capability_id=f"{connector}.search",
                    ),
                    ctx,
                )
                all_events.extend(mapped.events)
                audit.append(
                    AuditEntry(
                        connector=connector,
                        capability_id=f"{connector}.search",
                        query=f"entity={input.entity_value}",
                        queried_at=datetime.now(timezone.utc),
                        event_count=len(mapped.events),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - record + continue
                audit.append(
                    AuditEntry(
                        connector=connector,
                        query=f"entity={input.entity_value}",
                        queried_at=datetime.now(timezone.utc),
                        event_count=0,
                        error=str(exc),
                    )
                )

        # Sort by normalized UTC timestamp ascending.
        all_events.sort(key=lambda e: e.timestamp)

        # MITRE auto-tagging, threshold-gated.
        await self._tag_mitre(all_events, input.mitre_confidence_threshold, ctx)

        # Pivot suggestions.
        pivot_out = await PivotSuggestNode().run(
            PivotSuggestInput(entity_value=input.entity_value, events=all_events),
            ctx,
        )

        # Lineage / audit metadata.
        ctx.metadata[AUDIT_METADATA_KEY] = [a.model_dump() for a in audit]

        timeline = CorrelationTimeline(
            entity_type=input.entity_type,
            entity_value=input.entity_value,
            events=all_events,
            sources_queried=sources_queried,
            pivots=pivot_out.pivots,
            audit_trail=audit,
            mock_mode=True,
        )
        return CorrelationWorkbenchOutput(timeline=timeline)

    # --- helpers ---------------------------------------------------------- #

    @staticmethod
    def _select_connectors(
        entity_type: IOCType, fixture: dict[str, list]
    ) -> list[str]:
        """Connectors to fan out to.

        In mock mode the fixture's own connector set is authoritative
        (those are the connectors that actually have data for this
        entity). Intersect with the fallback ordering so the result is
        deterministic + ordered. If the fixture is empty, fall back to
        the static map (will yield an empty timeline but a real audit
        trail, which is the correct "we looked, found nothing" outcome).
        """
        fallback = _ENTITY_CONNECTOR_FALLBACK.get(
            entity_type, _ENTITY_CONNECTOR_FALLBACK[IOCType.OTHER]
        )
        if fixture:
            # Preserve fallback ordering, include any fixture connector
            # not already in the fallback list.
            ordered = [c for c in fallback if c in fixture]
            extras = [c for c in fixture if c not in ordered]
            return ordered + extras
        return fallback

    @staticmethod
    async def _tag_mitre(
        events: list[NormalizedEvent], threshold: float, ctx: NodeContext
    ) -> None:
        """Run each event's text through MitreMapperNode; attach tags above
        the confidence threshold. Mutates events in place.
        """
        mapper = MitreMapperNode()
        for ev in events:
            blob_parts = [ev.action or "", ev.summary]
            # pull a couple of high-signal raw fields if present
            for k in ("CommandLine", "FileName", "app", "event_simpleName"):
                v = ev.raw_event.get(k)
                if isinstance(v, str):
                    blob_parts.append(v)
            blob = " ".join(p for p in blob_parts if p)
            if not blob.strip():
                continue
            result = await mapper.run(
                MitreMapperInput(text=blob, min_confidence=threshold), ctx
            )
            ev.mitre_techniques = [
                MitreTag(
                    technique_id=t.technique_id,
                    name=t.name,
                    confidence=t.confidence,
                )
                for t in result.techniques
            ]


NodeRegistry.register(CorrelationWorkbenchNode)


__all__ = [
    "AUDIT_METADATA_KEY",
    "CorrelationWorkbenchInput",
    "CorrelationWorkbenchNode",
    "CorrelationWorkbenchOutput",
]
