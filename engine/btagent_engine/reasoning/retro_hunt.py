"""RetroHuntNode — check new intel against historical telemetry (UC-4.3, #107).

Closes EPIC-4. When a TI report arrives, the retro-hunt answers "were we
already compromised?": it derives the relevant techniques (reusing
HypothesisGenNode), checks each indicator against historical telemetry,
groups any sightings by ATT&CK tactic with first/last-seen, and flags
techniques seen-but-undetected as coverage gaps.

Compound node (like the correlation workbench): composes HypothesisGen +
a historical-sighting lookup. Mock mode pulls historical events from the
shared correlation fixtures keyed by indicator value (so an IOC whose
value appears in the fixtures registers a deterministic sighting); the
live path queries each connector's 90-day store and raises until wired.

The scheduler / TI-ingest trigger that *fires* a retro-hunt on every new
advisory is a Phase-3 trigger-system concern; this node is the work the
trigger invokes.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import UTC, datetime, timezone
from typing import ClassVar

from btagent_shared.security.correlation_fixtures import get_fixture
from btagent_shared.security.ocsf_map import get_map
from btagent_shared.types.hunt import HuntInput
from btagent_shared.types.retrohunt import RetroHuntReport, Sighting
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.data.ocsf_mapper import OCSFMapperInput, OCSFMapperNode
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.reasoning.hypothesis_gen import (
    _IOC_TYPE_DEFAULT_TTP,
    HypothesisGenInput,
    HypothesisGenNode,
)

# Technique -> tactic for the techniques HypothesisGen can emit. Unknown
# techniques fall back to "unknown". Kept inline (small, stable set);
# the full ATT&CK tactic map is a data-load concern for the live path.
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1059.001": "execution",
    "T1059.005": "execution",
    "T1078.001": "defense-evasion",
    "T1078.004": "defense-evasion",
    "T1566.001": "initial-access",
    "T1190": "initial-access",
    "T1133": "initial-access",
    "T1486": "impact",
    "T1027": "defense-evasion",
    "T1071.001": "command-and-control",
    "T1071.004": "command-and-control",
    "T1583.003": "resource-development",
    "T1003": "credential-access",
    "T1083": "discovery",
    "T1110": "credential-access",
    "T1053.005": "persistence",
}


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


class RetroHuntInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hunt_input: HuntInput = Field(
        ..., description="TI report: adversaries / TTPs / IOCs to retro-hunt."
    )
    window_days: int = Field(default=90, ge=1, le=730)
    covered_technique_ids: list[str] = Field(
        default_factory=list,
        description="Techniques with a deployed detection — used to flag coverage gaps.",
    )


class RetroHuntOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report: RetroHuntReport


class RetroHuntNode(Node[RetroHuntInput, RetroHuntOutput]):
    """Retro-hunt new intel against historical telemetry."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.retro_hunt",
        name="Retro-Hunt",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Check new threat intel against historical telemetry, group "
            "sightings by ATT&CK tactic, and flag seen-but-undetected gaps."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = RetroHuntInput
    output_schema: ClassVar[type[BaseModel]] = RetroHuntOutput

    async def run(
        self,
        input: RetroHuntInput,
        ctx: NodeContext,
    ) -> RetroHuntOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "Live retro-hunt (90-day connector queries) lands with the "
                "connector live-wiring. Set BTAGENT_MOCK_CONNECTORS=true for "
                "the fixture-backed mock path."
            )

        hunt_input = input.hunt_input

        # 1. Derive candidate techniques from the TI (reuse HypothesisGen).
        hyp_out = await HypothesisGenNode().run(HypothesisGenInput(hunt_input=hunt_input), ctx)
        technique_names = {h.ttp_id: h.ttp_name for h in hyp_out.hypotheses}

        # 2. Check each IOC against historical telemetry (mock: fixtures).
        mapper = OCSFMapperNode()
        sightings: list[Sighting] = []
        for ioc in hunt_input.iocs:
            fixture = get_fixture(ioc.value)
            if not fixture:
                continue  # no historical sighting for this indicator
            # Normalize the matched events to extract timing + connectors.
            all_norm = []
            connectors: list[str] = []
            for connector, raw_events in fixture.items():
                if get_map(connector) is None:
                    continue
                connectors.append(connector)
                mapped = await mapper.run(
                    OCSFMapperInput(
                        connector=connector,
                        raw_events=raw_events,
                        capability_id=f"{connector}.historical",
                    ),
                    ctx,
                )
                all_norm.extend(mapped.events)
            if not all_norm:
                continue
            timestamps = [e.timestamp for e in all_norm]
            # Attribute the sighting to the technique THIS indicator maps to
            # (by IOC type), not the first hypothesis — otherwise every
            # sighting collapses onto one technique. Prefer the
            # hypothesis-derived name when available.
            default = _IOC_TYPE_DEFAULT_TTP.get(ioc.type)
            if default is not None:
                ttp_id, ttp_name = default
            else:
                ttp_id, ttp_name = next(iter(technique_names.items()), ("T0000", ""))
            ttp_name = technique_names.get(ttp_id, ttp_name)
            tactic = _TECHNIQUE_TACTIC.get(ttp_id, "unknown")
            sightings.append(
                Sighting(
                    ioc_value=ioc.value,
                    technique_id=ttp_id,
                    technique_name=ttp_name,
                    tactic=tactic,
                    event_count=len(all_norm),
                    first_seen=min(timestamps),
                    last_seen=max(timestamps),
                    source_connectors=sorted(set(connectors)),
                    event_ids=[e.event_id for e in all_norm],
                )
            )

        # 3. Group by tactic.
        by_tactic: dict[str, list[Sighting]] = defaultdict(list)
        for s in sightings:
            by_tactic[s.tactic].append(s)

        techniques_seen = sorted({s.technique_id for s in sightings})
        covered = set(input.covered_technique_ids)
        gaps = [t for t in techniques_seen if t not in covered]

        report = RetroHuntReport(
            window_days=input.window_days,
            iocs_checked=len(hunt_input.iocs),
            sightings=sightings,
            sightings_by_tactic=dict(by_tactic),
            techniques_with_sightings=techniques_seen,
            coverage_gaps=gaps,
            compromise_suspected=bool(sightings),
            generated_at=datetime.now(UTC),
            mock_mode=True,
        )
        return RetroHuntOutput(report=report)


NodeRegistry.register(RetroHuntNode)


__all__ = [
    "RetroHuntInput",
    "RetroHuntNode",
    "RetroHuntOutput",
]
