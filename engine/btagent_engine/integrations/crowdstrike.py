"""CrowdStrike Falcon integration nodes.

Ports two representative tools from the existing
``agents/btagent_agents/mcp/servers/crowdstrike_mcp.py`` MCP server to
the engine Node model:

* ``CrowdStrikeListDetectionsNode`` -- list current Falcon detections.
* ``CrowdStrikeIsolateHostNode`` -- network-contain a host (the
  representative containment action; in production this composes with
  the HITL middleware in front of the Runner).

The fixtures are intentionally minimal -- one detection, one host --
just enough for tests to assert the schema shape. The richer agents/
fixtures stay in the agents/ tree until Sprint 3 cuts over.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.integrations._manifests import CROWDSTRIKE_MANIFEST


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------

_MOCK_DETECTIONS: list[dict[str, Any]] = [
    {
        "detection_id": "ldt:abcdef123456:1001",
        "created_timestamp": "2026-03-26T08:21:50Z",
        "max_severity": 90,
        "severity": "critical",
        "status": "new",
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Execution",
        "technique": "PowerShell",
        "technique_id": "T1059.001",
    },
    {
        "detection_id": "ldt:abcdef123456:1002",
        "created_timestamp": "2026-03-26T07:55:30Z",
        "max_severity": 70,
        "severity": "high",
        "status": "new",
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
    },
]

# Severity rank for filtering. Anything below the requested floor is
# dropped from the result set.
_SEVERITY_RANK: dict[str, int] = {
    "low": 30,
    "medium": 50,
    "high": 70,
    "critical": 90,
}

_MOCK_HOSTS: dict[str, dict[str, Any]] = {
    "WS-JSMITH-PC": {
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "hostname": "WS-JSMITH-PC",
    },
}


# ---------------------------------------------------------------------------
# Schemas: list_detections
# ---------------------------------------------------------------------------


class CrowdStrikeListDetectionsInput(BaseModel):
    severity: str = Field(
        default="all",
        description="Minimum severity floor: 'critical' | 'high' | 'medium' | 'low' | 'all'.",
    )
    limit: int = Field(
        default=50,
        ge=1,
        description="Maximum number of detections to return.",
    )


class CrowdStrikeListDetectionsOutput(BaseModel):
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Matching Falcon detections. Empty list when nothing matched.",
    )
    count: int = Field(
        default=0,
        description="Number of detections returned (after limit truncation).",
    )


# ---------------------------------------------------------------------------
# Schemas: isolate_host
# ---------------------------------------------------------------------------


class CrowdStrikeIsolateHostInput(BaseModel):
    hostname: str = Field(
        ...,
        description="Hostname to network-contain via Falcon.",
        examples=["WS-JSMITH-PC"],
    )


class CrowdStrikeIsolateHostOutput(BaseModel):
    hostname: str = Field(..., description="Echo of the targeted hostname.")
    device_id: str | None = Field(
        default=None,
        description="Falcon device id if the host was found, None otherwise.",
    )
    contained: bool = Field(
        default=False,
        description="True if the host was successfully placed in network containment.",
    )
    status: str = Field(
        default="not_found",
        description="One of 'contained' | 'not_found' (mock); production may add 'pending'.",
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@NodeRegistry.register
class CrowdStrikeListDetectionsNode(
    Node[CrowdStrikeListDetectionsInput, CrowdStrikeListDetectionsOutput]
):
    """List current CrowdStrike Falcon detections, optionally filtered by severity."""

    meta = NodeMeta(
        id="integration.crowdstrike.list_detections",
        name="CrowdStrike: List Detections",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Retrieve Falcon detections at or above a given severity. "
        "Returns the raw detection payloads plus a count.",
    )
    input_schema = CrowdStrikeListDetectionsInput
    output_schema = CrowdStrikeListDetectionsOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "list_detections"

    async def run(
        self,
        input: CrowdStrikeListDetectionsInput,
        ctx: NodeContext,
    ) -> CrowdStrikeListDetectionsOutput:
        if _mock_mode_enabled():
            sev = input.severity.lower()
            if sev == "all":
                pool = list(_MOCK_DETECTIONS)
            else:
                floor = _SEVERITY_RANK.get(sev)
                if floor is None:
                    # Unknown severity -> documented empty shape.
                    return CrowdStrikeListDetectionsOutput(detections=[], count=0)
                pool = [d for d in _MOCK_DETECTIONS if d["max_severity"] >= floor]
            detections = pool[: input.limit]
            return CrowdStrikeListDetectionsOutput(
                detections=detections,
                count=len(detections),
            )

        raise NotImplementedError(
            "CrowdStrike live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class CrowdStrikeIsolateHostNode(Node[CrowdStrikeIsolateHostInput, CrowdStrikeIsolateHostOutput]):
    """Network-contain a host via CrowdStrike Falcon.

    This is a destructive containment action; in a real deployment the
    Runner should be configured with a HITL middleware that gates this
    node on analyst approval. The Node itself does not enforce HITL --
    that's the middleware's job, see ``btagent_engine.middleware``.
    """

    meta = NodeMeta(
        id="integration.crowdstrike.isolate_host",
        name="CrowdStrike: Isolate Host",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Place a host in Falcon network containment. The agent "
        "remains operational for remote investigation, but all "
        "non-Falcon network traffic is blocked. Compose with HITL "
        "middleware before running in production.",
    )
    input_schema = CrowdStrikeIsolateHostInput
    output_schema = CrowdStrikeIsolateHostOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "isolate_host"

    async def run(
        self,
        input: CrowdStrikeIsolateHostInput,
        ctx: NodeContext,
    ) -> CrowdStrikeIsolateHostOutput:
        if _mock_mode_enabled():
            host = _MOCK_HOSTS.get(input.hostname)
            if host is None:
                # Documented empty / fall-through shape for unknown hosts.
                return CrowdStrikeIsolateHostOutput(
                    hostname=input.hostname,
                    device_id=None,
                    contained=False,
                    status="not_found",
                )
            return CrowdStrikeIsolateHostOutput(
                hostname=input.hostname,
                device_id=host["device_id"],
                contained=True,
                status="contained",
            )

        raise NotImplementedError(
            "CrowdStrike live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
