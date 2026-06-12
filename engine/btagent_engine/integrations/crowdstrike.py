"""CrowdStrike Falcon integration nodes.

Ports representative tools from the existing
``agents/btagent_agents/mcp/servers/crowdstrike_mcp.py`` MCP server to
the engine Node model:

* ``CrowdStrikeListDetectionsNode`` -- list current Falcon detections.
* ``CrowdStrikeEventSearchNode`` -- run a Falcon LogScale query over raw
  endpoint telemetry (ProcessRollup2 and similar event streams).
* ``CrowdStrikeIsolateHostNode`` -- network-contain a host (the
  representative containment action; in production this composes with
  the HITL middleware in front of the Runner).

The fixtures are intentionally minimal -- just enough for tests to
assert the schema shape. The richer agents/ fixtures stay in the agents/
tree until Sprint 3 cuts over.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.integrations._manifests import CROWDSTRIKE_MANIFEST
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


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

# Realistic ProcessRollup2-style raw endpoint events for the event_search mock.
# Fields match Falcon LogScale schema so the hunting-runner entity / observable
# extractors (ComputerName -> host, UserName -> user, SHA256HashData -> hash)
# can find their values without any adapter shim.
#
# Timestamps are expressed as offsets from now (in minutes) so the mock stays
# fresh regardless of when the tests run.  The third event is >48h old so that
# tests asserting lookback filtering can use a short window and expect 0 results.
_MOCK_ENDPOINT_EVENT_TEMPLATES: list[tuple[int, dict[str, Any]]] = [
    # (age_minutes, static_fields)
    (
        30,
        {
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "WS-JSMITH-PC",
            "UserName": "jsmith",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
            "SHA256HashData": "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
            "MD5HashData": "d41d8cd98f00b204e9800998ecf8427e",
            "TargetProcessId": "4812",
            "cid": "cid_abc123",
        },
    ),
    (
        90,
        {
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "WS-JSMITH-PC",
            "UserName": "jsmith",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "SHA256HashData": "def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "MD5HashData": "098f6bcd4621d373cade4e832627b4f6",
            "TargetProcessId": "3904",
            "cid": "cid_abc123",
        },
    ),
    (
        # >48h old — used by the lookback-filter test (lookback_hours=1 -> 0 results)
        2940,
        {
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "SRV-WEBAPP-01",
            "UserName": "svc_web",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\net.exe",
            "CommandLine": "net.exe localgroup administrators",
            "SHA256HashData": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fe",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
            "MD5HashData": "a87ff679a2f3e71d9181a67b7542122c",
            "TargetProcessId": "2248",
            "cid": "cid_abc123",
        },
    ),
]


def _build_mock_endpoint_events() -> list[dict[str, Any]]:
    """Return mock events with timestamps generated relative to *now*."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    result: list[dict[str, Any]] = []
    for age_minutes, fields in _MOCK_ENDPOINT_EVENT_TEMPLATES:
        ts = now - timedelta(minutes=age_minutes)
        result.append({"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"), **fields})
    return result


# ---------------------------------------------------------------------------
# Schemas: event_search
# ---------------------------------------------------------------------------


class CrowdStrikeEventSearchInput(BaseModel):
    query: str = Field(
        ...,
        description=(
            "Falcon LogScale / event-search query string "
            "(e.g. '#event_simpleName=ProcessRollup2 ImageFileName=/powershell.exe/'). "
            "Accepts the full LogScale filter syntax used by Falcon Insight event search."
        ),
        examples=["#event_simpleName=ProcessRollup2"],
    )
    lookback_hours: int = Field(
        default=24,
        ge=1,
        description="Look-back window in hours relative to now (maps to LogScale start/end time).",
    )
    max_events: int = Field(
        default=100,
        ge=1,
        description="Maximum number of raw endpoint events to return.",
    )


class CrowdStrikeEventSearchOutput(BaseModel):
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw Falcon LogScale endpoint events. Empty list when nothing matched.",
    )
    count: int = Field(
        default=0,
        description="Number of events returned (after max_events truncation).",
    )
    truncated: bool = Field(
        default=False,
        description="True if the search had more matches than max_events and they were dropped.",
    )


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
class CrowdStrikeEventSearchNode(Node[CrowdStrikeEventSearchInput, CrowdStrikeEventSearchOutput]):
    """Run a Falcon LogScale query over raw CrowdStrike endpoint telemetry.

    Executes an event-search query against Falcon Insight's raw event stream
    (ProcessRollup2, NetworkConnectIP4, DnsRequest, etc.), returning the
    matching raw events for downstream enrichment and entity extraction.

    Mock path returns ProcessRollup2-style fixtures so the hunting runner's
    entity / observable extractors find host (ComputerName), user (UserName),
    and hash (SHA256HashData) values. The lookback and max_events caps are
    honoured: events older than ``lookback_hours`` are filtered out and the
    result list is sliced to ``max_events``.
    """

    meta = NodeMeta(
        id="integration.crowdstrike.event_search",
        name="CrowdStrike: Event Search",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description=(
            "Execute a Falcon LogScale query over raw endpoint telemetry. "
            "Returns matching events plus a truncation flag when the result "
            "set exceeds max_events."
        ),
    )
    input_schema = CrowdStrikeEventSearchInput
    output_schema = CrowdStrikeEventSearchOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "event_search"

    async def run(
        self,
        input: CrowdStrikeEventSearchInput,
        ctx: NodeContext,
    ) -> CrowdStrikeEventSearchOutput:
        if _mock_mode_enabled():
            from datetime import UTC, datetime, timedelta

            cutoff = datetime.now(UTC) - timedelta(hours=input.lookback_hours)

            pool: list[dict[str, Any]] = []
            for event in _build_mock_endpoint_events():
                ts_raw = event.get("timestamp", "")
                try:
                    # Parse ISO timestamp; treat naive as UTC.
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts < cutoff:
                        continue
                except (ValueError, AttributeError):
                    pass  # Unparseable timestamps pass through (do not filter).
                pool.append(event)

            truncated = len(pool) > input.max_events
            events = pool[: input.max_events]
            return CrowdStrikeEventSearchOutput(
                events=events,
                count=len(events),
                truncated=truncated,
            )

        raise NotImplementedError(
            "CrowdStrike live event-search integration ships in Sprint 4 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


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
