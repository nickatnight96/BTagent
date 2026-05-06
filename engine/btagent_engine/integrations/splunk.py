"""Splunk integration nodes.

Ports the simplest representative tool from the existing
``agents/btagent_agents/mcp/servers/splunk_mcp.py`` MCP server -- the
SPL search -- to the engine Node model.

Mock fixtures are deliberately tiny (1-2 events). They exist only so
unit tests have a deterministic non-empty shape to assert against; the
canvas user composing a workflow is the consumer of the *schema*, not
of the fixture data. The richer realistic mocks live in the agents/ MCP
server and stay there until Sprint 3 cuts the agent over to the engine.

Production path is intentionally a ``NotImplementedError`` -- the real
Splunk REST client + credential vault wiring ships in the Sprint 2
follow-up. Until then, fail loudly so a misconfigured prod env doesn't
silently succeed against fixtures.
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


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------
# Two tiny deterministic events so the happy-path test has something to
# assert on. The fall-through (any query that doesn't match a keyword)
# returns the default fixture; an explicit empty / whitespace query
# returns no events -- this is the documented "no match" shape.

_MOCK_DEFAULT_EVENTS: list[dict[str, Any]] = [
    {
        "_time": "2026-03-26T08:14:22.000+00:00",
        "src_ip": "10.1.42.17",
        "dest_ip": "198.51.100.23",
        "dest_port": 443,
        "action": "allowed",
        "host": "fw-edge-01",
        "sourcetype": "palo_alto:traffic",
        "index": "network",
    },
    {
        "_time": "2026-03-26T08:13:55.000+00:00",
        "src_ip": "10.1.42.17",
        "dest_ip": "192.0.2.100",
        "dest_port": 53,
        "action": "allowed",
        "host": "fw-edge-01",
        "sourcetype": "palo_alto:traffic",
        "index": "network",
    },
]

_MOCK_AUTH_EVENTS: list[dict[str, Any]] = [
    {
        "_time": "2026-03-26T07:48:03.000+00:00",
        "src_ip": "185.220.101.42",
        "user": "jsmith",
        "action": "failure",
        "app": "Okta",
        "reason": "INVALID_CREDENTIALS",
        "host": "idp-prod-01",
        "sourcetype": "okta:log",
        "index": "authentication",
    },
]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SplunkSearchInput(BaseModel):
    query: str = Field(
        ...,
        description="SPL search string (e.g. 'index=network src_ip=10.1.42.17').",
        examples=["index=authentication action=failure", "index=network"],
    )
    earliest_time: str = Field(
        default="-24h",
        description="Start of time range (relative like '-24h' or absolute ISO timestamp).",
    )
    latest_time: str = Field(
        default="now",
        description="End of time range ('now' or absolute ISO timestamp).",
    )
    max_count: int = Field(
        default=100,
        ge=1,
        description="Maximum number of events to return; results past this are truncated.",
    )


class SplunkSearchOutput(BaseModel):
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Matching events. Empty list when nothing matched.",
    )
    count: int = Field(
        default=0,
        description="Number of events returned (after max_count truncation).",
    )
    truncated: bool = Field(
        default=False,
        description="True if Splunk had more matches than max_count and they were dropped.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class SplunkSearchNode(Node[SplunkSearchInput, SplunkSearchOutput]):
    """Run an SPL search against Splunk and return matching events."""

    meta = NodeMeta(
        id="integration.splunk.search",
        name="Splunk: Search",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Execute an SPL search against Splunk over a time range. "
        "Returns matching events plus a truncation flag when the "
        "result set exceeds max_count.",
    )
    input_schema = SplunkSearchInput
    output_schema = SplunkSearchOutput

    async def run(
        self,
        input: SplunkSearchInput,
        ctx: NodeContext,
    ) -> SplunkSearchOutput:
        if _mock_mode_enabled():
            q_lower = input.query.lower()
            if not q_lower.strip():
                # Documented empty / fall-through shape.
                return SplunkSearchOutput(events=[], count=0, truncated=False)
            if any(k in q_lower for k in ("authentication", "okta", "login")):
                pool = _MOCK_AUTH_EVENTS
            else:
                pool = _MOCK_DEFAULT_EVENTS
            truncated = len(pool) > input.max_count
            events = pool[: input.max_count]
            return SplunkSearchOutput(
                events=events,
                count=len(events),
                truncated=truncated,
            )

        raise NotImplementedError(
            "Splunk live REST integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
