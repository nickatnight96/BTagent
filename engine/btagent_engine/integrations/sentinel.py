"""Microsoft Sentinel integration node.

Ports the simplest representative tool from the existing
``agents/btagent_agents/mcp/servers/sentinel_mcp.py`` MCP server -- the
KQL query -- to the engine Node model.

The output is shaped after Azure Monitor's table response: a list of
column names plus the row dicts. This makes it composable with a
downstream "table to records" transform without leaking Sentinel-specific
fields up the workflow graph.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.integrations._manifests import SENTINEL_MANIFEST
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
# One sign-in row, one process row -- enough for tests to assert the
# row + column-name shape; canvas users get the schema, not the data.

_MOCK_SIGNIN_ROWS: list[dict[str, Any]] = [
    {
        "TimeGenerated": "2026-03-26T07:48:03Z",
        "UserPrincipalName": "jsmith@acme-corp.com",
        "AppDisplayName": "Azure VPN",
        "IPAddress": "185.220.101.42",
        "ResultType": 50126,
        "ResultDescription": "Invalid username or password",
        "RiskLevelDuringSignIn": "high",
    },
]

_MOCK_PROCESS_ROWS: list[dict[str, Any]] = [
    {
        "TimeGenerated": "2026-03-26T08:14:22Z",
        "Computer": "WS-JSMITH-PC",
        "Account": "ACME\\jsmith",
        "EventID": 4688,
        "NewProcessName": ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...",
    },
]


def _columns_for(rows: list[dict[str, Any]]) -> list[str]:
    """Stable column list = keys of the first row, in insertion order.

    Real Azure Monitor returns columns explicitly; we synthesize them
    from the first row in mock mode so the output schema is always
    consistent.
    """
    if not rows:
        return []
    return list(rows[0].keys())


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SentinelKQLQueryInput(BaseModel):
    query: str = Field(
        ...,
        description="KQL query string (e.g. 'SigninLogs | where ResultType != 0').",
        examples=["SigninLogs | where IPAddress == '185.220.101.42'"],
    )
    timespan_hours: int = Field(
        default=24,
        ge=1,
        description="Look-back window in hours. Mapped to ISO8601 PT<N>H for the API.",
    )


class SentinelKQLQueryOutput(BaseModel):
    rows: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Result rows. Empty list when nothing matched.",
    )
    column_names: list[str] = Field(
        default_factory=list,
        description="Ordered column names; empty when there are no rows.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class SentinelKQLQueryNode(Node[SentinelKQLQueryInput, SentinelKQLQueryOutput]):
    """Run a KQL query against Microsoft Sentinel and return rows + columns."""

    meta = NodeMeta(
        id="integration.sentinel.kql_query",
        name="Sentinel: KQL Query",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Execute a Kusto Query Language query against the linked "
        "Sentinel workspace over a look-back window. Returns rows "
        "plus the ordered column list.",
    )
    input_schema = SentinelKQLQueryInput
    output_schema = SentinelKQLQueryOutput
    manifest = SENTINEL_MANIFEST
    capability_id = "kql_query"

    async def run(
        self,
        input: SentinelKQLQueryInput,
        ctx: NodeContext,
    ) -> SentinelKQLQueryOutput:
        if _mock_mode_enabled():
            q_lower = input.query.lower()
            if not q_lower.strip():
                return SentinelKQLQueryOutput(rows=[], column_names=[])
            if "signin" in q_lower or "azureadid" in q_lower or "userprincipalname" in q_lower:
                rows = _MOCK_SIGNIN_ROWS
            elif "securityevent" in q_lower or "process" in q_lower or "eventid" in q_lower:
                rows = _MOCK_PROCESS_ROWS
            else:
                # Unknown / non-fixture query -> documented empty shape.
                return SentinelKQLQueryOutput(rows=[], column_names=[])
            return SentinelKQLQueryOutput(rows=rows, column_names=_columns_for(rows))

        raise NotImplementedError(
            "Microsoft Sentinel live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
