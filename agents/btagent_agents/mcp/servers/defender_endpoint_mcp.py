"""Microsoft Defender for Endpoint MCP server connector — Tier-1 slice (#100).

Second-largest EDR by market share and the KQL sibling of the existing
Sentinel SIEM connector. Follows the modern Tier-1 connector pattern
(Okta / Entra / GWS / Defender O365): mock-first with a dedicated fixtures
module, lazy ``${secret:…}`` resolution, guarded live mode, and full
contract tests.

Capabilities:

- ``mde_advanced_hunting_query(query, timespan="P1D", limit=100)`` — run an
  Advanced Hunting KQL query. The mock routes on the leading table name
  (``DeviceProcessEvents`` / ``DeviceNetworkEvents`` / ``DeviceLogonEvents``)
  and applies a coarse literal filter (see below).
- ``mde_list_alerts(severity="all", status=None, limit=50)`` — Graph
  ``alerts_v2``-style alert list with severity / status filters.
- ``mde_get_machine(hostname)`` — device record (risk score, exposure,
  health, isolation state).
- ``mde_isolate_machine(hostname, isolation_type="selective")`` — network
  containment. **Requires HITL approval** (parity with ``cs_isolate_host``;
  the HITLHook gates it in the execution path).

Mock KQL semantics (documented so tests and prompts agree)
----------------------------------------------------------
Real KQL is not interpreted. The mock takes the first word of the query as
the table name and then keeps rows containing **every** double-quoted string
literal appearing in the query (case-insensitive substring over the row's
JSON). ``where DeviceName == "WS-FINANCE-07"`` therefore narrows exactly as
an analyst would expect, while arbitrary operators degrade gracefully to
"no extra filtering". An unknown table returns an ``unknown_table`` error
envelope listing the tables the mock serves.

Secret hygiene mirrors the sibling connectors: the Graph client secret is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._defender_endpoint_fixtures import (
    MDE_FIXTURE_ALERTS,
    MDE_FIXTURE_HUNTING_TABLES,
    MDE_FIXTURE_MACHINES,
)

logger = logging.getLogger("btagent.mcp.servers.defender_endpoint")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# Severity rank for the alerts filter (Graph alerts_v2 vocabulary).
_SEVERITY_RANK: dict[str, int] = {
    "informational": 10,
    "low": 30,
    "medium": 50,
    "high": 70,
}

_QUOTED_LITERAL = re.compile(r'"([^"]+)"')


def _kql_table(query: str) -> str:
    """Return the leading table name of a KQL query (first token)."""
    stripped = (query or "").strip()
    if not stripped:
        return ""
    return stripped.split()[0].split("|")[0].strip()


def _kql_literals(query: str) -> list[str]:
    """Extract the double-quoted string literals from a KQL query."""
    return _QUOTED_LITERAL.findall(query or "")


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Graph client secret.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:mde-client-secret:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Defender for Endpoint MCP server class
# ---------------------------------------------------------------------------
class DefenderEndpointMCPServer:
    """Defender for Endpoint MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the MDE / Graph APIs unless explicitly opted out AND a client
    secret resolves. The mock path is what CI exercises; live mode is a
    guarded placeholder.
    """

    server_id: str = "defender_endpoint"

    DEFAULT_TENANT_REF: str = "${env:BTAGENT_MDE_TENANT_ID}"
    DEFAULT_CLIENT_ID_REF: str = "${env:BTAGENT_MDE_CLIENT_ID}"
    DEFAULT_CLIENT_SECRET_REF: str = "${secret:vault:defender_endpoint/graph_client_secret}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        tenant_ref: str | None = None,
        client_id_ref: str | None = None,
        client_secret_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url
            or os.getenv("BTAGENT_MDE_API_URL")
            or "https://api.securitycenter.microsoft.com"
        )
        self._tenant_ref: str = tenant_ref or self.DEFAULT_TENANT_REF
        self._client_id_ref: str = client_id_ref or self.DEFAULT_CLIENT_ID_REF
        self._client_secret_ref: str = client_secret_ref or self.DEFAULT_CLIENT_SECRET_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"DefenderEndpointMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_client_secret(self) -> str:
        """Resolve the Graph client secret lazily from the configured ref."""
        resolved: str = resolve_secret(self._client_secret_ref)
        return resolved

    # ----- tools -----

    async def mde_advanced_hunting_query(
        self,
        query: str,
        timespan: str = "P1D",
        limit: int = 100,
    ) -> dict[str, Any]:
        """Run an Advanced Hunting KQL query against Defender for Endpoint.

        Args:
            query: KQL query text; the leading token names the table.
            timespan: ISO-8601 duration lookback (echoed in mock mode).
            limit: Max rows to return.

        Returns:
            Envelope with the matched table, the rows, and the mock's
            applied literal filters (see the module docstring for the mock
            KQL semantics).
        """
        if self.mock_mode:
            return self._mock_advanced_hunting_query(query, timespan, limit)
        return await self._real_advanced_hunting_query(query, timespan, limit)

    async def mde_list_alerts(
        self,
        severity: str = "all",
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Defender for Endpoint alerts.

        Args:
            severity: Minimum severity (informational|low|medium|high) or
                "all".
            status: Optional exact status filter (new|inProgress|resolved).
            limit: Max alerts to return.

        Returns:
            Envelope with the alert objects (MITRE techniques + evidence).
        """
        if self.mock_mode:
            return self._mock_list_alerts(severity, status, limit)
        return await self._real_list_alerts(severity, status, limit)

    async def mde_get_machine(self, hostname: str) -> dict[str, Any]:
        """Get a device record from Defender for Endpoint.

        Args:
            hostname: The device's DNS name.

        Returns:
            Envelope with the machine record (risk / exposure / isolation
            state) or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_get_machine(hostname)
        return await self._real_get_machine(hostname)

    async def mde_isolate_machine(
        self,
        hostname: str,
        isolation_type: str = "selective",
    ) -> dict[str, Any]:
        """Isolate a device via Defender for Endpoint network containment.

        IMPORTANT: This is a containment action that requires HITL approval
        before execution (the HITLHook gates it in the execution path).

        Args:
            hostname: The device's DNS name.
            isolation_type: "selective" (Outlook/Teams keep working) or
                "full".

        Returns:
            Containment action result; ``requires_hitl`` is always True.
        """
        if self.mock_mode:
            return self._mock_isolate_machine(hostname, isolation_type)
        return await self._real_isolate_machine(hostname, isolation_type)

    # ----- mock implementations -----

    def _mock_advanced_hunting_query(self, query: str, timespan: str, limit: int) -> dict[str, Any]:
        table = _kql_table(query)
        rows = MDE_FIXTURE_HUNTING_TABLES.get(table)
        if rows is None:
            return {
                "status": "unknown_table",
                "is_mock": True,
                "query": query,
                "message": (
                    f"Mock Advanced Hunting serves only: "
                    f"{sorted(MDE_FIXTURE_HUNTING_TABLES)} (got {table!r})"
                ),
            }
        literals = [lit.lower() for lit in _kql_literals(query)]
        matched: list[dict[str, Any]] = []
        for row in rows:
            haystack = str(row).lower()
            if all(lit in haystack for lit in literals):
                matched.append(row)
            if len(matched) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "query": query,
            "table": table,
            "timespan": timespan,
            "applied_literal_filters": literals,
            "total": len(matched),
            "rows": matched,
        }

    def _mock_list_alerts(self, severity: str, status: str | None, limit: int) -> dict[str, Any]:
        min_rank = 0 if severity == "all" else _SEVERITY_RANK.get(severity.lower(), 0)
        alerts = [
            a
            for a in MDE_FIXTURE_ALERTS
            if _SEVERITY_RANK.get(str(a.get("severity", "")).lower(), 0) >= min_rank
            and (status is None or a.get("status") == status)
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "severity": severity,
            "alert_status": status,
            "total": len(alerts),
            "alerts": alerts,
        }

    def _mock_get_machine(self, hostname: str) -> dict[str, Any]:
        machine = MDE_FIXTURE_MACHINES.get(hostname)
        if machine is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Machine '{hostname}' not found in Defender for Endpoint",
            }
        return {"status": "success", "is_mock": True, "machine": machine}

    def _mock_isolate_machine(self, hostname: str, isolation_type: str) -> dict[str, Any]:
        machine = MDE_FIXTURE_MACHINES.get(hostname)
        if machine is None:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Machine '{hostname}' not found",
            }
        if isolation_type not in ("selective", "full"):
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid isolation_type {isolation_type!r} (selective|full)",
            }
        return {
            "status": "success",
            "is_mock": True,
            "action": "isolate",
            "isolation_type": isolation_type,
            "hostname": hostname,
            "machine_id": machine["id"],
            "isolation_state": "Isolated",
            "message": (
                f"Machine '{hostname}' has been {isolation_type}ly isolated. "
                "The MDE sensor remains connected for remote investigation."
            ),
            "requires_hitl": True,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_advanced_hunting_query(
        self, query: str, timespan: str, limit: int
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "defender_endpoint: live-mode hunting query refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Defender for Endpoint live mode requires a resolvable Graph "
                "client secret (wire "
                "${secret:vault:defender_endpoint/graph_client_secret} or set "
                "BTAGENT_MDE_CLIENT_SECRET)."
            )
        raise NotImplementedError("MDE live advanced_hunting_query not yet implemented")

    async def _real_list_alerts(
        self, severity: str, status: str | None, limit: int
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "defender_endpoint: live-mode alert list refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Defender for Endpoint live mode requires a resolvable Graph client secret"
            )
        raise NotImplementedError("MDE live list_alerts not yet implemented")

    async def _real_get_machine(self, hostname: str) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError(
                "Defender for Endpoint live mode requires a resolvable Graph client secret"
            )
        raise NotImplementedError("MDE live get_machine not yet implemented")

    async def _real_isolate_machine(self, hostname: str, isolation_type: str) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError(
                "Defender for Endpoint live mode requires a resolvable Graph client secret"
            )
        raise NotImplementedError("MDE live isolate_machine not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "mde_advanced_hunting_query",
                "description": (
                    "Run a Defender for Endpoint Advanced Hunting KQL query "
                    "(DeviceProcessEvents / DeviceNetworkEvents / "
                    "DeviceLogonEvents). KQL parity with the Sentinel "
                    "connector for endpoint telemetry."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "KQL query text"},
                        "timespan": {
                            "type": "string",
                            "description": "ISO-8601 duration lookback",
                            "default": "P1D",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max rows to return",
                            "default": 100,
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "mde_list_alerts",
                "description": (
                    "List Defender for Endpoint alerts with severity / status "
                    "filters. Alerts carry MITRE techniques and process / IP "
                    "evidence."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["informational", "low", "medium", "high", "all"],
                            "default": "all",
                            "description": "Minimum severity",
                        },
                        "status": {
                            "type": "string",
                            "description": "Optional exact status (new|inProgress|resolved)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max alerts to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "mde_get_machine",
                "description": (
                    "Get a Defender for Endpoint device record: risk score, "
                    "exposure level, health, isolation state, logged-on users."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Device DNS name"},
                    },
                    "required": ["hostname"],
                },
            },
            {
                "name": "mde_isolate_machine",
                "description": (
                    "Isolate a device via Defender for Endpoint network "
                    "containment (selective or full). REQUIRES HITL APPROVAL."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Device DNS name"},
                        "isolation_type": {
                            "type": "string",
                            "enum": ["selective", "full"],
                            "default": "selective",
                        },
                    },
                    "required": ["hostname"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = DefenderEndpointMCPServer()


@tool
async def mde_advanced_hunting_query(
    query: str,
    timespan: str = "P1D",
    limit: int = 100,
) -> dict[str, Any]:
    """Run a Defender for Endpoint Advanced Hunting KQL query.

    Args:
        query: KQL query text; the leading token names the table.
        timespan: ISO-8601 duration lookback.
        limit: Max rows to return.
    """
    return await _server.mde_advanced_hunting_query(query, timespan, limit)


@tool
async def mde_list_alerts(
    severity: str = "all",
    status: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List Defender for Endpoint alerts.

    Args:
        severity: Minimum severity (informational|low|medium|high) or "all".
        status: Optional exact status filter (new|inProgress|resolved).
        limit: Max alerts to return.
    """
    return await _server.mde_list_alerts(severity, status, limit)


@tool
async def mde_get_machine(hostname: str) -> dict[str, Any]:
    """Get a Defender for Endpoint device record.

    Args:
        hostname: The device's DNS name.
    """
    return await _server.mde_get_machine(hostname)


@tool
async def mde_isolate_machine(
    hostname: str,
    isolation_type: str = "selective",
) -> dict[str, Any]:
    """Isolate a device via Defender for Endpoint. Requires HITL approval.

    Args:
        hostname: The device's DNS name.
        isolation_type: "selective" or "full".
    """
    return await _server.mde_isolate_machine(hostname, isolation_type)
