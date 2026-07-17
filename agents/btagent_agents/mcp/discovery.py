"""MCP lazy tool discovery.

Provides:
- ``discover_tools()``  -- discovers available tools from MCP server instances
- ``mcp_router_tool``   -- a single LangChain tool that the agent calls to
  dispatch requests to the appropriate MCP server tool, avoiding token bloat
  from injecting every tool definition into the context.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from btagent_shared.types.mcp import MCPToolInfo
from langchain_core.tools import tool

from btagent_agents.mcp.registry import ManagedConnection

logger = logging.getLogger("btagent.mcp.discovery")

# ---------------------------------------------------------------------------
# Server registry -- maps server_id to its server class instance.
# Populated lazily on first call to ``discover_tools``.
# ---------------------------------------------------------------------------
_SERVER_CLASSES: dict[str, type] = {}
_SERVER_INSTANCES: dict[str, Any] = {}
_TOOL_INDEX: dict[str, MCPToolInfo] = {}
_TOOL_DISPATCH: dict[str, Any] = {}  # tool_name -> (server_instance, method_name)


def _ensure_servers_loaded() -> None:
    """Import MCP server classes lazily to avoid circular imports."""
    if _SERVER_CLASSES:
        return

    from btagent_agents.mcp.servers.cloudtrail_mcp import CloudTrailMCPServer
    from btagent_agents.mcp.servers.cortex_mcp import CortexXDRMCPServer
    from btagent_agents.mcp.servers.crowdstrike_mcp import CrowdStrikeMCPServer
    from btagent_agents.mcp.servers.defender_endpoint_mcp import DefenderEndpointMCPServer
    from btagent_agents.mcp.servers.defender_o365_mcp import DefenderO365MCPServer
    from btagent_agents.mcp.servers.duo_mcp import DuoMCPServer
    from btagent_agents.mcp.servers.elastic_mcp import ElasticMCPServer
    from btagent_agents.mcp.servers.entra_mcp import EntraMCPServer
    from btagent_agents.mcp.servers.git_mcp import GitMCPServer
    from btagent_agents.mcp.servers.gws_mcp import GoogleWorkspaceMCPServer
    from btagent_agents.mcp.servers.jira_mcp import JiraMCPServer
    from btagent_agents.mcp.servers.okta_mcp import OktaMCPServer
    from btagent_agents.mcp.servers.sentinel_mcp import SentinelMCPServer
    from btagent_agents.mcp.servers.sentinelone_mcp import SentinelOneMCPServer
    from btagent_agents.mcp.servers.servicenow_mcp import ServiceNowMCPServer
    from btagent_agents.mcp.servers.slack_mcp import SlackMCPServer
    from btagent_agents.mcp.servers.splunk_mcp import SplunkMCPServer
    from btagent_agents.mcp.servers.zeek_mcp import ZeekMCPServer

    _SERVER_CLASSES["splunk"] = SplunkMCPServer
    _SERVER_CLASSES["crowdstrike"] = CrowdStrikeMCPServer
    _SERVER_CLASSES["sentinel"] = SentinelMCPServer
    _SERVER_CLASSES["elastic"] = ElasticMCPServer
    _SERVER_CLASSES["okta"] = OktaMCPServer
    _SERVER_CLASSES["entra"] = EntraMCPServer
    _SERVER_CLASSES["gws"] = GoogleWorkspaceMCPServer
    _SERVER_CLASSES["defender_o365"] = DefenderO365MCPServer
    _SERVER_CLASSES["defender_endpoint"] = DefenderEndpointMCPServer
    _SERVER_CLASSES["sentinelone"] = SentinelOneMCPServer
    _SERVER_CLASSES["zeek"] = ZeekMCPServer
    _SERVER_CLASSES["cloudtrail"] = CloudTrailMCPServer
    _SERVER_CLASSES["cortex"] = CortexXDRMCPServer
    _SERVER_CLASSES["jira"] = JiraMCPServer
    _SERVER_CLASSES["slack"] = SlackMCPServer
    _SERVER_CLASSES["duo"] = DuoMCPServer
    _SERVER_CLASSES["servicenow"] = ServiceNowMCPServer
    _SERVER_CLASSES["git"] = GitMCPServer


def _get_server_instance(server_id: str) -> Any:
    """Get or create a server instance for *server_id*."""
    if server_id not in _SERVER_INSTANCES:
        _ensure_servers_loaded()
        cls = _SERVER_CLASSES.get(server_id)
        if cls is None:
            raise ValueError(f"Unknown MCP server: {server_id}")
        _SERVER_INSTANCES[server_id] = cls()
    return _SERVER_INSTANCES[server_id]


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


def discover_tools(
    connections: list[ManagedConnection] | None = None,
    *,
    server_ids: list[str] | None = None,
) -> list[MCPToolInfo]:
    """Discover available tools from MCP servers.

    This performs *lazy* discovery: it reads tool metadata (name, description,
    input_schema) from each server without loading the full tool
    implementation.  This keeps the agent's context window small.

    Args:
        connections: Optional list of active ``ManagedConnection`` objects.
            If provided, only tools from servers with an active connection
            are returned.
        server_ids: Optional explicit list of server IDs to discover.  If
            omitted all known servers are discovered.

    Returns:
        List of :class:`MCPToolInfo` for every discovered tool.
    """
    _ensure_servers_loaded()

    # Determine which servers to query
    if server_ids is not None:
        ids = server_ids
    elif connections is not None:
        ids = [c.server_name for c in connections]
    else:
        ids = list(_SERVER_CLASSES.keys())

    discovered: list[MCPToolInfo] = []

    for sid in ids:
        try:
            server = _get_server_instance(sid)
            metadata_list: list[dict[str, Any]] = server.get_tool_metadata()

            for meta in metadata_list:
                info = MCPToolInfo(
                    name=meta["name"],
                    description=meta["description"],
                    server_id=meta["server_id"],
                    input_schema=meta.get("input_schema", {}),
                )
                _TOOL_INDEX[info.name] = info

                # Register dispatch
                method = getattr(server, meta["name"], None)
                if method is not None:
                    _TOOL_DISPATCH[meta["name"]] = (server, meta["name"])

                discovered.append(info)

        except Exception as exc:
            logger.warning("Failed to discover tools from %s: %s", sid, exc)

    logger.info(
        "Discovered %d tools from %d servers: %s",
        len(discovered),
        len(ids),
        [t.name for t in discovered],
    )
    return discovered


def get_tool_catalog() -> dict[str, MCPToolInfo]:
    """Return the current tool index (name -> MCPToolInfo).

    If tools have not been discovered yet, triggers a full discovery.
    """
    if not _TOOL_INDEX:
        discover_tools()
    return dict(_TOOL_INDEX)


def get_tool_descriptions_text() -> str:
    """Format all discovered tools as a compact text block for agent context.

    Returns a string like::

        Available MCP tools:
        - splunk_search (splunk): Execute an SPL search query ...
        - cs_get_detections (crowdstrike): Retrieve CrowdStrike Falcon ...
        ...
    """
    catalog = get_tool_catalog()
    if not catalog:
        return "No MCP tools available."

    lines = ["Available MCP tools:"]
    for info in catalog.values():
        params = ""
        schema = info.input_schema
        if schema and "properties" in schema:
            param_names = list(schema["properties"].keys())
            required = schema.get("required", [])
            parts = []
            for p in param_names:
                parts.append(f"{p}{'*' if p in required else ''}")
            params = f"({', '.join(parts)})"
        lines.append(f"  - {info.name}{params} [{info.server_id}]: {info.description}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Router Tool -- single entry-point LangChain tool
# ---------------------------------------------------------------------------


@tool
async def mcp_router_tool(
    tool_name: str,
    arguments: str = "{}",
    hitl_approved: bool = False,
) -> dict[str, Any]:
    """Route a tool call to the appropriate MCP server.

    Instead of injecting every MCP tool into the agent context (which wastes
    tokens), the agent calls this single router tool specifying which MCP tool
    to invoke and what arguments to pass.

    Every dispatch is policy-checked against the connector manifests
    (:mod:`btagent_agents.mcp.policy`, #100 Layer 3): HITL-gated actions are
    refused with a ``hitl_required`` envelope until the HITL resume path
    re-invokes with ``hitl_approved=True``, capabilities whose declared
    TLP egress ranks below the active context classification are refused
    with ``tlp_blocked``, and undeclared tools are refused outright.

    Use ``get_tool_descriptions_text()`` to see which tools are available.

    Args:
        tool_name: Name of the MCP tool to invoke (e.g. "splunk_search",
            "cs_get_detections").
        arguments: JSON-encoded arguments for the tool.  Each tool has
            its own schema -- see the tool catalog for details.
        hitl_approved: Set ONLY by the HITL resume path after an analyst
            approves a gated action; never set speculatively.

    Returns:
        The result from the invoked MCP tool, or an error / policy dict.
    """
    # Parse arguments
    try:
        args = json.loads(arguments) if isinstance(arguments, str) else arguments
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "message": f"Invalid JSON arguments: {exc}",
            "tool_name": tool_name,
        }

    # Manifest policy gate (#100 Layer 3) — HITL / TLP / undeclared.
    from btagent_agents.mcp.policy import evaluate_tool_call

    verdict = evaluate_tool_call(tool_name, hitl_approved=hitl_approved)
    if not verdict.allowed:
        logger.warning("mcp policy refused %s: %s (%s)", tool_name, verdict.status, verdict.reason)
        return verdict.to_envelope()

    # Look up dispatch target
    if not _TOOL_DISPATCH:
        discover_tools()

    dispatch = _TOOL_DISPATCH.get(tool_name)
    if dispatch is None:
        available = list(_TOOL_DISPATCH.keys())
        return {
            "status": "error",
            "message": f"Unknown tool: '{tool_name}'",
            "available_tools": available,
        }

    server_instance, method_name = dispatch
    method = getattr(server_instance, method_name)

    # Invoke
    try:
        result = await method(**args)
        # OCSF contract check (#100 Layer 2) — refuse results that claim
        # event classes their manifest doesn't declare (connector bug).
        from btagent_agents.mcp.ocsf import validate_ocsf_claims

        violation = validate_ocsf_claims(tool_name, result)
        if violation is not None:
            logger.error("mcp ocsf violation for %s: %s", tool_name, violation["message"])
            return violation
        return result
    except TypeError as exc:
        return {
            "status": "error",
            "message": f"Invalid arguments for '{tool_name}': {exc}",
            "tool_name": tool_name,
            "provided_args": args,
        }
    except NotImplementedError:
        return {
            "status": "error",
            "message": (
                f"Tool '{tool_name}' real-mode not implemented. "
                "Set BTAGENT_MOCK_CONNECTORS=true for mock mode."
            ),
            "tool_name": tool_name,
        }
    except Exception as exc:
        logger.exception("MCP router error for tool %s", tool_name)
        return {
            "status": "error",
            "message": f"Tool execution failed: {exc}",
            "tool_name": tool_name,
        }
