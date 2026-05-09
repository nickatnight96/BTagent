"""BTagent MCP integration layer.

Public API:
    MCPConnectionRegistry  -- singleton connection pool manager
    discover_tools         -- lazy tool discovery from MCP servers
    mcp_router_tool        -- single LangChain tool that dispatches to MCP servers
"""

from btagent_agents.mcp.discovery import discover_tools, mcp_router_tool
from btagent_agents.mcp.registry import MCPConnectionRegistry

__all__ = [
    "MCPConnectionRegistry",
    "discover_tools",
    "mcp_router_tool",
]
