"""MCP server connectors for SIEM, EDR, and security tool integrations.

Available servers:
    SplunkMCPServer      -- Splunk Enterprise Security
    CrowdStrikeMCPServer -- CrowdStrike Falcon EDR
    SentinelMCPServer    -- Microsoft Sentinel SIEM
    ElasticMCPServer     -- Elastic Security SIEM
    OktaMCPServer        -- Okta Identity Platform (System Log + OAuth grants)
"""

from btagent_agents.mcp.servers.crowdstrike_mcp import CrowdStrikeMCPServer
from btagent_agents.mcp.servers.elastic_mcp import ElasticMCPServer
from btagent_agents.mcp.servers.okta_mcp import OktaMCPServer
from btagent_agents.mcp.servers.sentinel_mcp import SentinelMCPServer
from btagent_agents.mcp.servers.splunk_mcp import SplunkMCPServer

__all__ = [
    "SplunkMCPServer",
    "CrowdStrikeMCPServer",
    "SentinelMCPServer",
    "ElasticMCPServer",
    "OktaMCPServer",
]
