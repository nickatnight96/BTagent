"""MCP server connectors for SIEM, EDR, and security tool integrations.

Available servers:
    SplunkMCPServer      -- Splunk Enterprise Security
    CrowdStrikeMCPServer -- CrowdStrike Falcon EDR
    SentinelMCPServer    -- Microsoft Sentinel SIEM
    ElasticMCPServer     -- Elastic Security SIEM
    OktaMCPServer        -- Okta Identity Platform (System Log + OAuth grants)
    EntraMCPServer       -- Microsoft Entra ID / Azure AD (sign-in + audit + grants)
    GoogleWorkspaceMCPServer -- Google Workspace (login + admin/token activity + tokens)
    DefenderO365MCPServer -- Microsoft Defender for O365 (email events + quarantine + submissions)
    DefenderEndpointMCPServer -- Microsoft Defender for Endpoint (KQL hunting + alerts + isolation)
    SentinelOneMCPServer -- SentinelOne (Deep Visibility + threats + agents + mitigation)
    ZeekMCPServer        -- Zeek / Corelight (log-stream search + notices + behavioral summary)
    GitMCPServer         -- Detection-rule repository (HITL-gated PR composer surface)
"""

from btagent_agents.mcp.servers.crowdstrike_mcp import CrowdStrikeMCPServer
from btagent_agents.mcp.servers.defender_endpoint_mcp import DefenderEndpointMCPServer
from btagent_agents.mcp.servers.defender_o365_mcp import DefenderO365MCPServer
from btagent_agents.mcp.servers.elastic_mcp import ElasticMCPServer
from btagent_agents.mcp.servers.entra_mcp import EntraMCPServer
from btagent_agents.mcp.servers.git_mcp import GitMCPServer
from btagent_agents.mcp.servers.gws_mcp import GoogleWorkspaceMCPServer
from btagent_agents.mcp.servers.okta_mcp import OktaMCPServer
from btagent_agents.mcp.servers.sentinel_mcp import SentinelMCPServer
from btagent_agents.mcp.servers.sentinelone_mcp import SentinelOneMCPServer
from btagent_agents.mcp.servers.splunk_mcp import SplunkMCPServer
from btagent_agents.mcp.servers.zeek_mcp import ZeekMCPServer

__all__ = [
    "SplunkMCPServer",
    "CrowdStrikeMCPServer",
    "SentinelMCPServer",
    "ElasticMCPServer",
    "OktaMCPServer",
    "EntraMCPServer",
    "GoogleWorkspaceMCPServer",
    "DefenderO365MCPServer",
    "DefenderEndpointMCPServer",
    "SentinelOneMCPServer",
    "ZeekMCPServer",
    "GitMCPServer",
]
