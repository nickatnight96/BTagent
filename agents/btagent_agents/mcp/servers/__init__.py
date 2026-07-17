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
    CloudTrailMCPServer  -- AWS CloudTrail + GuardDuty (events + findings + principal summary)
    JiraMCPServer        -- Jira Service Management (IR ticket sink: create/comment/transition)
    SlackMCPServer       -- Slack (IC comms bridge: incident channels + messages + pins)
    DuoMCPServer         -- Cisco Duo MFA (auth logs + users + admin activity) [Tier-2]
    CortexXDRMCPServer   -- Palo Alto Cortex XDR (XQL + incidents + endpoints + isolation) [Tier-2]
    ServiceNowMCPServer  -- ServiceNow SecOps (SIR create + work notes + lifecycle) [Tier-2]
    GCPCloudAuditMCPServer -- GCP Cloud Audit Logs + SCC (audit search + findings + summary) [Tier-2]
    ProofpointMCPServer  -- Proofpoint TAP (message events + URL clicks + VAP summary) [Tier-2]
    WizMCPServer         -- Wiz CNAPP (posture issues + vulns + resource summary) [Tier-2]
    MimecastMCPServer    -- Mimecast email gateway (messages + held queue + URL clicks) [Tier-2]
    GitMCPServer         -- Detection-rule repository (HITL-gated PR composer surface)
"""

from btagent_agents.mcp.servers.cloudtrail_mcp import CloudTrailMCPServer
from btagent_agents.mcp.servers.cortex_mcp import CortexXDRMCPServer
from btagent_agents.mcp.servers.crowdstrike_mcp import CrowdStrikeMCPServer
from btagent_agents.mcp.servers.defender_endpoint_mcp import DefenderEndpointMCPServer
from btagent_agents.mcp.servers.defender_o365_mcp import DefenderO365MCPServer
from btagent_agents.mcp.servers.duo_mcp import DuoMCPServer
from btagent_agents.mcp.servers.elastic_mcp import ElasticMCPServer
from btagent_agents.mcp.servers.entra_mcp import EntraMCPServer
from btagent_agents.mcp.servers.gcp_mcp import GCPCloudAuditMCPServer
from btagent_agents.mcp.servers.git_mcp import GitMCPServer
from btagent_agents.mcp.servers.gws_mcp import GoogleWorkspaceMCPServer
from btagent_agents.mcp.servers.jira_mcp import JiraMCPServer
from btagent_agents.mcp.servers.mimecast_mcp import MimecastMCPServer
from btagent_agents.mcp.servers.okta_mcp import OktaMCPServer
from btagent_agents.mcp.servers.proofpoint_mcp import ProofpointMCPServer
from btagent_agents.mcp.servers.sentinel_mcp import SentinelMCPServer
from btagent_agents.mcp.servers.sentinelone_mcp import SentinelOneMCPServer
from btagent_agents.mcp.servers.servicenow_mcp import ServiceNowMCPServer
from btagent_agents.mcp.servers.slack_mcp import SlackMCPServer
from btagent_agents.mcp.servers.splunk_mcp import SplunkMCPServer
from btagent_agents.mcp.servers.wiz_mcp import WizMCPServer
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
    "CloudTrailMCPServer",
    "JiraMCPServer",
    "SlackMCPServer",
    "DuoMCPServer",
    "CortexXDRMCPServer",
    "ServiceNowMCPServer",
    "GCPCloudAuditMCPServer",
    "ProofpointMCPServer",
    "WizMCPServer",
    "MimecastMCPServer",
    "GitMCPServer",
]
