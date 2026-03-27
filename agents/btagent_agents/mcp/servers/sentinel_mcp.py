"""Microsoft Sentinel MCP server connector.

Tools:
- sentinel_query(kql_query, timespan)
- sentinel_get_incidents(status, severity)
- sentinel_get_alerts(timespan)

Mock mode returns realistic KQL query results, incident payloads,
and alert data.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.sentinel")

MOCK_MODE = (
    os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"
)


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_KQL_RESULTS: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "TimeGenerated": "2026-03-26T08:14:22Z",
            "Computer": "WS-JSMITH-PC",
            "Account": "ACME\\jsmith",
            "EventID": 4688,
            "NewProcessName": (
                "C:\\Windows\\System32\\"
                "WindowsPowerShell\\v1.0\\powershell.exe"
            ),
            "ParentProcessName": (
                "C:\\Windows\\System32\\cmd.exe"
            ),
            "CommandLine": (
                "powershell.exe -enc "
                "SQBFAFgAIAAoAE4AZQB3..."
            ),
            "SubjectLogonId": "0x3E7",
            "Type": "SecurityEvent",
        },
        {
            "TimeGenerated": "2026-03-26T08:13:55Z",
            "Computer": "WS-JSMITH-PC",
            "Account": "ACME\\jsmith",
            "EventID": 4688,
            "NewProcessName": (
                "C:\\Windows\\System32\\cmd.exe"
            ),
            "ParentProcessName": (
                "C:\\Program Files\\Microsoft Office\\"
                "root\\Office16\\OUTLOOK.EXE"
            ),
            "CommandLine": (
                'cmd.exe /c "start /b powershell -enc ..."'
            ),
            "SubjectLogonId": "0x3E7",
            "Type": "SecurityEvent",
        },
    ],
    "signin": [
        {
            "TimeGenerated": "2026-03-26T07:52:11Z",
            "UserPrincipalName": "jsmith@acme-corp.com",
            "AppDisplayName": "Azure VPN",
            "IPAddress": "10.1.42.17",
            "Location": "US, Virginia",
            "ResultType": 0,
            "ResultDescription": "Success",
            "ClientAppUsed": (
                "Mobile Apps and Desktop clients"
            ),
            "ConditionalAccessStatus": "success",
            "AuthenticationMethodsUsed": ["MFA Push"],
            "RiskLevelDuringSignIn": "none",
            "Type": "SigninLogs",
        },
        {
            "TimeGenerated": "2026-03-26T07:48:03Z",
            "UserPrincipalName": "jsmith@acme-corp.com",
            "AppDisplayName": "Azure VPN",
            "IPAddress": "185.220.101.42",
            "Location": "DE, Frankfurt",
            "ResultType": 50126,
            "ResultDescription": (
                "Invalid username or password"
            ),
            "ClientAppUsed": "Browser",
            "ConditionalAccessStatus": "failure",
            "AuthenticationMethodsUsed": ["Password"],
            "RiskLevelDuringSignIn": "high",
            "Type": "SigninLogs",
        },
        {
            "TimeGenerated": "2026-03-26T07:47:58Z",
            "UserPrincipalName": "jsmith@acme-corp.com",
            "AppDisplayName": "Azure VPN",
            "IPAddress": "185.220.101.42",
            "Location": "DE, Frankfurt",
            "ResultType": 50126,
            "ResultDescription": (
                "Invalid username or password"
            ),
            "ClientAppUsed": "Browser",
            "ConditionalAccessStatus": "failure",
            "AuthenticationMethodsUsed": ["Password"],
            "RiskLevelDuringSignIn": "high",
            "Type": "SigninLogs",
        },
    ],
    "network": [
        {
            "TimeGenerated": "2026-03-26T08:24:01Z",
            "SourceIP": "10.1.42.17",
            "DestinationIP": "198.51.100.23",
            "DestinationPort": 443,
            "Protocol": "TCP",
            "BytesSent": 154832,
            "BytesReceived": 2048,
            "Action": "Allow",
            "FlowDirection": "Outbound",
            "Computer": "WS-JSMITH-PC",
            "Type": "AzureNetworkAnalytics_CL",
        },
        {
            "TimeGenerated": "2026-03-26T08:23:12Z",
            "SourceIP": "10.1.42.17",
            "DestinationIP": "203.0.113.45",
            "DestinationPort": 8443,
            "Protocol": "TCP",
            "BytesSent": 42561,
            "BytesReceived": 1024,
            "Action": "Allow",
            "FlowDirection": "Outbound",
            "Computer": "WS-JSMITH-PC",
            "Type": "AzureNetworkAnalytics_CL",
        },
    ],
}

_MOCK_INCIDENTS = [
    {
        "incident_id": "inc_sentinel_001",
        "incident_number": 42871,
        "title": (
            "Multi-stage attack involving credential "
            "access and lateral movement"
        ),
        "severity": "High",
        "status": "New",
        "classification": None,
        "classification_reason": None,
        "created_time_utc": "2026-03-26T08:25:00Z",
        "last_modified_time_utc": "2026-03-26T08:25:00Z",
        "first_activity_time_utc": "2026-03-26T07:47:58Z",
        "last_activity_time_utc": "2026-03-26T08:24:01Z",
        "owner": {
            "object_id": None,
            "email": None,
            "assigned_to": "Unassigned",
        },
        "description": (
            "Multiple alerts correlated indicating a potential "
            "multi-stage attack: brute force authentication "
            "attempts from suspicious IP (185.220.101.42), "
            "followed by encoded PowerShell execution and "
            "potential data exfiltration from host WS-JSMITH-PC."
        ),
        "provider_name": "Azure Sentinel",
        "alert_ids": [
            "alrt_sentinel_001",
            "alrt_sentinel_002",
            "alrt_sentinel_003",
        ],
        "tactics": [
            "InitialAccess",
            "Execution",
            "Exfiltration",
        ],
        "related_entities": [
            {
                "kind": "Account",
                "name": "jsmith",
                "upn": "jsmith@acme-corp.com",
            },
            {
                "kind": "Host",
                "name": "WS-JSMITH-PC",
                "os_family": "Windows",
            },
            {"kind": "Ip", "address": "185.220.101.42"},
            {"kind": "Ip", "address": "198.51.100.23"},
        ],
        "labels": [],
    },
    {
        "incident_id": "inc_sentinel_002",
        "incident_number": 42870,
        "title": (
            "Suspicious scheduled task creation on "
            "database server"
        ),
        "severity": "Medium",
        "status": "New",
        "classification": None,
        "classification_reason": None,
        "created_time_utc": "2026-03-26T06:15:00Z",
        "last_modified_time_utc": "2026-03-26T06:15:00Z",
        "first_activity_time_utc": "2026-03-26T06:11:55Z",
        "last_activity_time_utc": "2026-03-26T06:12:00Z",
        "owner": {
            "object_id": None,
            "email": None,
            "assigned_to": "Unassigned",
        },
        "description": (
            "A scheduled task was created on SRV-DB-02 that "
            "executes a binary from ProgramData with an "
            "outbound connection parameter. This may indicate "
            "persistence establishment."
        ),
        "provider_name": "Azure Sentinel",
        "alert_ids": ["alrt_sentinel_004"],
        "tactics": ["Persistence", "CommandAndControl"],
        "related_entities": [
            {
                "kind": "Account",
                "name": "svc_backup",
                "upn": "svc_backup@acme-corp.com",
            },
            {
                "kind": "Host",
                "name": "SRV-DB-02",
                "os_family": "Windows",
            },
            {"kind": "Ip", "address": "198.51.100.23"},
        ],
        "labels": [],
    },
    {
        "incident_id": "inc_sentinel_003",
        "incident_number": 42869,
        "title": "DNS tunnelling activity detected",
        "severity": "Medium",
        "status": "Active",
        "classification": None,
        "classification_reason": None,
        "created_time_utc": "2026-03-26T06:35:00Z",
        "last_modified_time_utc": "2026-03-26T07:00:00Z",
        "first_activity_time_utc": "2026-03-26T06:30:00Z",
        "last_activity_time_utc": "2026-03-26T06:34:00Z",
        "owner": {
            "object_id": None,
            "email": None,
            "assigned_to": "analyst1@acme-corp.com",
        },
        "description": (
            "High-entropy DNS TXT queries observed from "
            "10.1.15.88 to data.evil-c2.example.com, "
            "consistent with DNS tunnelling for data "
            "exfiltration or C2 communication."
        ),
        "provider_name": "Azure Sentinel",
        "alert_ids": ["alrt_sentinel_005"],
        "tactics": ["Exfiltration", "CommandAndControl"],
        "related_entities": [
            {"kind": "Ip", "address": "10.1.15.88"},
            {
                "kind": "DnsResolution",
                "domain_name": "data.evil-c2.example.com",
            },
        ],
        "labels": [
            {"label_name": "DNS", "label_type": "User"},
        ],
    },
]

_MOCK_ALERTS = [
    {
        "alert_id": "alrt_sentinel_001",
        "display_name": (
            "Brute force attack against Azure AD account"
        ),
        "severity": "High",
        "status": "New",
        "time_generated": "2026-03-26T07:50:00Z",
        "alert_type": "BruteForce",
        "provider_name": (
            "Azure Active Directory Identity Protection"
        ),
        "description": (
            "Multiple failed sign-in attempts for "
            "jsmith@acme-corp.com from IP 185.220.101.42 "
            "(Frankfurt, Germany). The IP is associated with "
            "known Tor exit node infrastructure."
        ),
        "tactics": ["InitialAccess"],
        "techniques": ["T1110.001"],
        "entities": [
            {"kind": "Account", "name": "jsmith"},
            {"kind": "Ip", "address": "185.220.101.42"},
        ],
        "extended_properties": {
            "failed_attempts": "12",
            "source_geo": "DE, Frankfurt",
            "is_tor_exit": "true",
        },
    },
    {
        "alert_id": "alrt_sentinel_002",
        "display_name": (
            "Suspicious PowerShell command line detected"
        ),
        "severity": "High",
        "status": "New",
        "time_generated": "2026-03-26T08:22:10Z",
        "alert_type": "SuspiciousPowerShell",
        "provider_name": "Microsoft Defender for Endpoint",
        "description": (
            "Encoded PowerShell execution detected on "
            "WS-JSMITH-PC initiated from cmd.exe, which was "
            "spawned by Outlook. This chain is consistent "
            "with a spear-phishing attack."
        ),
        "tactics": ["Execution"],
        "techniques": ["T1059.001"],
        "entities": [
            {"kind": "Host", "name": "WS-JSMITH-PC"},
            {"kind": "Account", "name": "jsmith"},
            {"kind": "Process", "name": "powershell.exe"},
        ],
        "extended_properties": {
            "parent_process": "cmd.exe",
            "grandparent_process": "outlook.exe",
        },
    },
    {
        "alert_id": "alrt_sentinel_003",
        "display_name": "Anomalous outbound data transfer",
        "severity": "Medium",
        "status": "New",
        "time_generated": "2026-03-26T08:25:00Z",
        "alert_type": "DataExfiltration",
        "provider_name": "Microsoft Cloud App Security",
        "description": (
            "Unusual volume of outbound HTTPS traffic from "
            "WS-JSMITH-PC to 198.51.100.23 (154 MB in 10 "
            "minutes). The destination IP is not in any "
            "known CDN or SaaS provider range."
        ),
        "tactics": ["Exfiltration"],
        "techniques": ["T1041"],
        "entities": [
            {"kind": "Host", "name": "WS-JSMITH-PC"},
            {"kind": "Ip", "address": "198.51.100.23"},
        ],
        "extended_properties": {
            "bytes_sent": "154832000",
            "destination_geo": "Unknown",
        },
    },
    {
        "alert_id": "alrt_sentinel_004",
        "display_name": (
            "Persistence via scheduled task on server"
        ),
        "severity": "Medium",
        "status": "New",
        "time_generated": "2026-03-26T06:12:05Z",
        "alert_type": "ScheduledTaskPersistence",
        "provider_name": "Microsoft Defender for Endpoint",
        "description": (
            "Scheduled task 'SystemHealthCheck' created on "
            "SRV-DB-02 that runs every 15 minutes, executing "
            "a binary from C:\\ProgramData with an outbound "
            "connection parameter to 198.51.100.23:443."
        ),
        "tactics": ["Persistence"],
        "techniques": ["T1053.005"],
        "entities": [
            {"kind": "Host", "name": "SRV-DB-02"},
            {"kind": "Account", "name": "svc_backup"},
        ],
        "extended_properties": {
            "task_name": "SystemHealthCheck",
            "execution_interval": "15 minutes",
        },
    },
    {
        "alert_id": "alrt_sentinel_005",
        "display_name": "DNS tunnelling activity",
        "severity": "Medium",
        "status": "New",
        "time_generated": "2026-03-26T06:32:00Z",
        "alert_type": "DnsTunnelling",
        "provider_name": "Azure Sentinel Analytics",
        "description": (
            "High-entropy DNS TXT record queries detected "
            "from 10.1.15.88 to data.evil-c2.example.com. "
            "Average query length of 187 characters is "
            "consistent with DNS-based data exfiltration."
        ),
        "tactics": ["Exfiltration", "CommandAndControl"],
        "techniques": ["T1048.003", "T1071.004"],
        "entities": [
            {"kind": "Ip", "address": "10.1.15.88"},
            {
                "kind": "DnsResolution",
                "domain_name": "data.evil-c2.example.com",
            },
        ],
        "extended_properties": {
            "avg_query_length": "187",
            "query_count": "342",
        },
    },
]


# ---------------------------------------------------------------------------
# Sentinel MCP server class
# ---------------------------------------------------------------------------
class SentinelMCPServer:
    """Microsoft Sentinel MCP connector with mock and real modes."""

    server_id: str = "sentinel"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = (
            mock_mode if mock_mode is not None else MOCK_MODE
        )

    # ---- tools ----

    async def sentinel_query(
        self,
        kql_query: str,
        timespan: str = "P1D",
    ) -> dict[str, Any]:
        """Execute a KQL query against Microsoft Sentinel.

        Args:
            kql_query: Kusto Query Language query string.
            timespan: ISO 8601 duration (e.g. PT1H, P1D, P7D).

        Returns:
            Query results with columns and rows.
        """
        if self.mock_mode:
            return self._mock_query(kql_query, timespan)
        return self._real_query(kql_query, timespan)

    async def sentinel_get_incidents(
        self,
        status: str = "all",
        severity: str = "all",
    ) -> dict[str, Any]:
        """Retrieve incidents from Microsoft Sentinel.

        Args:
            status: Filter (New|Active|Closed|all).
            severity: Filter (High|Medium|Low|Informational|all).

        Returns:
            Incident payloads with entities and tactics.
        """
        if self.mock_mode:
            return self._mock_get_incidents(status, severity)
        return self._real_get_incidents(status, severity)

    async def sentinel_get_alerts(
        self,
        timespan: str = "P1D",
    ) -> dict[str, Any]:
        """Retrieve security alerts from Microsoft Sentinel.

        Args:
            timespan: ISO 8601 duration for lookback window.

        Returns:
            Alert payloads with entities and MITRE mappings.
        """
        if self.mock_mode:
            return self._mock_get_alerts(timespan)
        return self._real_get_alerts(timespan)

    # ---- mock implementations ----

    def _mock_query(
        self, kql_query: str, timespan: str
    ) -> dict[str, Any]:
        q_lower = kql_query.lower()
        if any(
            k in q_lower
            for k in ("signin", "aad", "authentication")
        ):
            rows = _MOCK_KQL_RESULTS["signin"]
        elif any(
            k in q_lower
            for k in ("network", "flow", "connection")
        ):
            rows = _MOCK_KQL_RESULTS["network"]
        else:
            rows = _MOCK_KQL_RESULTS["default"]

        columns = list(rows[0].keys()) if rows else []
        return {
            "status": "success",
            "query": kql_query,
            "timespan": timespan,
            "columns": columns,
            "rows": rows,
            "result_count": len(rows),
            "execution_time_ms": 2145,
            "is_mock": True,
        }

    def _mock_get_incidents(
        self, status: str, severity: str
    ) -> dict[str, Any]:
        incidents = _MOCK_INCIDENTS
        if status != "all":
            incidents = [
                i for i in incidents if i["status"] == status
            ]
        if severity != "all":
            incidents = [
                i for i in incidents if i["severity"] == severity
            ]
        return {
            "status": "success",
            "total": len(incidents),
            "incidents": incidents,
            "is_mock": True,
        }

    def _mock_get_alerts(self, timespan: str) -> dict[str, Any]:
        return {
            "status": "success",
            "timespan": timespan,
            "total": len(_MOCK_ALERTS),
            "alerts": _MOCK_ALERTS,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_query(
        self, kql_query: str, timespan: str
    ) -> dict[str, Any]:
        raise NotImplementedError(
            "Real Sentinel KQL query not yet implemented"
        )

    def _real_get_incidents(
        self, status: str, severity: str
    ) -> dict[str, Any]:
        raise NotImplementedError(
            "Real Sentinel incidents not yet implemented"
        )

    def _real_get_alerts(self, timespan: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Real Sentinel alerts not yet implemented"
        )

    # ---- tool metadata ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sentinel_query",
                "description": (
                    "Execute a KQL query against Microsoft "
                    "Sentinel. Returns query results with "
                    "columns and rows."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "kql_query": {
                            "type": "string",
                            "description": "KQL query string",
                        },
                        "timespan": {
                            "type": "string",
                            "description": (
                                "ISO 8601 duration "
                                "(e.g. PT1H, P1D)"
                            ),
                            "default": "P1D",
                        },
                    },
                    "required": ["kql_query"],
                },
            },
            {
                "name": "sentinel_get_incidents",
                "description": (
                    "Retrieve incidents from Microsoft Sentinel "
                    "with entities, tactics, and correlation."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": [
                                "New",
                                "Active",
                                "Closed",
                                "all",
                            ],
                            "default": "all",
                        },
                        "severity": {
                            "type": "string",
                            "enum": [
                                "High",
                                "Medium",
                                "Low",
                                "Informational",
                                "all",
                            ],
                            "default": "all",
                        },
                    },
                },
            },
            {
                "name": "sentinel_get_alerts",
                "description": (
                    "Retrieve security alerts from Microsoft "
                    "Sentinel with MITRE ATT&CK mappings and "
                    "entity details."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "timespan": {
                            "type": "string",
                            "description": (
                                "ISO 8601 duration for lookback"
                            ),
                            "default": "P1D",
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = SentinelMCPServer()


@tool
async def sentinel_query(
    kql_query: str,
    timespan: str = "P1D",
) -> dict[str, Any]:
    """Execute a KQL query against Microsoft Sentinel.

    Args:
        kql_query: Kusto Query Language query string.
        timespan: ISO 8601 duration (e.g. PT1H, P1D, P7D).
    """
    return await _server.sentinel_query(kql_query, timespan)


@tool
async def sentinel_get_incidents(
    status: str = "all",
    severity: str = "all",
) -> dict[str, Any]:
    """Retrieve incidents from Microsoft Sentinel.

    Args:
        status: Filter (New, Active, Closed, all).
        severity: Filter (High, Medium, Low, Informational, all).
    """
    return await _server.sentinel_get_incidents(status, severity)


@tool
async def sentinel_get_alerts(
    timespan: str = "P1D",
) -> dict[str, Any]:
    """Retrieve security alerts from Microsoft Sentinel.

    Args:
        timespan: ISO 8601 duration for lookback window.
    """
    return await _server.sentinel_get_alerts(timespan)
