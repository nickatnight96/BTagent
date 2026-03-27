"""Splunk MCP server connector.

Tools:
- splunk_search(query, earliest, latest)
- splunk_get_alerts(limit)
- splunk_get_notable(severity)

Mock mode returns realistic sample data (SPL queries, alert payloads,
notable events). Real mode is a placeholder for the Splunk REST API.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.splunk")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_SEARCH_RESULTS: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "_time": "2026-03-26T08:14:22.000+00:00",
            "src_ip": "10.1.42.17",
            "dest_ip": "198.51.100.23",
            "dest_port": 443,
            "action": "allowed",
            "app": "ssl",
            "bytes_out": 154_832,
            "user": "jsmith",
            "host": "fw-edge-01",
            "sourcetype": "palo_alto:traffic",
            "index": "network",
        },
        {
            "_time": "2026-03-26T08:14:19.000+00:00",
            "src_ip": "10.1.42.17",
            "dest_ip": "203.0.113.45",
            "dest_port": 8443,
            "action": "allowed",
            "app": "web-browsing",
            "bytes_out": 42_561,
            "user": "jsmith",
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
            "app": "dns",
            "bytes_out": 128,
            "user": "jsmith",
            "host": "fw-edge-01",
            "sourcetype": "palo_alto:traffic",
            "index": "network",
        },
    ],
    "authentication": [
        {
            "_time": "2026-03-26T07:52:11.000+00:00",
            "src_ip": "10.1.42.17",
            "user": "jsmith",
            "action": "success",
            "app": "Okta",
            "dest": "vpn.acme-corp.com",
            "authentication_method": "MFA_PUSH",
            "src_geo": "US, Virginia",
            "host": "idp-prod-01",
            "sourcetype": "okta:log",
            "index": "authentication",
        },
        {
            "_time": "2026-03-26T07:48:03.000+00:00",
            "src_ip": "185.220.101.42",
            "user": "jsmith",
            "action": "failure",
            "app": "Okta",
            "dest": "vpn.acme-corp.com",
            "authentication_method": "PASSWORD",
            "src_geo": "DE, Frankfurt",
            "reason": "INVALID_CREDENTIALS",
            "host": "idp-prod-01",
            "sourcetype": "okta:log",
            "index": "authentication",
        },
        {
            "_time": "2026-03-26T07:47:58.000+00:00",
            "src_ip": "185.220.101.42",
            "user": "jsmith",
            "action": "failure",
            "app": "Okta",
            "dest": "vpn.acme-corp.com",
            "authentication_method": "PASSWORD",
            "src_geo": "DE, Frankfurt",
            "reason": "INVALID_CREDENTIALS",
            "host": "idp-prod-01",
            "sourcetype": "okta:log",
            "index": "authentication",
        },
    ],
    "process": [
        {
            "_time": "2026-03-26T08:22:05.000+00:00",
            "host": "WS-JSMITH-PC",
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_process": "cmd.exe",
            "cmdline": "powershell.exe -enc SQBFAFgAIAAoA"
                       "E4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "user": "ACME\\jsmith",
            "pid": 7284,
            "ppid": 6140,
            "dest": "WS-JSMITH-PC",
            "sourcetype": "sysmon:process_create",
            "index": "endpoint",
        },
        {
            "_time": "2026-03-26T08:22:01.000+00:00",
            "host": "WS-JSMITH-PC",
            "process_name": "cmd.exe",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "parent_process": "outlook.exe",
            "cmdline": 'cmd.exe /c "start /b powershell -enc ..."',
            "user": "ACME\\jsmith",
            "pid": 6140,
            "ppid": 4512,
            "dest": "WS-JSMITH-PC",
            "sourcetype": "sysmon:process_create",
            "index": "endpoint",
        },
    ],
}

_MOCK_ALERTS = [
    {
        "alert_id": "ALR-2026032601",
        "title": "Brute Force Authentication - Multiple Failed Logins",
        "severity": "high",
        "triggered_at": "2026-03-26T07:50:00.000+00:00",
        "search_name": "Authentication - Brute Force Detection",
        "search_query": (
            'index=authentication action=failure '
            '| stats count by src_ip, user '
            '| where count > 5'
        ),
        "notable_fields": {
            "src_ip": "185.220.101.42",
            "user": "jsmith",
            "failure_count": 12,
        },
        "status": "new",
        "owner": "unassigned",
        "app": "SplunkEnterpriseSecuritySuite",
    },
    {
        "alert_id": "ALR-2026032602",
        "title": "Suspicious PowerShell - Encoded Command Execution",
        "severity": "critical",
        "triggered_at": "2026-03-26T08:22:10.000+00:00",
        "search_name": "Endpoint - Encoded PowerShell Detection",
        "search_query": (
            'index=endpoint sourcetype="sysmon:process_create" '
            'process_name=powershell.exe cmdline="*-enc*" '
            '| table _time, host, user, cmdline, parent_process'
        ),
        "notable_fields": {
            "host": "WS-JSMITH-PC",
            "user": "ACME\\jsmith",
            "parent_process": "cmd.exe",
        },
        "status": "new",
        "owner": "unassigned",
        "app": "SplunkEnterpriseSecuritySuite",
    },
    {
        "alert_id": "ALR-2026032603",
        "title": "Data Exfiltration - High Outbound Data Transfer",
        "severity": "high",
        "triggered_at": "2026-03-26T08:18:00.000+00:00",
        "search_name": "Network - Large Outbound Transfer",
        "search_query": (
            'index=network action=allowed direction=outbound '
            '| stats sum(bytes_out) as total_bytes by src_ip '
            '| where total_bytes > 50000000'
        ),
        "notable_fields": {
            "src_ip": "10.1.42.17",
            "total_bytes": 154_832_000,
            "dest_count": 3,
        },
        "status": "new",
        "owner": "unassigned",
        "app": "SplunkEnterpriseSecuritySuite",
    },
    {
        "alert_id": "ALR-2026032604",
        "title": "DNS Tunnelling Detected",
        "severity": "medium",
        "triggered_at": "2026-03-26T06:30:00.000+00:00",
        "search_name": "Network - DNS Tunnel Detection",
        "search_query": (
            'index=network sourcetype=dns query_type=TXT '
            '| eval query_len=len(query) '
            '| where query_len > 100'
        ),
        "notable_fields": {
            "src_ip": "10.1.15.88",
            "domain": "data.evil-c2.example.com",
            "avg_query_len": 187,
        },
        "status": "new",
        "owner": "unassigned",
        "app": "SplunkEnterpriseSecuritySuite",
    },
]

_MOCK_NOTABLES = [
    {
        "event_id": "NTB-2026032601",
        "rule_name": "Brute Force Access Behavior Detected",
        "severity": "high",
        "urgency": "high",
        "time": "2026-03-26T07:50:00.000+00:00",
        "src": "185.220.101.42",
        "dest": "vpn.acme-corp.com",
        "user": "jsmith",
        "status": "1",  # New
        "status_label": "New",
        "owner": "unassigned",
        "security_domain": "access",
        "drilldown_search": (
            'index=authentication src_ip=185.220.101.42 user=jsmith action=failure'
        ),
    },
    {
        "event_id": "NTB-2026032602",
        "rule_name": "Suspicious Process - Encoded PowerShell",
        "severity": "critical",
        "urgency": "critical",
        "time": "2026-03-26T08:22:10.000+00:00",
        "src": "WS-JSMITH-PC",
        "dest": "WS-JSMITH-PC",
        "user": "ACME\\jsmith",
        "status": "1",
        "status_label": "New",
        "owner": "unassigned",
        "security_domain": "endpoint",
        "drilldown_search": (
            'index=endpoint sourcetype="sysmon:process_create" '
            'host=WS-JSMITH-PC process_name=powershell.exe'
        ),
    },
    {
        "event_id": "NTB-2026032603",
        "rule_name": "Potential Data Exfiltration via HTTPS",
        "severity": "high",
        "urgency": "high",
        "time": "2026-03-26T08:18:00.000+00:00",
        "src": "10.1.42.17",
        "dest": "198.51.100.23",
        "user": "jsmith",
        "status": "1",
        "status_label": "New",
        "owner": "unassigned",
        "security_domain": "network",
        "drilldown_search": (
            'index=network src_ip=10.1.42.17 dest_ip=198.51.100.23 action=allowed'
        ),
    },
    {
        "event_id": "NTB-2026032604",
        "rule_name": "DNS Exfiltration Attempt",
        "severity": "medium",
        "urgency": "medium",
        "time": "2026-03-26T06:30:00.000+00:00",
        "src": "10.1.15.88",
        "dest": "data.evil-c2.example.com",
        "user": "unknown",
        "status": "1",
        "status_label": "New",
        "owner": "unassigned",
        "security_domain": "network",
        "drilldown_search": (
            'index=network sourcetype=dns query_type=TXT src_ip=10.1.15.88'
        ),
    },
]


# ---------------------------------------------------------------------------
# Splunk MCP server class
# ---------------------------------------------------------------------------
class SplunkMCPServer:
    """Splunk MCP connector with mock and real modes.

    In mock mode (default, controlled by ``BTAGENT_MOCK_CONNECTORS``),
    every tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "splunk"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def splunk_search(
        self,
        query: str,
        earliest: str = "-24h",
        latest: str = "now",
    ) -> dict[str, Any]:
        """Execute an SPL search query against Splunk.

        Args:
            query: SPL search string.
            earliest: Start of time range (e.g. ``-24h``, ``2026-03-25``).
            latest: End of time range (e.g. ``now``, ``2026-03-26``).

        Returns:
            Search results including events, statistics, and metadata.
        """
        if self.mock_mode:
            return self._mock_search(query, earliest, latest)
        return self._real_search(query, earliest, latest)

    async def splunk_get_alerts(
        self,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve recent triggered alerts from Splunk ES.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of alert payloads with metadata.
        """
        if self.mock_mode:
            return self._mock_get_alerts(limit)
        return self._real_get_alerts(limit)

    async def splunk_get_notable(
        self,
        severity: str = "all",
    ) -> dict[str, Any]:
        """Retrieve notable events from Splunk Enterprise Security.

        Args:
            severity: Filter by severity (critical, high, medium, low, all).

        Returns:
            List of notable event payloads.
        """
        if self.mock_mode:
            return self._mock_get_notable(severity)
        return self._real_get_notable(severity)

    # ---- mock implementations ----

    def _mock_search(
        self, query: str, earliest: str, latest: str
    ) -> dict[str, Any]:
        q_lower = query.lower()
        if "authentication" in q_lower or "okta" in q_lower or "login" in q_lower:
            events = _MOCK_SEARCH_RESULTS["authentication"]
        elif "process" in q_lower or "sysmon" in q_lower or "powershell" in q_lower:
            events = _MOCK_SEARCH_RESULTS["process"]
        else:
            events = _MOCK_SEARCH_RESULTS["default"]

        return {
            "status": "success",
            "search_id": "mock_sid_1711425600",
            "query": query,
            "earliest": earliest,
            "latest": latest,
            "result_count": len(events),
            "events": events,
            "execution_time_ms": 1842,
            "is_mock": True,
        }

    def _mock_get_alerts(self, limit: int) -> dict[str, Any]:
        alerts = _MOCK_ALERTS[:limit]
        return {
            "status": "success",
            "total": len(alerts),
            "alerts": alerts,
            "is_mock": True,
        }

    def _mock_get_notable(self, severity: str) -> dict[str, Any]:
        if severity == "all":
            notables = _MOCK_NOTABLES
        else:
            notables = [
                n for n in _MOCK_NOTABLES
                if n["severity"] == severity.lower()
            ]
        return {
            "status": "success",
            "total": len(notables),
            "notables": notables,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_search(
        self, query: str, earliest: str, latest: str
    ) -> dict[str, Any]:
        # TODO: Implement via Splunk REST API (services/search/jobs)
        raise NotImplementedError("Real Splunk search not yet implemented")

    def _real_get_alerts(self, limit: int) -> dict[str, Any]:
        raise NotImplementedError("Real Splunk alerts not yet implemented")

    def _real_get_notable(self, severity: str) -> dict[str, Any]:
        raise NotImplementedError("Real Splunk notables not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery without loading implementations."""
        return [
            {
                "name": "splunk_search",
                "description": (
                    "Execute an SPL search query against Splunk. "
                    "Returns matching events, statistics, and metadata."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "SPL search string",
                        },
                        "earliest": {
                            "type": "string",
                            "description": "Start of time range",
                            "default": "-24h",
                        },
                        "latest": {
                            "type": "string",
                            "description": "End of time range",
                            "default": "now",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "splunk_get_alerts",
                "description": (
                    "Retrieve recent triggered alerts from Splunk "
                    "Enterprise Security."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum alerts to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "splunk_get_notable",
                "description": (
                    "Retrieve notable events from Splunk Enterprise Security, "
                    "optionally filtered by severity."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": [
                                "critical",
                                "high",
                                "medium",
                                "low",
                                "all",
                            ],
                            "description": "Filter by severity",
                            "default": "all",
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = SplunkMCPServer()


@tool
async def splunk_search(
    query: str,
    earliest: str = "-24h",
    latest: str = "now",
) -> dict[str, Any]:
    """Execute an SPL search query against Splunk.

    Args:
        query: SPL search string.
        earliest: Start of time range (e.g. -24h, 2026-03-25).
        latest: End of time range (e.g. now, 2026-03-26).
    """
    return await _server.splunk_search(query, earliest, latest)


@tool
async def splunk_get_alerts(limit: int = 50) -> dict[str, Any]:
    """Retrieve recent triggered alerts from Splunk Enterprise Security.

    Args:
        limit: Maximum number of alerts to return.
    """
    return await _server.splunk_get_alerts(limit)


@tool
async def splunk_get_notable(severity: str = "all") -> dict[str, Any]:
    """Retrieve notable events from Splunk ES filtered by severity.

    Args:
        severity: Filter by severity (critical, high, medium, low, all).
    """
    return await _server.splunk_get_notable(severity)
