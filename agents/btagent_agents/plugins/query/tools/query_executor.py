"""Query execution tool for the Query plugin."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# Destructive-query safety check
# --------------------------------------------------------------------------- #

_DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(delete|drop|truncate|alter|update|insert|modify|remove)\b",
    re.IGNORECASE,
)

SUPPORTED_PLATFORMS = {"splunk", "elastic", "sentinel", "crowdstrike"}

# --------------------------------------------------------------------------- #
# Mock result generators for development and testing
# --------------------------------------------------------------------------- #


def _deterministic_ip(seed: str, index: int) -> str:
    """Generate a deterministic IP address from a seed string."""
    h = hashlib.md5(f"{seed}:{index}".encode()).hexdigest()  # noqa: S324
    octets = [int(h[i : i + 2], 16) for i in range(0, 8, 2)]
    # Avoid reserved ranges
    octets[0] = max(10, min(223, octets[0]))
    return ".".join(str(o) for o in octets)


def _mock_splunk_results(query: str) -> dict[str, Any]:
    """Generate realistic mock Splunk search results."""
    seed = query[:50]
    now = datetime.now(timezone.utc)

    return {
        "results": [
            {
                "_time": (now.isoformat()),
                "host": f"srv-web-{i:02d}",
                "sourcetype": "syslog" if i % 2 == 0 else "WinEventLog",
                "src_ip": _deterministic_ip(seed, i),
                "dest_ip": _deterministic_ip(seed, i + 100),
                "action": "allowed" if i % 3 != 0 else "blocked",
                "count": (i + 1) * 12,
            }
            for i in range(5)
        ],
        "result_count": 5,
        "search_time_seconds": 2.3,
        "earliest": (now.isoformat()),
        "latest": (now.isoformat()),
    }


def _mock_sentinel_results(query: str) -> dict[str, Any]:
    """Generate realistic mock Sentinel/KQL results."""
    seed = query[:50]
    now = datetime.now(timezone.utc)

    return {
        "results": [
            {
                "TimeGenerated": now.isoformat(),
                "Type": ["SigninLogs", "SecurityEvent", "CommonSecurityLog"][i % 3],
                "SourceIP": _deterministic_ip(seed, i),
                "DestinationIP": _deterministic_ip(seed, i + 100),
                "Action": "Success" if i % 2 == 0 else "Failure",
                "Count": (i + 1) * 8,
            }
            for i in range(5)
        ],
        "result_count": 5,
        "execution_time_ms": 1450,
    }


def _mock_elastic_results(query: str) -> dict[str, Any]:
    """Generate realistic mock Elastic results."""
    seed = query[:50]
    now = datetime.now(timezone.utc)

    return {
        "hits": {
            "total": {"value": 5, "relation": "eq"},
            "hits": [
                {
                    "_index": f"logs-endpoint-{i}",
                    "_source": {
                        "@timestamp": now.isoformat(),
                        "host": {"name": f"workstation-{i:03d}"},
                        "source": {"ip": _deterministic_ip(seed, i)},
                        "destination": {"ip": _deterministic_ip(seed, i + 100)},
                        "event": {
                            "action": "connection_attempted",
                            "outcome": "success" if i % 2 == 0 else "failure",
                        },
                    },
                }
                for i in range(5)
            ],
        },
        "took": 87,
    }


def _mock_crowdstrike_results(query: str) -> dict[str, Any]:
    """Generate realistic mock CrowdStrike Falcon results."""
    seed = query[:50]
    now = datetime.now(timezone.utc)

    return {
        "results": [
            {
                "timestamp": now.isoformat(),
                "aid": f"abc{i:04d}def",
                "ComputerName": f"DESKTOP-{i:04X}",
                "event_simpleName": [
                    "ProcessRollup2", "NetworkConnectIP4", "DnsRequest"
                ][i % 3],
                "RemoteAddressIP4": _deterministic_ip(seed, i),
                "FileName": ["svchost.exe", "powershell.exe", "cmd.exe"][i % 3],
            }
            for i in range(5)
        ],
        "result_count": 5,
        "query_time_ms": 620,
    }


_MOCK_GENERATORS: dict[str, Any] = {
    "splunk": _mock_splunk_results,
    "sentinel": _mock_sentinel_results,
    "elastic": _mock_elastic_results,
    "crowdstrike": _mock_crowdstrike_results,
}


@tool
def query_executor(
    query: str,
    platform: str = "splunk",
    mock_mode: bool = True,
) -> dict[str, Any]:
    """Execute a SIEM/EDR query and return results.

    In mock mode (default), returns realistic sample results for development
    and testing. In real mode, acts as a placeholder for MCP connector calls
    to the actual SIEM/EDR platform.

    Args:
        query: The query string to execute (SPL, KQL, EQL, or CrowdStrike
            syntax depending on the target platform).
        platform: Target platform — one of 'splunk', 'elastic', 'sentinel',
            or 'crowdstrike'. Defaults to 'splunk'.
        mock_mode: When True (default), return simulated results. When False,
            attempt to execute via MCP connector (placeholder).
    """
    platform = platform.lower().strip()
    if platform not in SUPPORTED_PLATFORMS:
        return {
            "error": (
                f"Unsupported platform '{platform}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_PLATFORMS))}"
            ),
        }

    # Safety check: block destructive queries regardless of mode.
    if _DESTRUCTIVE_PATTERNS.search(query):
        return {
            "error": (
                "Query execution BLOCKED: potentially destructive operation detected. "
                "Only read-only queries are permitted."
            ),
            "blocked_query": query,
        }

    if mock_mode:
        generator = _MOCK_GENERATORS[platform]
        results = generator(query)
        return {
            "status": "success",
            "mode": "mock",
            "platform": platform,
            "query": query,
            "data": results,
            "note": (
                "These are simulated results for development/testing. "
                "Set mock_mode=False and configure the MCP connector for "
                "real query execution."
            ),
        }

    # Real mode: placeholder for MCP connector integration.
    # In production, this will call the appropriate MCP server:
    #   - splunk  → mcp-splunk server
    #   - elastic → mcp-elastic server
    #   - sentinel → mcp-sentinel server
    #   - crowdstrike → mcp-crowdstrike server
    return {
        "status": "error",
        "mode": "real",
        "platform": platform,
        "query": query,
        "error": (
            f"Real-mode execution for '{platform}' is not yet configured. "
            "Please ensure the appropriate MCP connector is set up in the "
            "agent configuration."
        ),
        "setup_hint": (
            f"Add an MCPConnection for '{platform}' to the AgentConfig "
            "mcp_connections list."
        ),
    }
