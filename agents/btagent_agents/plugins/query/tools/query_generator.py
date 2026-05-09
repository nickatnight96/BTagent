"""Query generation tool for the Query plugin."""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# Supported platforms and their metadata
# --------------------------------------------------------------------------- #

SUPPORTED_PLATFORMS = {
    "splunk": "Splunk SPL",
    "elastic": "Elastic EQL / KQL",
    "sentinel": "Microsoft Sentinel KQL",
    "crowdstrike": "CrowdStrike Falcon",
}

# --------------------------------------------------------------------------- #
# Query templates organized by platform and intent
# --------------------------------------------------------------------------- #

_SPL_TEMPLATES: dict[str, str] = {
    "ip_search": (
        "index=* earliest=-24h latest=now "
        '(src_ip="{value}" OR dest_ip="{value}") '
        "| stats count by index, sourcetype, src_ip, dest_ip, action "
        "| sort -count"
    ),
    "domain_search": (
        "index=dns OR index=proxy OR index=web earliest=-24h latest=now "
        '(query="{value}" OR url="*{value}*") '
        "| stats count by src_ip, query, answer, action "
        "| sort -count"
    ),
    "hash_search": (
        "index=endpoint earliest=-7d latest=now "
        '(file_hash="{value}" OR sha256="{value}" OR md5="{value}") '
        "| stats count by host, file_name, file_path, process_name "
        "| sort -count"
    ),
    "email_search": (
        "index=email earliest=-24h latest=now "
        '(sender="{value}" OR recipient="{value}") '
        "| stats count by sender, recipient, subject, action "
        "| sort -count"
    ),
    "process_search": (
        "index=endpoint earliest=-24h latest=now "
        'process_name="{value}" '
        "| stats count by host, process_name, parent_process_name, user, cmdline "
        "| sort -count"
    ),
    "auth_failure": (
        "index=auth earliest=-24h latest=now action=failure "
        "| stats count by src_ip, user, dest, app "
        "| where count > 5 "
        "| sort -count"
    ),
    "lateral_movement": (
        "index=endpoint OR index=auth earliest=-24h latest=now "
        "(EventCode=4624 Logon_Type=3 OR EventCode=4648 OR process_name IN "
        '("psexec.exe","wmic.exe","winrm.cmd","powershell.exe")) '
        "| stats count by src_ip, dest, user, process_name "
        "| sort -count"
    ),
    "data_transfer": (
        "index=proxy OR index=firewall earliest=-24h latest=now "
        "| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port "
        "| where total_bytes > 104857600 "
        "| sort -total_bytes "
        "| eval total_mb=round(total_bytes/1048576,2)"
    ),
    "generic": (
        'index=* earliest=-24h latest=now "{value}" '
        "| stats count by index, sourcetype, host "
        "| sort -count"
    ),
}

_KQL_TEMPLATES: dict[str, str] = {
    "ip_search": (
        "union * \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where SourceIP == "{value}" or DestinationIP == "{value}" \n'
        "| summarize Count=count() by Type, SourceIP, DestinationIP, Action \n"
        "| order by Count desc"
    ),
    "domain_search": (
        "DnsEvents \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where Name contains "{value}" \n'
        "| summarize Count=count() by ClientIP, Name, QueryType, IPAddresses \n"
        "| order by Count desc"
    ),
    "hash_search": (
        "DeviceFileEvents \n"
        "| where TimeGenerated > ago(7d) \n"
        '| where SHA256 == "{value}" or MD5 == "{value}" \n'
        "| summarize Count=count() by DeviceName, FileName, FolderPath, "
        "InitiatingProcessFileName \n"
        "| order by Count desc"
    ),
    "email_search": (
        "EmailEvents \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where SenderFromAddress == "{value}" '
        'or RecipientEmailAddress == "{value}" \n'
        "| summarize Count=count() by SenderFromAddress, "
        "RecipientEmailAddress, Subject, DeliveryAction \n"
        "| order by Count desc"
    ),
    "process_search": (
        "DeviceProcessEvents \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where FileName == "{value}" \n'
        "| summarize Count=count() by DeviceName, FileName, "
        "InitiatingProcessFileName, AccountName, ProcessCommandLine \n"
        "| order by Count desc"
    ),
    "auth_failure": (
        "SigninLogs \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where ResultType != "0" \n'
        "| summarize FailureCount=count() by IPAddress, "
        "UserPrincipalName, AppDisplayName, ResultDescription \n"
        "| where FailureCount > 5 \n"
        "| order by FailureCount desc"
    ),
    "lateral_movement": (
        "DeviceLogonEvents \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where LogonType in ("RemoteInteractive", "Network", "NewCredentials") \n'
        "| summarize Count=count() by RemoteIP, DeviceName, "
        "AccountName, LogonType \n"
        "| order by Count desc"
    ),
    "data_transfer": (
        "CommonSecurityLog \n"
        "| where TimeGenerated > ago(24h) \n"
        "| summarize TotalBytes=sum(SentBytes) by SourceIP, "
        "DestinationIP, DestinationPort \n"
        "| where TotalBytes > 104857600 \n"
        "| extend TotalMB = round(TotalBytes / 1048576.0, 2) \n"
        "| order by TotalBytes desc"
    ),
    "generic": (
        "union * \n"
        "| where TimeGenerated > ago(24h) \n"
        '| where * contains "{value}" \n'
        "| summarize Count=count() by Type \n"
        "| order by Count desc"
    ),
}

_EQL_TEMPLATES: dict[str, str] = {
    "ip_search": ('any where source.ip == "{value}" or destination.ip == "{value}"'),
    "domain_search": ('dns where dns.question.name == "{value}"'),
    "hash_search": ('file where file.hash.sha256 == "{value}" or file.hash.md5 == "{value}"'),
    "process_search": ('process where process.name == "{value}"'),
    "auth_failure": ('authentication where event.outcome == "failure"'),
    "lateral_movement": (
        "sequence by host.name with maxspan=5m\n"
        '  [authentication where event.outcome == "success" '
        'and source.ip != "127.0.0.1"]\n'
        "  [process where process.name in "
        '("cmd.exe", "powershell.exe", "wmic.exe")]'
    ),
    "generic": ('any where message : "*{value}*"'),
}

_CS_TEMPLATES: dict[str, str] = {
    "ip_search": (
        "event_simpleName IN (NetworkConnectIP4, DnsRequest) "
        'AND (RemoteAddressIP4="{value}" OR aip="{value}")'
    ),
    "domain_search": ('event_simpleName=DnsRequest AND DomainName="{value}"'),
    "hash_search": (
        'event_simpleName IN (PeFileWritten, NewExecutableRenamed) AND SHA256HashData="{value}"'
    ),
    "process_search": ('event_simpleName=ProcessRollup2 AND FileName="{value}"'),
    "auth_failure": ("event_simpleName=UserLogonFailed2"),
    "generic": ('"{value}"'),
}

_PLATFORM_TEMPLATES: dict[str, dict[str, str]] = {
    "splunk": _SPL_TEMPLATES,
    "elastic": _EQL_TEMPLATES,
    "sentinel": _KQL_TEMPLATES,
    "crowdstrike": _CS_TEMPLATES,
}

# --------------------------------------------------------------------------- #
# Intent detection
# --------------------------------------------------------------------------- #

_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ip_search",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    ("hash_search", re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
    ("email_search", re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    (
        "domain_search",
        re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|net|org|io|ru|cn|xyz|top|info|co|uk|de|gov|edu|onion)\b",
            re.IGNORECASE,
        ),
    ),
]

_KEYWORD_INTENTS: list[tuple[str, list[str]]] = [
    (
        "auth_failure",
        [
            "brute force",
            "failed login",
            "authentication failure",
            "password spray",
            "credential stuff",
            "logon failure",
        ],
    ),
    (
        "lateral_movement",
        [
            "lateral movement",
            "pivot",
            "psexec",
            "remote exec",
            "pass the hash",
            "pass-the-hash",
            "wmi ",
            "winrm",
        ],
    ),
    (
        "data_transfer",
        [
            "exfiltration",
            "data transfer",
            "large upload",
            "bytes transferred",
            "data leak",
        ],
    ),
    (
        "process_search",
        [
            "process",
            "execution",
            "running",
            "spawned",
            "parent process",
        ],
    ),
]

# --------------------------------------------------------------------------- #
# Destructive query patterns to block
# --------------------------------------------------------------------------- #

_DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(delete|drop|truncate|alter|update|insert|modify|remove)\b",
    re.IGNORECASE,
)


def _detect_intent(description: str) -> tuple[str, str]:
    """Detect the query intent and extract a key value from the description.

    Returns (intent, extracted_value).
    """
    # Check regex-based patterns first (IOC-driven).
    for intent, pattern in _INTENT_PATTERNS:
        match = pattern.search(description)
        if match:
            return intent, match.group(0)

    # Check keyword-based intents.
    desc_lower = description.lower()
    for intent, keywords in _KEYWORD_INTENTS:
        if any(kw in desc_lower for kw in keywords):
            return intent, ""

    return "generic", description.strip()[:200]


def _validate_syntax(query: str, platform: str) -> list[str]:
    """Run basic syntax checks on the generated query.

    Returns a list of warnings (empty if OK).
    """
    warnings: list[str] = []

    if _DESTRUCTIVE_PATTERNS.search(query):
        warnings.append(
            "BLOCKED: Query contains potentially destructive operations. "
            "Only read-only queries are permitted."
        )

    if platform == "splunk":
        # Check for unbalanced quotes
        if query.count('"') % 2 != 0:
            warnings.append("Possible unbalanced double quotes in SPL query.")
        # Check for common SPL issues
        if "| eval" in query and "=" not in query.split("| eval")[-1]:
            warnings.append("eval command may be missing assignment operator.")

    if platform == "sentinel":
        # Basic KQL checks
        if query.count('"') % 2 != 0:
            warnings.append("Possible unbalanced double quotes in KQL query.")

    return warnings


def _generate_explanation(intent: str, value: str, platform: str) -> str:
    """Generate a plain-English explanation of what the query does."""
    platform_name = SUPPORTED_PLATFORMS.get(platform, platform)
    explanations: dict[str, str] = {
        "ip_search": (
            f"Searches {platform_name} for all network activity involving "
            f"IP address {value} in the last 24 hours, summarized by source type "
            "and action taken."
        ),
        "domain_search": (
            f"Searches {platform_name} DNS and proxy logs for queries to or "
            f"connections involving the domain '{value}' in the last 24 hours."
        ),
        "hash_search": (
            f"Searches {platform_name} endpoint logs for any file matching "
            f"hash {value[:16]}... over the last 7 days, grouped by host "
            "and file path."
        ),
        "email_search": (
            f"Searches {platform_name} email logs for messages sent by or "
            f"received by {value} in the last 24 hours."
        ),
        "process_search": (
            f"Searches {platform_name} endpoint telemetry for process "
            f"executions matching '{value}', grouped by host and user."
        ),
        "auth_failure": (
            f"Searches {platform_name} authentication logs for failed login "
            "attempts exceeding 5 failures per source in the last 24 hours."
        ),
        "lateral_movement": (
            f"Searches {platform_name} for indicators of lateral movement "
            "including remote logons and suspicious process execution "
            "in the last 24 hours."
        ),
        "data_transfer": (
            f"Searches {platform_name} network logs for outbound data "
            "transfers exceeding 100 MB in the last 24 hours, sorted by volume."
        ),
        "generic": (
            f"Performs a broad search across {platform_name} for the specified "
            "terms in the last 24 hours, grouped by data source."
        ),
    }
    return explanations.get(intent, f"Custom query against {platform_name}.")


@tool
def query_generator(
    description: str,
    platform: str = "splunk",
) -> dict[str, Any]:
    """Generate a SIEM/EDR query from a natural-language description.

    Translates an investigation question or search requirement into a
    platform-specific query with a plain-English explanation. Supports
    Splunk SPL, Elastic EQL/KQL, Microsoft Sentinel KQL, and CrowdStrike
    Falcon query syntax.

    Args:
        description: Natural-language description of what to search for.
            Can include IOCs (IPs, domains, hashes, emails) which will be
            automatically detected and embedded in the query.
        platform: Target platform — one of 'splunk', 'elastic', 'sentinel',
            or 'crowdstrike'. Defaults to 'splunk'.
    """
    platform = platform.lower().strip()
    if platform not in SUPPORTED_PLATFORMS:
        return {
            "error": (
                f"Unsupported platform '{platform}'. "
                f"Supported: {', '.join(SUPPORTED_PLATFORMS.keys())}"
            ),
        }

    intent, value = _detect_intent(description)
    templates = _PLATFORM_TEMPLATES[platform]

    # Fall back to generic if the intent doesn't have a template for this platform.
    template = templates.get(intent, templates.get("generic", '"{value}"'))
    query = template.format(value=value) if value else template

    warnings = _validate_syntax(query, platform)
    if any("BLOCKED" in w for w in warnings):
        return {
            "error": "Query generation blocked due to safety violation.",
            "warnings": warnings,
        }

    explanation = _generate_explanation(intent, value, platform)

    return {
        "query": query,
        "platform": platform,
        "platform_name": SUPPORTED_PLATFORMS[platform],
        "intent": intent,
        "explanation": explanation,
        "time_range": "Last 24 hours (default)" if "7d" not in query else "Last 7 days",
        "warnings": warnings,
        "suggestions": [
            "Adjust time range if no results are found.",
            "Add field-specific filters to narrow results.",
            "Consider running follow-up queries for related IOCs.",
        ],
    }
