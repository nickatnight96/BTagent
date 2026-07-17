"""Recorded Palo Alto Cortex XDR fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Cortex XDR API surfaces the live connector will call:

- ``CORTEX_FIXTURE_INCIDENTS`` — ``/incidents/get_incidents``-style incident
  objects (severity / status / host / MITRE mapping, alert count).
- ``CORTEX_FIXTURE_ENDPOINTS`` — ``/endpoints/get_endpoint``-style records
  keyed by ``endpoint_name`` (connection + isolation status, OS, last-seen).
- ``CORTEX_FIXTURE_XQL_EVENTS`` — XQL (Cortex Query Language) result rows (one
  stream, typed by ``event_type``: ``PROCESS`` / ``NETWORK`` / ``DNS``), the
  XQL mock's data source.

The fixtures tell one coherent hands-on-keyboard story on ``WIN10-FIN-07``:

* An encoded-command ``powershell.exe`` (spawned from ``winword.exe`` — a
  macro-borne loader) writes and runs ``updater.exe``, still **new /
  unresolved** — the triage-priority incident.
* ``updater.exe`` resolves and beacons to ``cdn-sync.example.io``
  (45.77.10.204:443) at a fixed cadence (C2), mapping to T1059.001 / T1071.
* ``SRV-DB-11`` carries an older ``informational`` incident already resolved
  as a false positive — the noise-floor comparison.

Join keys: ``endpoint_id`` ties incidents ↔ endpoints ↔ XQL rows;
``endpoint_name`` / ``host_name`` carries the human-readable device name on
every surface.
"""

from __future__ import annotations

from typing import Any

C2_IP = "45.77.10.204"

CORTEX_FIXTURE_INCIDENTS: list[dict[str, Any]] = [
    {
        "incident_id": "INC-4821",
        "incident_name": "Encoded PowerShell loader with outbound C2 beacon",
        "severity": "high",
        "status": "new",
        "resolution_status": "STATUS_010_NEW",
        "creation_time": "2026-07-02T08:14:20Z",
        "modification_time": "2026-07-02T08:20:00Z",
        "host_name": "WIN10-FIN-07",
        "endpoint_id": "ep-1101",
        "assigned_user": None,
        "alert_count": 4,
        "mitre_tactics": ["Execution", "Command-And-Control"],
        "mitre_techniques": ["T1059.001", "T1071.001"],
        "description": (
            "winword.exe spawned an encoded powershell.exe that dropped "
            "updater.exe; the process beacons to cdn-sync.example.io."
        ),
    },
    {
        "incident_id": "INC-4655",
        "incident_name": "Port scan from internal host",
        "severity": "informational",
        "status": "resolved",
        "resolution_status": "STATUS_070_RESOLVED_FALSE_POSITIVE",
        "creation_time": "2026-06-28T13:00:00Z",
        "modification_time": "2026-06-28T15:42:00Z",
        "host_name": "SRV-DB-11",
        "endpoint_id": "ep-2202",
        "assigned_user": "soc-analyst@example.com",
        "alert_count": 1,
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1046"],
        "description": "Vulnerability scanner sweep; confirmed authorised.",
    },
]


CORTEX_FIXTURE_ENDPOINTS: dict[str, dict[str, Any]] = {
    "WIN10-FIN-07": {
        "endpoint_id": "ep-1101",
        "endpoint_name": "WIN10-FIN-07",
        "endpoint_type": "AGENT_TYPE_SECONDARY",
        "endpoint_status": "CONNECTED",
        "is_isolated": "AGENT_UNISOLATED",
        "os_type": "AGENT_OS_WINDOWS",
        "os_version": "Windows 10 Enterprise 22H2",
        "ip": ["10.12.4.71"],
        "public_ip": "203.0.113.88",
        "users": ["ACME\\jvega"],
        "domain": "ACME",
        "last_seen": "2026-07-02T08:19:40Z",
        "install_date": "2025-11-03T09:00:00Z",
        "content_version": "890-104233",
        "group_name": "Finance-Workstations",
    },
    "SRV-DB-11": {
        "endpoint_id": "ep-2202",
        "endpoint_name": "SRV-DB-11",
        "endpoint_type": "AGENT_TYPE_SERVER",
        "endpoint_status": "CONNECTED",
        "is_isolated": "AGENT_UNISOLATED",
        "os_type": "AGENT_OS_WINDOWS",
        "os_version": "Windows Server 2022",
        "ip": ["10.20.0.11"],
        "public_ip": "203.0.113.89",
        "users": ["ACME\\svc-sql"],
        "domain": "ACME",
        "last_seen": "2026-07-02T08:18:00Z",
        "install_date": "2024-09-14T08:30:00Z",
        "content_version": "890-104233",
        "group_name": "Database-Servers",
    },
}


CORTEX_FIXTURE_XQL_EVENTS: list[dict[str, Any]] = [
    {
        "event_type": "PROCESS",
        "event_time": "2026-07-02T08:13:50Z",
        "endpoint_id": "ep-1101",
        "endpoint_name": "WIN10-FIN-07",
        "actor_effective_username": "ACME\\jvega",
        "action_process_image_name": "powershell.exe",
        "action_process_image_command_line": (
            "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A"
        ),
        "causality_actor_process_image_name": "winword.exe",
        "action_process_image_sha256": (
            "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
        ),
    },
    {
        "event_type": "PROCESS",
        "event_time": "2026-07-02T08:14:05Z",
        "endpoint_id": "ep-1101",
        "endpoint_name": "WIN10-FIN-07",
        "actor_effective_username": "ACME\\jvega",
        "action_process_image_name": "updater.exe",
        "action_process_image_command_line": "C:\\Users\\jvega\\AppData\\Roaming\\updater.exe",
        "causality_actor_process_image_name": "powershell.exe",
        "action_process_image_sha256": (
            "ff00eeddccbbaa998877665544332211009f8e7d6c5b4a39281706f5e4d3c2b1"
        ),
    },
    {
        "event_type": "DNS",
        "event_time": "2026-07-02T08:14:12Z",
        "endpoint_id": "ep-1101",
        "endpoint_name": "WIN10-FIN-07",
        "actor_effective_username": "ACME\\jvega",
        "action_process_image_name": "updater.exe",
        "dns_query_name": "cdn-sync.example.io",
        "dns_response_ip": C2_IP,
    },
    {
        "event_type": "NETWORK",
        "event_time": "2026-07-02T08:14:15Z",
        "endpoint_id": "ep-1101",
        "endpoint_name": "WIN10-FIN-07",
        "actor_effective_username": "ACME\\jvega",
        "action_process_image_name": "updater.exe",
        "action_remote_ip": C2_IP,
        "action_remote_port": 443,
        "action_local_ip": "10.12.4.71",
        "action_local_port": 51884,
    },
    {
        "event_type": "PROCESS",
        "event_time": "2026-07-02T06:00:00Z",
        "endpoint_id": "ep-2202",
        "endpoint_name": "SRV-DB-11",
        "actor_effective_username": "ACME\\svc-sql",
        "action_process_image_name": "sqlservr.exe",
        "action_process_image_command_line": "sqlservr.exe -s MSSQLSERVER",
        "causality_actor_process_image_name": "services.exe",
        "action_process_image_sha256": (
            "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
        ),
    },
]
