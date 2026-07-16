"""Recorded SentinelOne fixtures for mock-mode responses (#100).

Shapes mirror the Management API surfaces the live connector will call:

- ``S1_FIXTURE_THREATS`` — ``/threats``-style threat objects
  (``threatInfo`` with confidence / incident / mitigation lifecycles,
  ``agentRealtimeInfo`` for the device join).
- ``S1_FIXTURE_AGENTS`` — ``/agents``-style agent records keyed by
  ``computerName`` (network status, infected flag, versions).
- ``S1_FIXTURE_DV_EVENTS`` — Deep Visibility event rows (one stream, typed
  by ``eventType``: ``Process Creation`` / ``IP Connect`` / ``DNS``), the
  S1QL mock's data source.

The fixtures tell one coherent ransomware-precursor story on
``LAPTOP-DESIGN-03``:

* ``pennysvc.exe`` (malicious, ransomware classification) runs from a user
  temp dir, still **not mitigated** — the triage-priority threat.
* It deletes volume shadow copies via ``vssadmin`` (T1490), resolves and
  beacons to ``lockpay.example.net`` (198.51.100.99:443).
* An older PUA threat on ``SRV-BUILD-02`` was already mitigated (killed)
  and resolved as false positive — the noise-floor comparison.

Join keys: ``agentRealtimeInfo.agentId`` / ``agentId`` ties threats ↔
agents ↔ Deep Visibility rows; ``computerName``/``endpointName`` carries the
human-readable device name on every surface.
"""

from __future__ import annotations

from typing import Any

S1_FIXTURE_THREATS: list[dict[str, Any]] = [
    {
        "id": "1400000000000000001",
        "threatInfo": {
            "threatName": "pennysvc.exe",
            "classification": "Ransomware",
            "confidenceLevel": "malicious",
            "analystVerdict": "undefined",
            "incidentStatus": "unresolved",
            "mitigationStatus": "not_mitigated",
            "initiatedBy": "agent_policy",
            "createdAt": "2026-06-15T14:02:11Z",
            "identifiedAt": "2026-06-15T14:02:09Z",
            "sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "filePath": "C:\\Users\\dkim\\AppData\\Local\\Temp\\pennysvc.exe",
            "processUser": "ACME\\dkim",
            "mitreTactics": ["Impact"],
            "mitreTechniques": ["T1486", "T1490"],
        },
        "agentRealtimeInfo": {
            "agentId": "1200000000000000101",
            "agentComputerName": "LAPTOP-DESIGN-03",
            "agentOsType": "windows",
            "agentVersion": "23.4.2.14",
            "agentIsActive": True,
        },
    },
    {
        "id": "1400000000000000002",
        "threatInfo": {
            "threatName": "toolbar_installer.exe",
            "classification": "PUA",
            "confidenceLevel": "suspicious",
            "analystVerdict": "false_positive",
            "incidentStatus": "resolved",
            "mitigationStatus": "mitigated",
            "initiatedBy": "agent_policy",
            "createdAt": "2026-06-12T09:15:00Z",
            "identifiedAt": "2026-06-12T09:14:58Z",
            "sha256": "c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8",
            "filePath": "C:\\Users\\builder\\Downloads\\toolbar_installer.exe",
            "processUser": "ACME\\builder",
            "mitreTactics": [],
            "mitreTechniques": [],
        },
        "agentRealtimeInfo": {
            "agentId": "1200000000000000102",
            "agentComputerName": "SRV-BUILD-02",
            "agentOsType": "windows",
            "agentVersion": "23.4.2.14",
            "agentIsActive": True,
        },
    },
]


S1_FIXTURE_AGENTS: dict[str, dict[str, Any]] = {
    "LAPTOP-DESIGN-03": {
        "id": "1200000000000000101",
        "computerName": "LAPTOP-DESIGN-03",
        "osName": "Windows 11 Pro",
        "osType": "windows",
        "agentVersion": "23.4.2.14",
        "isActive": True,
        "infected": True,
        "networkStatus": "connected",
        "lastActiveDate": "2026-06-15T14:10:00Z",
        "registeredAt": "2025-10-20T11:00:00Z",
        "externalIp": "203.0.113.120",
        "lastIpToMgmt": "10.5.2.33",
        "domain": "ACME",
        "lastLoggedInUserName": "dkim",
        "groupName": "Workstations",
        "siteName": "US-East",
        "mitigationMode": "protect",
    },
    "SRV-BUILD-02": {
        "id": "1200000000000000102",
        "computerName": "SRV-BUILD-02",
        "osName": "Windows Server 2022",
        "osType": "windows",
        "agentVersion": "23.4.2.14",
        "isActive": True,
        "infected": False,
        "networkStatus": "connected",
        "lastActiveDate": "2026-06-15T14:09:00Z",
        "registeredAt": "2024-07-05T08:30:00Z",
        "externalIp": "203.0.113.121",
        "lastIpToMgmt": "10.6.0.18",
        "domain": "ACME",
        "lastLoggedInUserName": "builder",
        "groupName": "Servers",
        "siteName": "US-East",
        "mitigationMode": "protect",
    },
}


S1_FIXTURE_DV_EVENTS: list[dict[str, Any]] = [
    {
        "eventType": "Process Creation",
        "eventTime": "2026-06-15T14:01:55Z",
        "agentId": "1200000000000000101",
        "endpointName": "LAPTOP-DESIGN-03",
        "user": "ACME\\dkim",
        "processName": "pennysvc.exe",
        "processCmd": "C:\\Users\\dkim\\AppData\\Local\\Temp\\pennysvc.exe -install",
        "parentProcessName": "explorer.exe",
        "sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
    },
    {
        "eventType": "Process Creation",
        "eventTime": "2026-06-15T14:02:30Z",
        "agentId": "1200000000000000101",
        "endpointName": "LAPTOP-DESIGN-03",
        "user": "ACME\\dkim",
        "processName": "vssadmin.exe",
        "processCmd": "vssadmin.exe delete shadows /all /quiet",
        "parentProcessName": "pennysvc.exe",
        "sha256": "dd11ee22ff33aa44bb55cc66dd77ee88ff99aa00bb11cc22dd33ee44ff55aa66",
    },
    {
        "eventType": "DNS",
        "eventTime": "2026-06-15T14:03:02Z",
        "agentId": "1200000000000000101",
        "endpointName": "LAPTOP-DESIGN-03",
        "user": "ACME\\dkim",
        "processName": "pennysvc.exe",
        "dnsRequest": "lockpay.example.net",
        "dnsResponse": "198.51.100.99",
    },
    {
        "eventType": "IP Connect",
        "eventTime": "2026-06-15T14:03:05Z",
        "agentId": "1200000000000000101",
        "endpointName": "LAPTOP-DESIGN-03",
        "user": "ACME\\dkim",
        "processName": "pennysvc.exe",
        "dstIp": "198.51.100.99",
        "dstPort": 443,
        "srcIp": "10.5.2.33",
        "srcPort": 50611,
    },
    {
        "eventType": "Process Creation",
        "eventTime": "2026-06-15T10:20:00Z",
        "agentId": "1200000000000000102",
        "endpointName": "SRV-BUILD-02",
        "user": "ACME\\builder",
        "processName": "msbuild.exe",
        "processCmd": "msbuild.exe Build.proj /m",
        "parentProcessName": "cmd.exe",
        "sha256": "ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66ee77ff88aa99bb00",
    },
]
