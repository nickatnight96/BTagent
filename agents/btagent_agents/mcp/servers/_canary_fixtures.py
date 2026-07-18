"""Recorded Thinkst Canary fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Thinkst Canary Console API surfaces the live connector will
call:

- ``CANARY_FIXTURE_INCIDENTS`` — ``/api/v1/incidents/all``-style incident rows:
  ``id``, ``incident_type`` (canarytoken triggered / port scan / SMB file open
  / SSH login attempt / HTTP login attempt), ``src_host`` (attacker IP),
  ``target`` (the tripped canary/token name), ``description``, ``created`` (ts),
  ``acknowledged`` flag.
- ``CANARY_FIXTURE_DEVICES`` — deployed canaries + canarytokens inventory keyed
  by name: ``kind`` (canary | canarytoken), ``location``, ``live`` flag,
  ``last_triggered``.

The fixtures tell one coherent intruder story from a single attacker IP
(``198.51.100.23``) moving through the deception grid — every event is
high-fidelity (a canary trip is almost always a real intruder):

* A **canarytoken** (a planted fake AWS key, ``aws-key-finance``) is used —
  the attacker found and tried the decoy credential.
* The attacker then **port-scans** a Canary (``fileserver-decoy``) and finally
  **opens an SMB share** on it — lateral movement into the honeypot.
* A stray, already-acknowledged **HTTP login** trip on ``vpn-portal-decoy``
  from a benign scanner is the noise-floor comparison.

Join discipline: ``src_host`` (attacker IP) ties incidents together for the
per-IP summary; ``target`` is the canary/token name on the device inventory.
"""

from __future__ import annotations

from typing import Any

ATTACKER_IP = "198.51.100.23"


CANARY_FIXTURE_INCIDENTS: list[dict[str, Any]] = [
    {
        "id": "inc-canary-0001",
        "incident_type": "canarytoken triggered",
        "src_host": ATTACKER_IP,
        "target": "aws-key-finance",
        "description": "Canarytoken (AWS API key) used: GetCallerIdentity from 198.51.100.23.",
        "created": "2026-07-17T02:05:00Z",
        "acknowledged": False,
    },
    {
        "id": "inc-canary-0002",
        "incident_type": "port scan",
        "src_host": ATTACKER_IP,
        "target": "fileserver-decoy",
        "description": "Host port scan detected against Canary fileserver-decoy.",
        "created": "2026-07-17T02:11:00Z",
        "acknowledged": False,
    },
    {
        "id": "inc-canary-0003",
        "incident_type": "SMB file open",
        "src_host": ATTACKER_IP,
        "target": "fileserver-decoy",
        "description": "SMB share 'Payroll$' opened on Canary fileserver-decoy.",
        "created": "2026-07-17T02:14:00Z",
        "acknowledged": False,
    },
    # Noise floor: an already-acknowledged benign scanner trip from another IP.
    {
        "id": "inc-canary-0004",
        "incident_type": "HTTP login attempt",
        "src_host": "203.0.113.9",
        "target": "vpn-portal-decoy",
        "description": "HTTP login page hit by a known vulnerability scanner.",
        "created": "2026-07-16T18:00:00Z",
        "acknowledged": True,
    },
]


CANARY_FIXTURE_DEVICES: dict[str, dict[str, Any]] = {
    "aws-key-finance": {
        "name": "aws-key-finance",
        "kind": "canarytoken",
        "location": "Finance SharePoint / creds.txt",
        "live": True,
        "last_triggered": "2026-07-17T02:05:00Z",
    },
    "fileserver-decoy": {
        "name": "fileserver-decoy",
        "kind": "canary",
        "location": "10.20.0.51 (Datacenter VLAN)",
        "live": True,
        "last_triggered": "2026-07-17T02:14:00Z",
    },
    "vpn-portal-decoy": {
        "name": "vpn-portal-decoy",
        "kind": "canary",
        "location": "DMZ",
        "live": True,
        "last_triggered": "2026-07-16T18:00:00Z",
    },
    "printer-decoy": {
        "name": "printer-decoy",
        "kind": "canary",
        "location": "10.12.4.200 (Office VLAN)",
        "live": True,
        "last_triggered": "",
    },
}
