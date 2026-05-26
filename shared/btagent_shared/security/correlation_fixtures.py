"""Deterministic cross-source raw-event fixtures for UC-1.2 mock mode.

Keyed by entity value, each entry holds raw vendor events across several
connectors that *share entities* so they correlate into a believable
timeline. Critically, the raw events keep their native vendor shapes
(Splunk ``src_ip``, Elastic ``source.ip``) so the OCSFMapperNode does
real normalization work — proving the "no manual rekeying" acceptance
criterion rather than faking it.

Lives in shared/ (pydantic-free pure data) so any tier can use it for
demos / tests. Live mode replaces the fixture pull with real connector
queries.
"""

from __future__ import annotations

from typing import Any

# entity_value -> connector -> list[raw vendor event]
CORRELATION_FIXTURES: dict[str, dict[str, list[dict[str, Any]]]] = {
    # An internal host IP seen beaconing out, across SIEM + firewall + EDR.
    "10.1.42.17": {
        "splunk": [
            {
                "_time": "2026-05-21T09:14:03+00:00",
                "_cd": "12:884421",
                "src_ip": "10.1.42.17",
                "dest_ip": "185.220.101.42",
                "user": "jsmith",
                "host": "WS-JSMITH-PC",
                "action": "allowed",
                "bytes_out": 8442,
            },
            {
                "_time": "2026-05-21T09:19:51+00:00",
                "_cd": "12:884512",
                "src_ip": "10.1.42.17",
                "dest_ip": "185.220.101.42",
                "user": "jsmith",
                "host": "WS-JSMITH-PC",
                "action": "allowed",
                "bytes_out": 9120,
            },
        ],
        "firewall": [
            {
                "receive_time": "2026-05-21T09:14:01+00:00",
                "event_id": "fw-99821",
                "src": "10.1.42.17",
                "dst": "185.220.101.42",
                "action": "allow",
                "app": "ssl",
            },
        ],
        "crowdstrike": [
            {
                "timestamp": 1779354883,  # epoch for 2026-05-21T09:14:43Z — exercises the int path
                "event_id": "cs-5521",
                "event_simpleName": "ProcessRollup2",
                "ComputerName": "WS-JSMITH-PC",
                "UserName": "jsmith",
                "LocalAddressIP4": "10.1.42.17",
                "SHA256HashData": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "FileName": "powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
            },
        ],
        "elastic": [
            {
                "@timestamp": "2026-05-21T09:20:11.000Z",
                "_id": "es-AX42",
                "source": {"ip": "10.1.42.17"},
                "destination": {"ip": "185.220.101.42"},
                "user": {"name": "jsmith"},
                "host": {"name": "WS-JSMITH-PC"},
                "event": {"action": "network_flow"},
                "dns": {"question": {"name": "evil-c2.example"}},
            },
        ],
    },
    # A user identity correlated across identity (Sentinel) + SIEM.
    "jsmith": {
        "sentinel": [
            {
                "TimeGenerated": "2026-05-21T08:55:00Z",
                "_id": "sent-7741",
                "AccountUpn": "jsmith@corp.example.com",
                "IpAddress": "10.1.42.17",
                "Computer": "WS-JSMITH-PC",
                "ResultType": "0",
            },
            {
                "TimeGenerated": "2026-05-21T08:51:00Z",
                "_id": "sent-7738",
                "AccountUpn": "jsmith@corp.example.com",
                "IpAddress": "203.0.113.9",
                "Computer": "WS-JSMITH-PC",
                "ResultType": "50126",  # failed login
            },
        ],
        "splunk": [
            {
                "_time": "2026-05-21T08:55:02+00:00",
                "_cd": "12:880011",
                "src_ip": "10.1.42.17",
                "user": "jsmith",
                "host": "WS-JSMITH-PC",
                "action": "authenticated",
            },
        ],
    },
}


def get_fixture(entity_value: str) -> dict[str, list[dict[str, Any]]]:
    """Raw events per connector for an entity, or empty dict if unknown."""
    return CORRELATION_FIXTURES.get(entity_value, {})


__all__ = ["CORRELATION_FIXTURES", "get_fixture"]
