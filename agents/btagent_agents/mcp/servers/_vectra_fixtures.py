"""Recorded Vectra AI NDR fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Vectra Detect / RUX API surfaces the live connector will
call:

- ``VECTRA_FIXTURE_DETECTIONS`` — ``/api/v3/detections`` rows: ``detection_id``,
  ``detection_type``, ``category`` (command-and-control / lateral-movement /
  exfiltration / reconnaissance), ``threat`` + ``certainty`` scores (0-100),
  ``state`` (active/fixed), ``src_host`` (name + ip), ``triage`` flag.
- ``VECTRA_FIXTURE_HOSTS`` — ``/api/v3/hosts`` records keyed by host name:
  aggregate ``threat`` / ``certainty`` scores, ``is_key_asset``, ``state``,
  ``last_detection``, ``ip``.

The fixtures tell one coherent kill-chain story on ``WIN10-FIN-07``:

* Vectra fires escalating detections on the host — **reconnaissance** →
  **command-and-control** (hidden HTTPS tunnel) → **lateral movement** (SMB
  brute) → **exfiltration** (data smuggler) — pushing its aggregate
  threat/certainty into the critical quadrant (high-threat, high-certainty).
* ``SRV-DB-11`` carries one low-score recon detection already ``fixed`` — the
  noise-floor comparison.

Join discipline: ``src_host.name`` on a detection is the ``name`` key on the
host inventory — the same host across both surfaces.
"""

from __future__ import annotations

from typing import Any

COMPROMISED_HOST = "WIN10-FIN-07"


def _detection(
    *,
    detection_id: str,
    detection_type: str,
    category: str,
    threat: int,
    certainty: int,
    state: str,
    host: str,
    host_ip: str,
    first_seen: str,
    triage: bool = False,
) -> dict[str, Any]:
    return {
        "detection_id": detection_id,
        "detection_type": detection_type,
        "category": category,
        "threat": threat,
        "certainty": certainty,
        "state": state,
        "src_host": {"name": host, "ip": host_ip},
        "first_timestamp": first_seen,
        "triaged": triage,
    }


VECTRA_FIXTURE_DETECTIONS: list[dict[str, Any]] = [
    _detection(
        detection_id="det-1001",
        detection_type="Suspicious Port Scan",
        category="reconnaissance",
        threat=30,
        certainty=45,
        state="active",
        host=COMPROMISED_HOST,
        host_ip="10.12.4.71",
        first_seen="2026-07-16T08:00:00Z",
    ),
    _detection(
        detection_id="det-1002",
        detection_type="Hidden HTTPS Tunnel",
        category="command-and-control",
        threat=82,
        certainty=76,
        state="active",
        host=COMPROMISED_HOST,
        host_ip="10.12.4.71",
        first_seen="2026-07-16T08:20:00Z",
    ),
    _detection(
        detection_id="det-1003",
        detection_type="SMB Brute Force",
        category="lateral-movement",
        threat=74,
        certainty=68,
        state="active",
        host=COMPROMISED_HOST,
        host_ip="10.12.4.71",
        first_seen="2026-07-16T08:40:00Z",
    ),
    _detection(
        detection_id="det-1004",
        detection_type="Smash and Grab (Data Smuggler)",
        category="exfiltration",
        threat=91,
        certainty=84,
        state="active",
        host=COMPROMISED_HOST,
        host_ip="10.12.4.71",
        first_seen="2026-07-16T09:05:00Z",
    ),
    # Noise floor: a low-score recon detection already resolved on another host.
    _detection(
        detection_id="det-0900",
        detection_type="Suspicious Port Scan",
        category="reconnaissance",
        threat=15,
        certainty=20,
        state="fixed",
        host="SRV-DB-11",
        host_ip="10.20.0.11",
        first_seen="2026-07-15T13:00:00Z",
        triage=True,
    ),
]


VECTRA_FIXTURE_HOSTS: dict[str, dict[str, Any]] = {
    COMPROMISED_HOST: {
        "name": COMPROMISED_HOST,
        "ip": "10.12.4.71",
        "threat": 91,
        "certainty": 84,
        "state": "active",
        "is_key_asset": True,
        "last_detection": "2026-07-16T09:05:00Z",
        "detection_count": 4,
    },
    "SRV-DB-11": {
        "name": "SRV-DB-11",
        "ip": "10.20.0.11",
        "threat": 15,
        "certainty": 20,
        "state": "active",
        "is_key_asset": True,
        "last_detection": "2026-07-15T13:00:00Z",
        "detection_count": 1,
    },
    "WS-DESIGN-22": {
        "name": "WS-DESIGN-22",
        "ip": "10.12.4.90",
        "threat": 0,
        "certainty": 0,
        "state": "active",
        "is_key_asset": False,
        "last_detection": "",
        "detection_count": 0,
    },
}
