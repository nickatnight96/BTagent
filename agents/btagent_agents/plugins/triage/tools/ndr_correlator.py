"""NDR-triage correlation tool for the Triage plugin.

Consumes the Vectra AI NDR connector's normalised output — the detection rows
of a ``vectra_list_detections`` envelope (``category``, ``threat``,
``certainty``, ``state``, ``triaged``, ``src_host``) — and correlates them into
a ranked, per-host **campaign view**.

The Vectra connector already ships a per-host rollup (``vectra_host_summary``);
this correlator adds what that single-host view cannot: it ranks **every** host
against each other and scores how far a host has progressed **through the kill
chain**. A host with active detections spanning multiple stages
(reconnaissance → command-and-control → lateral-movement → exfiltration) is a
confirmed campaign and outranks a host with a single high-threat detection.

Only **active, untriaged** detections count toward the live campaign view —
``fixed`` or analyst-``triaged`` detections are already handled and must not
inflate a host's live footprint (mirrors the deception correlator's treatment
of acknowledged trips).

Pure and deterministic: :func:`correlate_ndr_detections` does the work over
plain dicts (the shape the connector returns), and :func:`ndr_triage` is a thin
JSON-parsing ``@tool`` wrapper (mirroring :func:`deception_triage`).

Priority model (per host)
-------------------------
* ``critical`` — an **exfiltration** detection is active (data is leaving), or
  **three or more** distinct kill-chain stages are active (a deep campaign).
* ``high`` — **command-and-control** or **lateral-movement** is active (the
  host is past reconnaissance / post-compromise).
* ``medium`` — a single earlier-stage detection with an elevated threat score
  (``max_threat >= 50``).
* ``low`` — reconnaissance-only / low-threat noise.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

# Kill-chain ordering — deeper stage = later in the intrusion.
_KILL_CHAIN_ORDER: dict[str, int] = {
    "reconnaissance": 1,
    "command-and-control": 2,
    "lateral-movement": 3,
    "exfiltration": 4,
}

# Post-compromise stages that warrant a high floor on their own.
_POST_COMPROMISE = {"command-and-control", "lateral-movement"}

# Threat floor for a single earlier-stage detection to rank medium.
_ELEVATED_THREAT = 50

# Priority ordering for ranking (higher = more urgent).
_PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _host_priority(stages: set[str], max_threat: int) -> str:
    """Priority for a host from its active kill-chain stages + max threat."""
    if "exfiltration" in stages:
        return "critical"
    if len(stages) >= 3:
        return "critical"
    if stages & _POST_COMPROMISE:
        return "high"
    if max_threat >= _ELEVATED_THREAT:
        return "medium"
    return "low"


def correlate_ndr_detections(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate Vectra NDR detections into a ranked per-host campaign view.

    Pure: no I/O. Accepts the ``detections`` list of a ``vectra_list_detections``
    envelope. See the module docstring for the priority model.
    """
    detections = detections or []

    # Aggregate the live footprint per host from active, untriaged detections.
    hosts: dict[str, dict[str, Any]] = {}
    for det in detections:
        if str(det.get("state", "")).lower() != "active":
            continue
        if det.get("triaged"):
            continue
        src = det.get("src_host") or {}
        name = str(src.get("name") or "")
        if not name:
            continue
        category = str(det.get("category") or "").lower()
        threat = int(det.get("threat") or 0)
        certainty = int(det.get("certainty") or 0)

        h = hosts.setdefault(
            name,
            {
                "host": name,
                "ip": src.get("ip", ""),
                "stages": set(),
                "categories": [],
                "max_threat": 0,
                "max_certainty": 0,
                "detection_count": 0,
            },
        )
        if category:
            h["stages"].add(category)
            h["categories"].append(category)
        h["max_threat"] = max(h["max_threat"], threat)
        h["max_certainty"] = max(h["max_certainty"], certainty)
        h["detection_count"] += 1

    correlated: list[dict[str, Any]] = []
    for h in hosts.values():
        stages: set[str] = h["stages"]
        priority = _host_priority(stages, h["max_threat"])
        deepest = max(stages, key=lambda s: _KILL_CHAIN_ORDER.get(s, 0), default="")
        campaign = len(stages) >= 2  # progression across ≥2 kill-chain stages
        correlated.append(
            {
                "host": h["host"],
                "ip": h["ip"],
                "priority": priority,
                "kill_chain_stages": sorted(stages, key=lambda s: _KILL_CHAIN_ORDER.get(s, 0)),
                "deepest_stage": deepest,
                "campaign": campaign,
                "max_threat": h["max_threat"],
                "max_certainty": h["max_certainty"],
                "detection_count": h["detection_count"],
                "rationale": _rationale(stages, campaign, h["max_threat"]),
            }
        )

    # Rank: priority, then kill-chain depth, then threat.
    correlated.sort(
        key=lambda hh: (
            _PRIORITY_RANK.get(hh["priority"], 0),
            _KILL_CHAIN_ORDER.get(hh["deepest_stage"], 0),
            hh["max_threat"],
        ),
        reverse=True,
    )

    counts: dict[str, int] = {p: 0 for p in _PRIORITY_RANK}
    for hh in correlated:
        counts[hh["priority"]] = counts.get(hh["priority"], 0) + 1

    campaign_count = sum(1 for hh in correlated if hh["campaign"])

    return {
        "total_hosts": len(correlated),
        # The headline: hosts showing kill-chain progression (multi-stage).
        "campaign_count": campaign_count,
        "counts_by_priority": counts,
        "hosts": correlated,
    }


def _rationale(stages: set[str], campaign: bool, max_threat: int) -> str:
    if "exfiltration" in stages:
        return "Active exfiltration detection — data is leaving the host; contain now."
    if len(stages) >= 3:
        return "Three or more kill-chain stages active — a deep, confirmed campaign on this host."
    if stages & _POST_COMPROMISE:
        return "Command-and-control / lateral-movement active — host is past reconnaissance."
    if campaign:
        return "Detections span multiple kill-chain stages — progression under way."
    if max_threat >= _ELEVATED_THREAT:
        return "Single elevated-threat detection — investigate before it progresses."
    return "Reconnaissance-only / low-threat activity — monitor."


@tool
def ndr_triage(detections_json: str) -> dict[str, Any]:
    """Correlate Vectra NDR telemetry into a ranked per-host campaign view.

    Consumes the ``detections`` array of a ``vectra_list_detections`` envelope
    and ranks each host by how far it has progressed through the kill chain
    (reconnaissance → command-and-control → lateral-movement → exfiltration).
    Surfaces the headline campaign signal — a host with detections spanning
    multiple kill-chain stages — and reports the campaign count and the
    per-host stage rollup. Only active, untriaged detections count.

    Args:
        detections_json: JSON array of Vectra detection objects (the
            ``detections`` field of a ``vectra_list_detections`` envelope).
    """
    try:
        detections = json.loads(detections_json) if detections_json else []
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}", "total_hosts": 0, "hosts": []}

    if not isinstance(detections, list):
        return {
            "error": "detections_json must be a JSON array of Vectra detection objects",
            "total_hosts": 0,
            "hosts": [],
        }

    return correlate_ndr_detections(detections)
