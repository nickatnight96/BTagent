"""Deception-triage correlation tool for the Triage plugin.

Consumes the Thinkst Canary connector's normalised output — the incident rows
of a ``canary_list_incidents`` envelope (``incident_type``, ``src_host``,
``target``, ``acknowledged``) — and correlates them into a ranked list of
**deception incidents** grouped by attacker IP.

Deception telemetry is the highest-fidelity signal class in the fleet: a
Canary (honeypot) or Canarytoken (planted decoy credential / file / URL) only
ever fires when something touches a resource that has no legitimate use, so
every trip is a near-zero-false-positive intruder signal. The correlator's job
is not to decide *whether* something is malicious — the trip already answers
that — but to rank *how far through the kill chain* the intruder has moved.

The headline signal it exists to surface is **one attacker IP tripping more
than one distinct decoy** — an intruder moving laterally across the deception
grid (mirrors ``canary_incident_summary``'s ``multi_decoy`` flag, but ranked
and batched across every incident in the window).

Pure and deterministic: :func:`correlate_deception_events` does the work over
plain dicts (the shape the connector returns), and :func:`deception_triage` is
a thin JSON-parsing ``@tool`` wrapper so the agent can invoke it (mirroring
:func:`phishing_triage`).

Priority model (per correlated incident)
----------------------------------------
* ``critical`` — an **unacknowledged** incident whose ``src_host`` tripped
  **more than one distinct decoy** in the batch: lateral movement across the
  deception grid.
* ``high`` — an unacknowledged **canarytoken use** (a planted decoy credential
  was used) or a direct **service interaction** with a canary (SMB/SSH/HTTP
  login, file open) on a single decoy: an intruder past reconnaissance.
* ``medium`` — an unacknowledged **recon-only** trip (port / host scan) on a
  single decoy: the intruder found the decoy but has not yet interacted.
* ``low`` — an **acknowledged** incident (already triaged, or a known benign
  scanner on the noise floor).
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

# Priority ordering for ranking (higher = more urgent).
_PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _classify_incident_type(incident_type: str) -> str:
    """Bucket a Canary incident type into a kill-chain stage.

    Returns one of ``credential_use`` (a decoy secret was used),
    ``interaction`` (a canary service was touched), or ``recon`` (scan only).
    """
    t = (incident_type or "").strip().lower()
    if "canarytoken" in t or "token" in t:
        return "credential_use"
    if "scan" in t:
        return "recon"
    # SMB/SSH/HTTP logins, file opens, share access — direct service contact.
    return "interaction"


def _base_priority(stage: str) -> str:
    """Single-decoy priority floor for an unacknowledged incident stage."""
    if stage in ("credential_use", "interaction"):
        return "high"
    return "medium"  # recon


def correlate_deception_events(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate Canary incidents into ranked deception incidents.

    Pure: no I/O. Accepts the ``incidents`` list of a ``canary_list_incidents``
    envelope. See the module docstring for the priority model.
    """
    incidents = incidents or []

    # First pass: how many distinct decoys did each attacker IP trip, counting
    # only unacknowledged trips (acknowledged ones are already handled and must
    # not inflate an active intruder's movement score).
    decoys_by_host: dict[str, set[str]] = {}
    for inc in incidents:
        if inc.get("acknowledged"):
            continue
        host = str(inc.get("src_host") or "")
        target = str(inc.get("target") or "")
        if not host or not target:
            continue
        decoys_by_host.setdefault(host, set()).add(target)

    correlated: list[dict[str, Any]] = []
    for inc in incidents:
        host = str(inc.get("src_host") or "")
        incident_type = str(inc.get("incident_type") or "")
        acknowledged = bool(inc.get("acknowledged"))
        stage = _classify_incident_type(incident_type)
        multi_decoy = len(decoys_by_host.get(host, set())) > 1

        if acknowledged:
            priority = "low"
        elif multi_decoy:
            priority = "critical"
        else:
            priority = _base_priority(stage)

        correlated.append(
            {
                "priority": priority,
                "src_host": host,
                "target": inc.get("target", ""),
                "incident_type": incident_type,
                "stage": stage,
                "acknowledged": acknowledged,
                "multi_decoy": multi_decoy and not acknowledged,
                "id": inc.get("id", ""),
                "rationale": _rationale(stage, acknowledged, multi_decoy),
            }
        )

    # Rank most-urgent first; stable within a priority tier.
    correlated.sort(key=lambda i: _PRIORITY_RANK.get(i["priority"], 0), reverse=True)

    counts: dict[str, int] = {p: 0 for p in _PRIORITY_RANK}
    for inc in correlated:
        counts[inc["priority"]] = counts.get(inc["priority"], 0) + 1

    # Attacker rollup: most decoys tripped first (the lateral-movement view).
    attackers = [
        {
            "src_host": host,
            "distinct_decoys": len(decoys),
            "decoys_tripped": sorted(decoys),
            "moving": len(decoys) > 1,
        }
        for host, decoys in decoys_by_host.items()
    ]
    attackers.sort(key=lambda a: a["distinct_decoys"], reverse=True)

    # Active intruders = unacknowledged attackers moving across >1 decoy.
    active = sum(1 for a in attackers if a["moving"])

    return {
        "total_incidents": len(correlated),
        # The headline: attackers moving across more than one decoy.
        "active_intruder_count": active,
        "counts_by_priority": counts,
        "attackers": attackers,
        "incidents": correlated,
    }


def _rationale(stage: str, acknowledged: bool, multi_decoy: bool) -> str:
    if acknowledged:
        return "Incident already acknowledged — triaged or a known benign scanner."
    if multi_decoy:
        return (
            "Source IP tripped more than one distinct decoy — lateral movement "
            "across the deception grid."
        )
    if stage == "credential_use":
        return "A planted decoy credential (canarytoken) was used — intruder past reconnaissance."
    if stage == "interaction":
        return "A canary service was directly interacted with — intruder past reconnaissance."
    return "Recon-only trip (scan) on a single decoy — intruder found the decoy."


@tool
def deception_triage(incidents_json: str) -> dict[str, Any]:
    """Correlate Thinkst Canary telemetry into ranked deception incidents.

    Consumes the ``incidents`` array of a ``canary_list_incidents`` envelope
    and ranks each trip by how far through the kill chain the intruder has
    moved. Surfaces the headline lateral-movement signal — one attacker IP
    tripping more than one distinct decoy — and reports the active-intruder
    count and the per-attacker decoy rollup.

    Args:
        incidents_json: JSON array of Canary incident objects (the
            ``incidents`` field of a ``canary_list_incidents`` envelope).
    """
    try:
        incidents = json.loads(incidents_json) if incidents_json else []
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}", "total_incidents": 0, "incidents": []}

    if not isinstance(incidents, list):
        return {
            "error": "incidents_json must be a JSON array of Canary incident objects",
            "total_incidents": 0,
            "incidents": [],
        }

    return correlate_deception_events(incidents)
