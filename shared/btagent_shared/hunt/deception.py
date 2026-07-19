"""Deception hunt-finding mapper (deception vertical, slice 1).

Bridges the deception-triage correlator into the Phase 6 hunt-findings
pipeline. The correlator
(``btagent_agents.plugins.triage.tools.deception_correlator``) ranks Thinkst
Canary telemetry — canarytoken use, port scans, SMB/SSH/HTTP interactions —
into prioritised **deception incidents**. This module is the pure,
dependency-free conversion of those incidents into
:class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects so they
land in the same triage inbox (clustering, suppression, promotion) as every
other hunt source.

Deception is the fleet's **highest-fidelity** signal: a canary/canarytoken only
fires when something touches a resource with no legitimate use, so every trip
is a near-zero-false-positive intruder signal. That shows up here as a higher
confidence floor than the other domains — even a single acknowledged trip has a
real basis.

Mirrors :mod:`btagent_shared.hunt.email` (and the agentic/cloud mappers):
**pure**, no I/O, operating on the plain dict shape the correlator returns, so
``shared`` never imports from ``agents``. A later slice wires a runner + the
``POST /hunt/findings`` ingest.

Mapping decisions
-----------------
* ``source`` = :data:`HuntSource.DECEPTION`, ``domain`` =
  :data:`HuntDomain.DECEPTION` on every finding.
* ``severity`` tracks the correlator's priority; ``confidence`` is a fixed
  (high) rung per priority.
* ``technique_ids`` by kill-chain stage: ``credential_use`` →
  ``T1078`` (Valid Accounts), ``interaction`` → ``T1021`` (Remote Services),
  ``recon`` → ``T1046`` (Network Service Discovery). A ``multi_decoy`` trip also
  carries ``T1210`` (Exploitation of Remote Services — lateral movement).
* ``entities`` — the attacker IP (``kind="attacker_ip"``) and the tripped decoy
  (``kind="decoy"``); these are the clustering keys.
* ``observables`` — the attacker IP as an ``ip`` observable (the pivot).
* ``evidence`` — the raw incident dict.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntObservable,
    RecordFindingRequest,
)

# Correlator priority → finding severity.
_SEVERITY_BY_PRIORITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

# Correlator priority → finding confidence rung. Deception is near-zero false
# positive, so the floor sits well above the other domains'.
_CONFIDENCE_BY_PRIORITY: dict[str, float] = {
    "critical": 0.98,
    "high": 0.9,
    "medium": 0.8,
    "low": 0.6,
}

# Kill-chain stage → MITRE technique.
_T_BY_STAGE: dict[str, str] = {
    "credential_use": "T1078",  # Valid Accounts (a decoy credential was used)
    "interaction": "T1021",  # Remote Services (SMB/SSH/HTTP interaction)
    "recon": "T1046",  # Network Service Discovery (scan)
}
_T_LATERAL_MOVEMENT = "T1210"  # Exploitation of Remote Services (multi-decoy)


def _technique_ids(incident: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    stage = str(incident.get("stage") or "")
    mapped = _T_BY_STAGE.get(stage)
    if mapped:
        ids.append(mapped)
    if incident.get("multi_decoy"):
        ids.append(_T_LATERAL_MOVEMENT)
    return ids


def _title(incident: dict[str, Any]) -> str:
    priority = str(incident.get("priority") or "").upper()
    incident_type = str(incident.get("incident_type") or "deception trip")
    target = str(incident.get("target") or "a decoy")
    src = str(incident.get("src_host") or "unknown source")
    return f"[{priority}] Deception: {incident_type} on {target} from {src}"


def _entities(incident: dict[str, Any]) -> list[HuntEntity]:
    entities: list[HuntEntity] = []
    src = str(incident.get("src_host") or "").strip()
    if src:
        entities.append(HuntEntity(kind="attacker_ip", value=src))
    target = str(incident.get("target") or "").strip()
    if target:
        entities.append(HuntEntity(kind="decoy", value=target))
    return entities


def _observables(incident: dict[str, Any]) -> list[HuntObservable]:
    src = str(incident.get("src_host") or "").strip()
    return [HuntObservable(type="ip", value=src)] if src else []


def deception_incident_to_finding(incident: dict[str, Any]) -> RecordFindingRequest:
    """Map one correlator incident dict to a :class:`RecordFindingRequest`."""
    priority = str(incident.get("priority") or "medium").strip().lower()
    severity = _SEVERITY_BY_PRIORITY.get(priority, Severity.MEDIUM)
    confidence = _CONFIDENCE_BY_PRIORITY.get(priority, 0.8)
    return RecordFindingRequest(
        source=HuntSource.DECEPTION,
        domain=HuntDomain.DECEPTION,
        title=_title(incident),
        description=str(incident.get("rationale") or ""),
        severity=severity,
        confidence=confidence,
        technique_ids=_technique_ids(incident),
        entities=_entities(incident),
        observables=_observables(incident),
        evidence={"deception_incident": incident},
    )


def deception_incidents_to_findings(correlation: dict[str, Any]) -> list[RecordFindingRequest]:
    """Map a deception-correlator result into hunt-finding requests.

    Pure: no I/O. Accepts the dict returned by ``correlate_deception_events``
    (the ``incidents`` list is what matters) and returns one
    :class:`RecordFindingRequest` per incident, preserving the correlator's
    critical-first ordering.
    """
    incidents = (correlation or {}).get("incidents") or []
    return [deception_incident_to_finding(inc) for inc in incidents]
