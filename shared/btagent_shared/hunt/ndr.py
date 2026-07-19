"""NDR hunt-finding mapper (NDR vertical, slice 1).

Bridges the NDR-triage correlator into the Phase 6 hunt-findings pipeline. The
correlator (``btagent_agents.plugins.triage.tools.ndr_correlator``) rolls Vectra
AI network detections up **per host** and scores how far through the kill chain
each host has progressed (reconnaissance → command-and-control →
lateral-movement → exfiltration). This module is the pure, dependency-free
conversion of those per-host rollups into
:class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects so they
land in the same triage inbox (clustering, suppression, promotion) as every
other hunt source.

Unlike the email/deception mappers (one finding per *incident*), NDR emits one
finding per **host** — the correlator has already collapsed a host's detections
into a single campaign rollup, so the host is the natural unit of triage.

Mirrors :mod:`btagent_shared.hunt.deception` / :mod:`btagent_shared.hunt.email`:
**pure**, no I/O, operating on the plain dict shape the correlator returns, so
``shared`` never imports from ``agents``. A later slice wires a runner + the
``POST /hunt/findings`` ingest.

Mapping decisions
-----------------
* ``source`` = :data:`HuntSource.NDR`, ``domain`` = :data:`HuntDomain.NDR`.
* ``severity`` tracks the correlator's priority; ``confidence`` is informed by
  Vectra's own ``max_certainty`` (0-100) with a per-priority floor — NDR is
  AI-scored and higher-FP than deception, so the floor sits below it.
* ``technique_ids`` — one per active kill-chain stage on the host:
  ``reconnaissance`` → ``T1046``, ``command-and-control`` → ``T1071``,
  ``lateral-movement`` → ``T1021``, ``exfiltration`` → ``T1041``.
* ``entities`` — the host (``kind="host"``) and its IP (``kind="ip"``); these
  are the clustering keys.
* ``observables`` — the host IP as an ``ip`` observable (the pivot).
* ``evidence`` — the raw per-host rollup dict.
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

# Per-priority confidence floor. NDR is AI-scored (higher FP than deception), so
# the floor sits below the deception mapper's.
_CONFIDENCE_FLOOR_BY_PRIORITY: dict[str, float] = {
    "critical": 0.85,
    "high": 0.7,
    "medium": 0.55,
    "low": 0.4,
}

# Kill-chain stage → MITRE technique.
_T_BY_STAGE: dict[str, str] = {
    "reconnaissance": "T1046",  # Network Service Discovery
    "command-and-control": "T1071",  # Application Layer Protocol
    "lateral-movement": "T1021",  # Remote Services
    "exfiltration": "T1041",  # Exfiltration Over C2 Channel
}


def _confidence(priority: str, max_certainty: int) -> float:
    """Blend Vectra's certainty (0-100) with a per-priority floor."""
    floor = _CONFIDENCE_FLOOR_BY_PRIORITY.get(priority, 0.55)
    certainty = max(0.0, min(1.0, max_certainty / 100.0))
    return round(max(floor, certainty), 4)


def _technique_ids(host: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for stage in host.get("kill_chain_stages") or []:
        mapped = _T_BY_STAGE.get(str(stage))
        if mapped and mapped not in ids:
            ids.append(mapped)
    return ids


def _title(host: dict[str, Any]) -> str:
    priority = str(host.get("priority") or "").upper()
    name = str(host.get("host") or "unknown host")
    deepest = str(host.get("deepest_stage") or "activity")
    stage_count = len(host.get("kill_chain_stages") or [])
    campaign = " — campaign" if host.get("campaign") else ""
    return (
        f"[{priority}] NDR: {name} reached {deepest} ({stage_count} kill-chain stage(s)){campaign}"
    )


def _entities(host: dict[str, Any]) -> list[HuntEntity]:
    entities: list[HuntEntity] = []
    name = str(host.get("host") or "").strip()
    if name:
        entities.append(HuntEntity(kind="host", value=name))
    ip = str(host.get("ip") or "").strip()
    if ip:
        entities.append(HuntEntity(kind="ip", value=ip))
    return entities


def _observables(host: dict[str, Any]) -> list[HuntObservable]:
    ip = str(host.get("ip") or "").strip()
    return [HuntObservable(type="ip", value=ip)] if ip else []


def ndr_host_to_finding(host: dict[str, Any]) -> RecordFindingRequest:
    """Map one correlator per-host rollup to a :class:`RecordFindingRequest`."""
    priority = str(host.get("priority") or "medium").strip().lower()
    severity = _SEVERITY_BY_PRIORITY.get(priority, Severity.MEDIUM)
    confidence = _confidence(priority, int(host.get("max_certainty") or 0))
    return RecordFindingRequest(
        source=HuntSource.NDR,
        domain=HuntDomain.NDR,
        title=_title(host),
        description=str(host.get("rationale") or ""),
        severity=severity,
        confidence=confidence,
        technique_ids=_technique_ids(host),
        entities=_entities(host),
        observables=_observables(host),
        evidence={"ndr_host": host},
    )


def ndr_hosts_to_findings(correlation: dict[str, Any]) -> list[RecordFindingRequest]:
    """Map an NDR-correlator result into hunt-finding requests.

    Pure: no I/O. Accepts the dict returned by ``correlate_ndr_detections``
    (the ``hosts`` list is what matters) and returns one
    :class:`RecordFindingRequest` per host, preserving the correlator's
    critical-first ordering.
    """
    hosts = (correlation or {}).get("hosts") or []
    return [ndr_host_to_finding(h) for h in hosts]
