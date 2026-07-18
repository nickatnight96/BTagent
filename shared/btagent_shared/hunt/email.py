"""Email-security hunt-finding mapper (email vertical, slice 1).

Bridges the phishing-triage correlator into the Phase 6 hunt-findings pipeline.
The correlator (``btagent_agents.plugins.triage.tools.phishing_correlator``)
already ranks email-security telemetry — Defender for O365 / Proofpoint /
Mimecast message events, URL clicks, and the quarantine queue — into a list of
prioritised **phishing incidents**. This module is the pure, dependency-free
conversion of those incidents into
:class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects so they
land in the same triage inbox (clustering, suppression, promotion) as every
other hunt source.

It mirrors the other domain mappers (:mod:`btagent_shared.hunt.agentic`,
:mod:`btagent_shared.hunt.cloud`): **pure**, no I/O, operating on the plain
dict shape the correlator returns (``model_dump``-friendly), so ``shared`` never
imports from ``agents``. A later slice wires a runner + the ``POST
/hunt/findings`` ingest; this slice is just the schema + mapping + tests.

Mapping decisions
-----------------
* ``source`` = :data:`HuntSource.EMAIL_SECURITY`, ``domain`` =
  :data:`HuntDomain.EMAIL` on every finding.
* ``severity`` tracks the correlator's priority (critical → CRITICAL, … low →
  LOW); ``confidence`` is a fixed rung per priority.
* ``technique_ids`` — always ``T1566`` (Phishing). A permitted click or a
  ``click``-kind incident adds ``T1566.002`` (Spearphishing Link); a
  ``malware`` verdict adds ``T1566.001`` (Spearphishing Attachment).
* ``entities`` — recipient (``kind="email_recipient"``) and, when present,
  sender (``kind="email_sender"``); these are the clustering keys.
* ``observables`` — the clicked ``url`` and the ``internet_message_id`` when
  present, so promotion carries the pivot artifacts.
* ``evidence`` — the raw incident dict plus the correlator's ``rationale``.
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

# Correlator priority → finding confidence rung.
_CONFIDENCE_BY_PRIORITY: dict[str, float] = {
    "critical": 0.95,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.45,
}

_T_PHISHING = "T1566"
_T_PHISHING_LINK = "T1566.002"
_T_PHISHING_ATTACHMENT = "T1566.001"

# Verdicts that indicate a malware-bearing message (attachment technique).
_MALWARE_VERDICTS = {"malware"}


def _technique_ids(incident: dict[str, Any]) -> list[str]:
    """Technique set for an incident — always phishing, refined by kind/verdict."""
    ids = [_T_PHISHING]
    verdict = str(incident.get("verdict") or "").strip().lower()
    if incident.get("kind") == "click" or incident.get("clicked"):
        ids.append(_T_PHISHING_LINK)
    if verdict in _MALWARE_VERDICTS:
        ids.append(_T_PHISHING_ATTACHMENT)
    return ids


def _title(incident: dict[str, Any]) -> str:
    priority = str(incident.get("priority") or "").upper()
    verdict = str(incident.get("verdict") or "suspicious")
    recipient = str(incident.get("recipient") or "unknown recipient")
    kind = incident.get("kind")
    if kind == "click":
        return f"[{priority}] Malicious URL click by {recipient} ({verdict})"
    if kind == "quarantine":
        return f"[{priority}] Quarantined {verdict} message for {recipient} awaiting review"
    delivery = str(incident.get("delivery_action") or "")
    delivered = " (delivered)" if delivery.lower() == "delivered" else ""
    clicked = " and clicked" if incident.get("clicked") else ""
    return f"[{priority}] {verdict} email to {recipient}{delivered}{clicked}"


def _entities(incident: dict[str, Any]) -> list[HuntEntity]:
    entities: list[HuntEntity] = []
    recipient = str(incident.get("recipient") or "").strip()
    if recipient:
        entities.append(HuntEntity(kind="email_recipient", value=recipient))
    sender = str(incident.get("sender") or "").strip()
    if sender:
        entities.append(HuntEntity(kind="email_sender", value=sender))
    return entities


def _observables(incident: dict[str, Any]) -> list[HuntObservable]:
    observables: list[HuntObservable] = []
    url = str(incident.get("url") or "").strip()
    if url:
        observables.append(HuntObservable(type="url", value=url))
    mid = str(incident.get("internet_message_id") or "").strip()
    if mid:
        observables.append(HuntObservable(type="email_message_id", value=mid))
    return observables


def phishing_incident_to_finding(incident: dict[str, Any]) -> RecordFindingRequest:
    """Map one correlator incident dict to a :class:`RecordFindingRequest`."""
    priority = str(incident.get("priority") or "medium").strip().lower()
    severity = _SEVERITY_BY_PRIORITY.get(priority, Severity.MEDIUM)
    confidence = _CONFIDENCE_BY_PRIORITY.get(priority, 0.6)
    return RecordFindingRequest(
        source=HuntSource.EMAIL_SECURITY,
        domain=HuntDomain.EMAIL,
        title=_title(incident),
        description=str(incident.get("rationale") or ""),
        severity=severity,
        confidence=confidence,
        technique_ids=_technique_ids(incident),
        entities=_entities(incident),
        observables=_observables(incident),
        evidence={"phishing_incident": incident},
    )


def phishing_incidents_to_findings(correlation: dict[str, Any]) -> list[RecordFindingRequest]:
    """Map a phishing-correlator result into hunt-finding requests.

    Pure: no I/O. Accepts the dict returned by
    ``correlate_email_threats`` (the ``incidents`` list is what matters) and
    returns one :class:`RecordFindingRequest` per incident, preserving the
    correlator's critical-first ordering.
    """
    incidents = (correlation or {}).get("incidents") or []
    return [phishing_incident_to_finding(inc) for inc in incidents]
