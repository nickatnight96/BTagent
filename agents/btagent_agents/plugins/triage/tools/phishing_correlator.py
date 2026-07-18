"""Phishing-triage correlation tool for the Triage plugin.

Consumes the email-security connectors' normalised
:mod:`btagent_shared.types.email_hunt` output — ``EmailMessageEvent`` (message
flow + verdict + delivery), ``EmailClickEvent`` (post-delivery URL clicks), and
``QuarantinedMessage`` (the hold-review queue) — and correlates them into a
ranked list of **phishing incidents**.

The headline signal it exists to surface is the one the ``EmailClickEvent``
schema was added for: a malicious message that was **delivered** and then
**clicked (permitted)** — a delivered phish that has become an active incident.

Pure and deterministic: :func:`correlate_email_threats` does the work over
plain dicts (the ``model_dump(mode="json")`` shape the connectors return), and
:func:`phishing_triage` is a thin JSON-parsing ``@tool`` wrapper so the agent
can invoke it (mirroring the enrichment plugin's ``bulk_enrich``).

Priority model (per correlated message)
---------------------------------------
* ``critical`` — malicious verdict, **delivered**, and a **permitted click**
  on the same message (active incident).
* ``high`` — a ``malware`` / ``high_confidence_phish`` message delivered but
  not (yet) clicked; **or** a standalone permitted click on a malicious URL
  with no matching message in the batch.
* ``medium`` — a ``phish`` / ``suspicious`` message delivered but not clicked;
  **or** a held (quarantined) malicious message still awaiting review.
* ``low`` — a malicious message the gateway **blocked / quarantined** with no
  click (defence worked); a blocked click.

Clean (``none``) messages are not incidents and are omitted.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

# Verdicts that make a message/click a phishing concern.
_MALICIOUS_VERDICTS = {"phish", "high_confidence_phish", "malware", "suspicious"}
# The subset that warrants a higher floor even before a click.
_SEVERE_VERDICTS = {"malware", "high_confidence_phish"}

# Priority ordering for ranking (higher = more urgent).
_PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _is_malicious(verdict: str) -> bool:
    return (verdict or "").strip().lower() in _MALICIOUS_VERDICTS


def _permitted_click_msg_ids(clicks: list[dict[str, Any]]) -> set[str]:
    """Message ids that have a permitted click on a malicious URL."""
    ids: set[str] = set()
    for c in clicks:
        if (
            str(c.get("disposition", "")).lower() == "permitted"
            and _is_malicious(str(c.get("verdict", "")))
            and c.get("internet_message_id")
        ):
            ids.add(str(c["internet_message_id"]))
    return ids


def _message_priority(verdict: str, delivered: bool, clicked: bool) -> str | None:
    """Priority for a message incident, or None if it isn't an incident."""
    if not _is_malicious(verdict):
        return None
    v = verdict.strip().lower()
    if delivered and clicked:
        return "critical"
    if delivered and v in _SEVERE_VERDICTS:
        return "high"
    if delivered:
        return "medium"
    # Not delivered — blocked / quarantined inline; the gateway stopped it.
    return "low"


def correlate_email_threats(
    messages: list[dict[str, Any]],
    clicks: list[dict[str, Any]] | None = None,
    quarantine: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Correlate normalised email units into ranked phishing incidents.

    Pure: no I/O. Accepts the ``model_dump(mode="json")`` dict shape the email
    connectors return. See the module docstring for the priority model.
    """
    messages = messages or []
    clicks = clicks or []
    quarantine = quarantine or []

    permitted_ids = _permitted_click_msg_ids(clicks)
    known_msg_ids: set[str] = set()
    incidents: list[dict[str, Any]] = []

    # --- message-anchored incidents ---
    for msg in messages:
        mid = str(msg.get("internet_message_id") or "")
        if mid:
            known_msg_ids.add(mid)
        verdict = str(msg.get("verdict") or "none")
        delivered = str(msg.get("delivery_action") or "").lower() == "delivered"
        clicked = bool(mid) and mid in permitted_ids
        priority = _message_priority(verdict, delivered, clicked)
        if priority is None:
            continue
        incidents.append(
            {
                "kind": "message",
                "priority": priority,
                "recipient": msg.get("recipient", ""),
                "internet_message_id": mid,
                "subject": msg.get("subject", ""),
                "sender": msg.get("sender", ""),
                "verdict": verdict,
                "delivery_action": msg.get("delivery_action", ""),
                "clicked": clicked,
                "rationale": _rationale(verdict, delivered, clicked),
            }
        )

    # --- standalone permitted clicks (no matching message in the batch) ---
    for c in clicks:
        mid = str(c.get("internet_message_id") or "")
        if (
            str(c.get("disposition", "")).lower() == "permitted"
            and _is_malicious(str(c.get("verdict", "")))
            and mid not in known_msg_ids
        ):
            incidents.append(
                {
                    "kind": "click",
                    "priority": "high",
                    "recipient": c.get("recipient", ""),
                    "internet_message_id": mid,
                    "url": c.get("url", ""),
                    "verdict": c.get("verdict", ""),
                    "clicked": True,
                    "rationale": "Permitted click on a malicious URL with no message context.",
                }
            )

    # --- held (quarantined) malicious messages awaiting review ---
    for q in quarantine:
        verdict = str(q.get("verdict") or "none")
        if not _is_malicious(verdict):
            continue
        if str(q.get("release_status", "")).lower() != "needs_review":
            continue
        incidents.append(
            {
                "kind": "quarantine",
                "priority": "medium",
                "recipient": q.get("recipient", ""),
                "subject": q.get("subject", ""),
                "verdict": verdict,
                "release_status": q.get("release_status", ""),
                "clicked": False,
                "rationale": "Malicious message held for review — release decision required.",
            }
        )

    # Rank most-urgent first; stable within a priority tier.
    incidents.sort(key=lambda i: _PRIORITY_RANK.get(i["priority"], 0), reverse=True)

    counts: dict[str, int] = {p: 0 for p in _PRIORITY_RANK}
    recipient_hits: dict[str, int] = {}
    for inc in incidents:
        counts[inc["priority"]] = counts.get(inc["priority"], 0) + 1
        r = str(inc.get("recipient") or "")
        if r:
            recipient_hits[r] = recipient_hits.get(r, 0) + 1

    active = sum(1 for i in incidents if i["priority"] == "critical")
    most_targeted = sorted(recipient_hits.items(), key=lambda kv: kv[1], reverse=True)

    return {
        "total_incidents": len(incidents),
        # The headline: delivered-and-clicked malicious mail = active incidents.
        "active_incident_count": active,
        "counts_by_priority": counts,
        "most_targeted_recipients": [{"recipient": r, "incidents": n} for r, n in most_targeted],
        "incidents": incidents,
    }


def _rationale(verdict: str, delivered: bool, clicked: bool) -> str:
    v = (verdict or "").strip().lower()
    if delivered and clicked:
        return f"{v} message was delivered and the recipient clicked (permitted) — active incident."
    if delivered and v in _SEVERE_VERDICTS:
        return f"{v} message was delivered; no click yet — contain before it is opened."
    if delivered:
        return f"{v} message was delivered but not clicked."
    return f"{v} message was blocked/quarantined by the gateway — defence held."


@tool
def phishing_triage(
    message_events_json: str,
    click_events_json: str = "[]",
    quarantine_json: str = "[]",
) -> dict[str, Any]:
    """Correlate email-security telemetry into ranked phishing incidents.

    Consumes the normalised output of the email connectors (Defender for O365,
    Proofpoint, Mimecast) and surfaces the delivered-phish-that-was-clicked
    active-incident signal. Ranks incidents critical → low and reports the
    active-incident count and the most-targeted recipients.

    Args:
        message_events_json: JSON array of normalised EmailMessageEvent objects
            (the ``events`` field of a connector message-search envelope).
        click_events_json: JSON array of normalised EmailClickEvent objects
            (the ``clicks`` field of a connector click-search envelope).
        quarantine_json: JSON array of normalised QuarantinedMessage objects
            (the ``messages`` field of a connector held/quarantine envelope).
    """
    try:
        messages = json.loads(message_events_json) if message_events_json else []
        clicks = json.loads(click_events_json) if click_events_json else []
        quarantine = json.loads(quarantine_json) if quarantine_json else []
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}", "total_incidents": 0, "incidents": []}

    if (
        not isinstance(messages, list)
        or not isinstance(clicks, list)
        or not isinstance(quarantine, list)
    ):
        return {
            "error": "Each argument must be a JSON array of normalised email objects",
            "total_incidents": 0,
            "incidents": [],
        }

    return correlate_email_threats(messages, clicks, quarantine)
