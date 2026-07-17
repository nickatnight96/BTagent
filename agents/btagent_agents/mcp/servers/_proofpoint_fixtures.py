"""Recorded Proofpoint TAP fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Proofpoint TAP SIEM API (``/v2/siem/all``) surfaces the live
connector will call:

- ``PFPT_FIXTURE_MESSAGES`` — ``messagesDelivered`` / ``messagesBlocked`` rows
  (``messageID``, ``messageTime``, ``sender``, ``recipient``, ``subject``,
  ``threatsInfoMap`` with per-threat ``classification``, ``senderIP``,
  ``_disposition`` = delivered|blocked). ``threatsInfoMap.classification``
  drives the verdict (malware > phish > spam).
- ``PFPT_FIXTURE_CLICKS`` — ``clicksPermitted`` / ``clicksBlocked`` rows
  (``messageID``, ``clickTime``, ``url``, ``classification``, ``recipient``,
  ``sender``, ``campaignId``, ``_disposition`` = permitted|blocked).

The fixtures tell one coherent phishing-campaign story for
``dkim@example.com``:

* A ``phish`` message (``invoice #4471``) is **delivered** — URL Defense didn't
  block the message — and the recipient then **clicks it (permitted)**: the
  delivered-phish → active-incident escalation Proofpoint TAP exists to catch.
* A ``malware`` message to ``bwallace@example.com`` is **blocked** at the
  gateway, and a later click on its rewritten URL is **blocked** too.
* A clean newsletter to ``dkim@example.com`` is delivered (verdict none) — the
  noise floor.

Join discipline: ``messageID`` is the message id on every surface — it ties a
click back to its delivered/blocked message; ``recipient`` is the VAP key.
"""

from __future__ import annotations

from typing import Any

CAMPAIGN_ID = "cmp-4471-invoice"


def _msg(
    *,
    message_id: str,
    message_time: str,
    sender: str,
    recipient: str,
    subject: str,
    classification: str | None,
    disposition: str,
    sender_ip: str,
) -> dict[str, Any]:
    """Build one Proofpoint TAP message row (delivered or blocked)."""
    threats_info = (
        []
        if classification is None
        else [
            {
                "threatType": "url",
                "classification": classification,
                "threat": f"{classification}-indicator",
                "threatUrl": "https://cdn-invoice.example.io/pay",
            }
        ]
    )
    return {
        "messageID": message_id,
        "messageTime": message_time,
        "sender": sender,
        "fromAddress": sender,
        "recipient": [recipient],
        "subject": subject,
        "senderIP": sender_ip,
        "threatsInfoMap": threats_info,
        "_disposition": disposition,
    }


PFPT_FIXTURE_MESSAGES: list[dict[str, Any]] = [
    # Delivered phish that the user later clicks — the active-incident seed.
    _msg(
        message_id="<msg-phish-001@example.io>",
        message_time="2026-07-08T13:02:00Z",
        sender="billing@cdn-invoice.example.io",
        recipient="dkim@example.com",
        subject="Invoice #4471 — payment overdue",
        classification="phish",
        disposition="delivered",
        sender_ip="45.61.100.9",
    ),
    # Malware blocked at the gateway.
    _msg(
        message_id="<msg-malw-002@example.io>",
        message_time="2026-07-08T13:20:00Z",
        sender="hr@cdn-invoice.example.io",
        recipient="bwallace@example.com",
        subject="Updated org chart (attachment)",
        classification="malware",
        disposition="blocked",
        sender_ip="45.61.100.9",
    ),
    # Clean newsletter — the noise floor.
    _msg(
        message_id="<msg-clean-003@example.com>",
        message_time="2026-07-08T15:00:00Z",
        sender="news@marketing.example.com",
        recipient="dkim@example.com",
        subject="Your weekly digest",
        classification=None,
        disposition="delivered",
        sender_ip="203.0.113.60",
    ),
]


def _click(
    *,
    message_id: str,
    click_time: str,
    url: str,
    classification: str,
    recipient: str,
    sender: str,
    disposition: str,
) -> dict[str, Any]:
    """Build one Proofpoint TAP click row (permitted or blocked)."""
    return {
        "messageID": message_id,
        "clickTime": click_time,
        "threatTime": click_time,
        "url": url,
        "classification": classification,
        "recipient": recipient,
        "sender": sender,
        "senderIP": "45.61.100.9",
        "campaignId": CAMPAIGN_ID,
        "_disposition": disposition,
    }


PFPT_FIXTURE_CLICKS: list[dict[str, Any]] = [
    # The delivered phish gets clicked (permitted) — active incident.
    _click(
        message_id="<msg-phish-001@example.io>",
        click_time="2026-07-08T13:07:30Z",
        url="https://cdn-invoice.example.io/pay",
        classification="phish",
        recipient="dkim@example.com",
        sender="billing@cdn-invoice.example.io",
        disposition="permitted",
    ),
    # A later click on the malware URL is blocked at the interstitial.
    _click(
        message_id="<msg-malw-002@example.io>",
        click_time="2026-07-08T14:05:00Z",
        url="https://cdn-invoice.example.io/orgchart",
        classification="malware",
        recipient="bwallace@example.com",
        sender="hr@cdn-invoice.example.io",
        disposition="blocked",
    ),
]
