"""Recorded Mimecast fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Mimecast API surfaces the live connector will call:

- ``MIMECAST_FIXTURE_MESSAGES`` — Message Tracking / SIEM rows
  (``fromEnv``/``to``, ``subject``, ``senderIP``, ``status`` delivered/held/
  bounced, ``detectionLevel`` verdict category, ``route`` inbound/outbound).
- ``MIMECAST_FIXTURE_HELD`` — ``/gateway/get-hold-message-list`` rows (the
  admin hold-review queue): ``id``, ``fromEnv``, ``to``, ``subject``,
  ``reason`` (spam/malware/impersonation/…), ``dateReceived``, ``status``
  held/released/rejected — the quarantine surface.
- ``MIMECAST_FIXTURE_CLICKS`` — ``/ttp/url/get-logs`` rows (URL Protect):
  ``url``, ``action`` block/permit/warn, ``category`` malicious/phishing/…,
  ``userEmailAddress``, ``fromUserEmailAddress``, ``date``, ``messageId``.

The fixtures tell one coherent BEC-plus-phish story for ``dkim@example.com``:

* An **impersonation** (BEC) email from a look-alike domain is **held** for
  review — the impersonation-protect surface.
* A **malware** email to ``bwallace@example.com`` is **blocked** at the
  gateway.
* A **phish** email is **delivered** to ``dkim@example.com`` and the user then
  **clicks its rewritten URL (permitted)** — the delivered-phish → active-
  incident signal, joined on ``messageId``.
* A clean newsletter to ``dkim@example.com`` is delivered — the noise floor.

Join discipline: ``messageId`` ties clicks back to their message; ``to`` /
``userEmailAddress`` is the recipient on every surface.
"""

from __future__ import annotations

from typing import Any

ATTACKER_IP = "45.61.100.9"


MIMECAST_FIXTURE_MESSAGES: list[dict[str, Any]] = [
    # Delivered phish that the user later clicks — the active-incident seed.
    {
        "messageId": "<mc-phish-001@example.io>",
        "received": "2026-07-11T09:02:00Z",
        "fromEnv": "billing@payments-invoice.example.io",
        "to": "dkim@example.com",
        "subject": "Invoice #7781 — overdue notice",
        "senderIP": ATTACKER_IP,
        "status": "delivered",
        "detectionLevel": "phishing",
        "route": "inbound",
    },
    # Malware blocked at the gateway.
    {
        "messageId": "<mc-malw-002@example.io>",
        "received": "2026-07-11T09:20:00Z",
        "fromEnv": "hr@payments-invoice.example.io",
        "to": "bwallace@example.com",
        "subject": "Updated benefits form",
        "senderIP": ATTACKER_IP,
        "status": "blocked",
        "detectionLevel": "malware",
        "route": "inbound",
    },
    # Clean newsletter — the noise floor.
    {
        "messageId": "<mc-clean-003@example.com>",
        "received": "2026-07-11T15:00:00Z",
        "fromEnv": "news@marketing.example.com",
        "to": "dkim@example.com",
        "subject": "Weekly product digest",
        "senderIP": "203.0.113.60",
        "status": "delivered",
        "detectionLevel": "none",
        "route": "inbound",
    },
]


MIMECAST_FIXTURE_HELD: list[dict[str, Any]] = [
    # BEC / impersonation email held for admin review.
    {
        "id": "mc-held-0001",
        "fromEnv": "ceo@example-corp.example.co",
        "to": "dkim@example.com",
        "subject": "Urgent: wire transfer needed today",
        "reason": "impersonation",
        "dateReceived": "2026-07-11T08:40:00Z",
        "status": "held",
    },
    # A spam email already released after review.
    {
        "id": "mc-held-0002",
        "fromEnv": "promos@bulk-mail.example.net",
        "to": "bwallace@example.com",
        "subject": "You have won a prize",
        "reason": "spam",
        "dateReceived": "2026-07-10T12:00:00Z",
        "status": "released",
    },
]


MIMECAST_FIXTURE_CLICKS: list[dict[str, Any]] = [
    # The delivered phish gets clicked (permitted) — active incident.
    {
        "messageId": "<mc-phish-001@example.io>",
        "date": "2026-07-11T09:07:30Z",
        "url": "https://payments-invoice.example.io/pay",
        "action": "permit",
        "category": "phishing",
        "userEmailAddress": "dkim@example.com",
        "fromUserEmailAddress": "billing@payments-invoice.example.io",
    },
    # A later click on a malicious URL is blocked at the interstitial.
    {
        "messageId": "<mc-malw-002@example.io>",
        "date": "2026-07-11T10:05:00Z",
        "url": "https://payments-invoice.example.io/form",
        "action": "block",
        "category": "malicious",
        "userEmailAddress": "bwallace@example.com",
        "fromUserEmailAddress": "hr@payments-invoice.example.io",
    },
]
