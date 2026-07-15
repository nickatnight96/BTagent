"""Recorded Defender for Office 365 fixtures for mock-mode responses (#100).

Shapes mirror the provider surfaces the live connector will call:

- ``O365_FIXTURE_EMAIL_EVENTS`` — Advanced Hunting ``EmailEvents`` rows
  (Timestamp / NetworkMessageId / InternetMessageId / SenderFromAddress /
  SenderIPv4 / RecipientEmailAddress / Subject / ThreatTypes /
  PhishConfidenceLevel / ThreatNames / DeliveryAction / DeliveryLocation /
  UrlCount / AttachmentCount).
- ``O365_FIXTURE_QUARANTINE`` — quarantine entries (Graph
  ``security/quarantineMessages``-style: releaseStatus lifecycle).
- ``O365_FIXTURE_SUBMISSIONS`` — user/admin threat submissions (Graph
  ``security/threatSubmission/emailThreats``-style).

The fixtures tell one coherent phishing-triage story so contract tests can
assert cross-surface joins:

* A credential-phish wave from ``billing@invoice-alerts.example.net``
  (subject "Action required: unpaid invoice #4471") hits three users with
  three different outcomes — delivered to alice (the triage-priority case),
  junked for bob, quarantined for carol (high-confidence phish).
* A malware attachment ("Trojan:JS/Phonk.A") to dave is blocked outright.
* A clean newsletter and a junked pharma-spam round out the noise floor.
* alice reports her delivered phish (completed, verdict ``phish``); an admin
  submission for dave's malware is still running; bob mis-reports the
  newsletter as not-junk (completed, verdict ``none``).

Join keys: ``InternetMessageId`` (events ↔ submissions),
``NetworkMessageId`` (events ↔ quarantine).
"""

from __future__ import annotations

from typing import Any

O365_FIXTURE_EMAIL_EVENTS: list[dict[str, Any]] = [
    # --- Credential-phish campaign: invoice #4471 ---
    {
        "Timestamp": "2026-06-01T08:12:04Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000001",
        "InternetMessageId": "<campaign-4471-a@invoice-alerts.example.net>",
        "SenderFromAddress": "billing@invoice-alerts.example.net",
        "SenderIPv4": "203.0.113.66",
        "RecipientEmailAddress": "alice@example.com",
        "Subject": "Action required: unpaid invoice #4471",
        "ThreatTypes": "Phish",
        "PhishConfidenceLevel": "Normal",
        "ThreatNames": "Cred-harvest URL",
        "DeliveryAction": "Delivered",
        "DeliveryLocation": "Inbox/folder",
        "UrlCount": 2,
        "AttachmentCount": 0,
    },
    {
        "Timestamp": "2026-06-01T08:12:09Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000002",
        "InternetMessageId": "<campaign-4471-b@invoice-alerts.example.net>",
        "SenderFromAddress": "billing@invoice-alerts.example.net",
        "SenderIPv4": "203.0.113.66",
        "RecipientEmailAddress": "bob@example.com",
        "Subject": "Action required: unpaid invoice #4471",
        "ThreatTypes": "Phish",
        "PhishConfidenceLevel": "Normal",
        "ThreatNames": "Cred-harvest URL",
        "DeliveryAction": "Junked",
        "DeliveryLocation": "Junk folder",
        "UrlCount": 2,
        "AttachmentCount": 0,
    },
    {
        "Timestamp": "2026-06-01T08:12:15Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000003",
        "InternetMessageId": "<campaign-4471-c@invoice-alerts.example.net>",
        "SenderFromAddress": "billing@invoice-alerts.example.net",
        "SenderIPv4": "203.0.113.66",
        "RecipientEmailAddress": "carol@example.com",
        "Subject": "Action required: unpaid invoice #4471",
        "ThreatTypes": "Phish",
        "PhishConfidenceLevel": "High",
        "ThreatNames": "Cred-harvest URL",
        "DeliveryAction": "Quarantined",
        "DeliveryLocation": "Quarantine",
        "UrlCount": 2,
        "AttachmentCount": 0,
    },
    # --- Malware attachment, blocked ---
    {
        "Timestamp": "2026-06-01T11:47:31Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000004",
        "InternetMessageId": "<track-8813@parcel-track.example.org>",
        "SenderFromAddress": "delivery@parcel-track.example.org",
        "SenderIPv4": "198.51.100.77",
        "RecipientEmailAddress": "dave@example.com",
        "Subject": "Your parcel could not be delivered",
        "ThreatTypes": "Malware",
        "PhishConfidenceLevel": "",
        "ThreatNames": "Trojan:JS/Phonk.A",
        "DeliveryAction": "Blocked",
        "DeliveryLocation": "Dropped",
        "UrlCount": 0,
        "AttachmentCount": 1,
    },
    # --- Clean newsletter (noise floor) ---
    {
        "Timestamp": "2026-06-01T13:02:50Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000005",
        "InternetMessageId": "<digest-2026-06-01@vendor.example.com>",
        "SenderFromAddress": "news@vendor.example.com",
        "SenderIPv4": "192.0.2.10",
        "RecipientEmailAddress": "alice@example.com",
        "Subject": "June product digest",
        "ThreatTypes": "",
        "PhishConfidenceLevel": "",
        "ThreatNames": "",
        "DeliveryAction": "Delivered",
        "DeliveryLocation": "Inbox/folder",
        "UrlCount": 6,
        "AttachmentCount": 0,
    },
    # --- Pharma spam, junked ---
    {
        "Timestamp": "2026-06-01T15:20:11Z",
        "NetworkMessageId": "nm-00000000-0000-4000-8000-000000000006",
        "InternetMessageId": "<promo-771@deals.example.biz>",
        "SenderFromAddress": "offers@deals.example.biz",
        "SenderIPv4": "203.0.113.200",
        "RecipientEmailAddress": "bob@example.com",
        "Subject": "Limited offer just for you",
        "ThreatTypes": "Spam",
        "PhishConfidenceLevel": "",
        "ThreatNames": "",
        "DeliveryAction": "Junked",
        "DeliveryLocation": "Junk folder",
        "UrlCount": 4,
        "AttachmentCount": 0,
    },
]


O365_FIXTURE_QUARANTINE: list[dict[str, Any]] = [
    # carol's high-confidence phish from the campaign — awaiting review.
    {
        "id": "q-00000000-0000-4000-8000-00000000000a",
        "networkMessageId": "nm-00000000-0000-4000-8000-000000000003",
        "internetMessageId": "<campaign-4471-c@invoice-alerts.example.net>",
        "senderAddress": "billing@invoice-alerts.example.net",
        "recipientAddress": "carol@example.com",
        "subject": "Action required: unpaid invoice #4471",
        "quarantineReason": "HighConfPhish",
        "releaseStatus": "notReleased",
        "receivedDateTime": "2026-06-01T08:12:15Z",
        "expiresDateTime": "2026-07-01T08:12:15Z",
    },
    # An older spam a user asked to be released — request granted.
    {
        "id": "q-00000000-0000-4000-8000-00000000000b",
        "networkMessageId": "nm-00000000-0000-4000-8000-0000000000f0",
        "internetMessageId": "<promo-698@deals.example.biz>",
        "senderAddress": "offers@deals.example.biz",
        "recipientAddress": "erin@example.com",
        "subject": "Your subscription renewal",
        "quarantineReason": "Spam",
        "releaseStatus": "released",
        "receivedDateTime": "2026-05-28T09:30:00Z",
        "expiresDateTime": "2026-06-27T09:30:00Z",
    },
]


O365_FIXTURE_SUBMISSIONS: list[dict[str, Any]] = [
    # alice reports the phish that reached her inbox — analysis agrees.
    {
        "id": "sub-00000000-0000-4000-8000-0000000000a1",
        "category": "phishing",
        "status": "completed",
        "createdBy": {"user": {"email": "alice@example.com"}},
        "createdDateTime": "2026-06-01T08:45:00Z",
        "internetMessageId": "<campaign-4471-a@invoice-alerts.example.net>",
        "recipientEmailAddress": "alice@example.com",
        "subject": "Action required: unpaid invoice #4471",
        "result": {"category": "phish"},
    },
    # Admin re-submits dave's blocked malware for detonation — still running.
    {
        "id": "sub-00000000-0000-4000-8000-0000000000a2",
        "category": "malware",
        "status": "running",
        "createdBy": {"user": {"email": "secops-admin@example.com"}},
        "createdDateTime": "2026-06-01T12:10:00Z",
        "internetMessageId": "<track-8813@parcel-track.example.org>",
        "recipientEmailAddress": "dave@example.com",
        "subject": "Your parcel could not be delivered",
        "result": {},
    },
    # bob mis-reports the newsletter as not-junk — analysis returns clean.
    {
        "id": "sub-00000000-0000-4000-8000-0000000000a3",
        "category": "notJunk",
        "status": "completed",
        "createdBy": {"user": {"email": "bob@example.com"}},
        "createdDateTime": "2026-06-01T14:00:00Z",
        "internetMessageId": "<digest-2026-06-01@vendor.example.com>",
        "recipientEmailAddress": "bob@example.com",
        "subject": "June product digest",
        "result": {"category": "none"},
    },
]
