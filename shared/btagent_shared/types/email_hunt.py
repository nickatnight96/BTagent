"""Email-security hunt schemas (#100 Tier-1 — email connectors).

Data contracts for the email-security connector family (Defender for Office
365 first; Google Workspace Security and the Tier-2 gateways later). Mirrors
:mod:`btagent_shared.types.identity_hunt`: the connectors normalise raw
provider JSON into these shapes so phishing-triage detectors reason over one
schema regardless of vendor.

Three units:

- :class:`EmailMessageEvent` — one message-flow observation (Defender
  ``EmailEvents`` row / message trace): who sent what to whom, the provider's
  threat verdict, and where the message actually landed.
- :class:`QuarantinedMessage` — one message sitting in quarantine with its
  release lifecycle (the admin-action surface of phishing triage).
- :class:`EmailThreatSubmission` — one user/admin report (the ~40%-of-queue
  phishing-triage intake #100 calls out).

Join discipline: ``internet_message_id`` (RFC 5322 Message-ID) joins events ↔
submissions across providers; ``network_message_id`` (provider-scoped GUID)
joins events ↔ quarantine within Defender.

Design notes: no heavy deps (``shared/`` tier), Pydantic v2 with
``ConfigDict(extra="forbid")``, lowercase StrEnum values throughout.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EmailSecurityProvider(StrEnum):
    """Email-security product the observation originates from."""

    DEFENDER_O365 = "defender_o365"
    GOOGLE_WORKSPACE = "google_workspace"
    PROOFPOINT = "proofpoint"  # Proofpoint TAP (Tier-2 #100)
    GENERIC = "generic"


class EmailThreatVerdict(StrEnum):
    """Provider threat classification for a message.

    ``high_confidence_phish`` is kept distinct from ``phish`` — Defender
    policies treat them differently (HCP bypasses allow-lists) and triage
    priority follows suit.
    """

    NONE = "none"
    SPAM = "spam"
    PHISH = "phish"
    HIGH_CONFIDENCE_PHISH = "high_confidence_phish"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"


class EmailDeliveryAction(StrEnum):
    """Where the provider actually put the message."""

    DELIVERED = "delivered"
    DELIVERED_TO_JUNK = "delivered_to_junk"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    REPLACED = "replaced"  # attachment stripped / ZAP replaced content
    UNKNOWN = "unknown"


class QuarantineReleaseStatus(StrEnum):
    """Lifecycle of a quarantined message's release request."""

    NEEDS_REVIEW = "needs_review"
    RELEASE_REQUESTED = "release_requested"
    RELEASED = "released"
    DENIED = "denied"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class ThreatSubmissionCategory(StrEnum):
    """What the reporter claims the message is."""

    PHISHING = "phishing"
    SPAM = "spam"
    MALWARE = "malware"
    NOT_JUNK = "not_junk"


class ThreatSubmissionStatus(StrEnum):
    """Provider-side analysis state of a submission."""

    NEW = "new"
    RUNNING = "running"
    COMPLETED = "completed"
    UNKNOWN = "unknown"


class ClickDisposition(StrEnum):
    """What the URL-defense gateway did when a recipient clicked a link.

    ``blocked`` means the gateway interstitial stopped the navigation;
    ``permitted`` means the click went through (the message-was-clicked
    signal that turns a delivered-phish into an active-incident).
    """

    BLOCKED = "blocked"
    PERMITTED = "permitted"


# ---------------------------------------------------------------------------
# Normalised units
# ---------------------------------------------------------------------------


class EmailMessageEvent(BaseModel):
    """One message-flow observation from an email-security provider."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    provider: EmailSecurityProvider
    # Provider-scoped message GUID (Defender NetworkMessageId) — joins to
    # quarantine entries; empty when the provider has no such id.
    network_message_id: str = Field(default="", max_length=200)
    # RFC 5322 Message-ID — the cross-provider join key to submissions.
    internet_message_id: str = Field(default="", max_length=512)
    timestamp: datetime
    sender: str = Field(default="", max_length=512)
    sender_ip: str = Field(default="", max_length=64)
    recipient: str = Field(default="", max_length=512)
    subject: str = Field(default="", max_length=1024)
    verdict: EmailThreatVerdict = EmailThreatVerdict.NONE
    delivery_action: EmailDeliveryAction = EmailDeliveryAction.UNKNOWN
    delivery_location: str = Field(default="", max_length=200)
    threat_names: list[str] = Field(default_factory=list)
    url_count: int = 0
    attachment_count: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)


class QuarantinedMessage(BaseModel):
    """One message held in quarantine, with its release lifecycle."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    provider: EmailSecurityProvider
    network_message_id: str = Field(default="", max_length=200)
    internet_message_id: str = Field(default="", max_length=512)
    sender: str = Field(default="", max_length=512)
    recipient: str = Field(default="", max_length=512)
    subject: str = Field(default="", max_length=1024)
    verdict: EmailThreatVerdict = EmailThreatVerdict.NONE
    release_status: QuarantineReleaseStatus = QuarantineReleaseStatus.UNKNOWN
    received_at: datetime
    expires_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class EmailThreatSubmission(BaseModel):
    """One user/admin-reported message (the phishing-triage intake queue)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    provider: EmailSecurityProvider
    submitted_by: str = Field(default="", max_length=512)
    category: ThreatSubmissionCategory
    status: ThreatSubmissionStatus = ThreatSubmissionStatus.UNKNOWN
    # The provider's post-analysis verdict; NONE until analysis completes.
    result_verdict: EmailThreatVerdict = EmailThreatVerdict.NONE
    internet_message_id: str = Field(default="", max_length=512)
    recipient: str = Field(default="", max_length=512)
    subject: str = Field(default="", max_length=1024)
    submitted_at: datetime
    raw: dict[str, Any] = Field(default_factory=dict)


class EmailClickEvent(BaseModel):
    """One URL-click observation from an email URL-defense gateway.

    Distinct from :class:`EmailMessageEvent` — a click is a *post-delivery*
    action on a rewritten link (Proofpoint URL Defense, ATP Safe Links). A
    ``permitted`` click on a ``phish``/``malware`` URL is the strongest
    "delivered phish is now an active incident" signal in phishing triage.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    provider: EmailSecurityProvider
    # Provider message id — joins a click back to its message event.
    internet_message_id: str = Field(default="", max_length=512)
    url: str = Field(default="", max_length=4096)
    verdict: EmailThreatVerdict = EmailThreatVerdict.NONE
    disposition: ClickDisposition = ClickDisposition.PERMITTED
    sender: str = Field(default="", max_length=512)
    recipient: str = Field(default="", max_length=512)
    sender_ip: str = Field(default="", max_length=64)
    campaign_id: str = Field(default="", max_length=200)
    clicked_at: datetime
    raw: dict[str, Any] = Field(default_factory=dict)
