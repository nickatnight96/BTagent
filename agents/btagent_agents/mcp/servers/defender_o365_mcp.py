"""Microsoft Defender for Office 365 MCP server connector — Tier-1 slice (#100).

First email-security connector (Tier-1 row: "Phishing triage is ~40% of every
SOC's queue"). Surfaces three capabilities to the agent layer; both raw
provider JSON and normalised :mod:`btagent_shared.types.email_hunt` objects
are returned so future phishing-triage detectors reason over one schema.

Capabilities:

- ``o365_email_events_search(start, end, sender=None, recipient=None,
  subject_contains=None, limit=100)`` — Advanced Hunting ``EmailEvents``
  rows (message flow + threat verdicts + delivery outcomes).
- ``o365_list_quarantine(start=None, end=None, recipient=None, limit=100)``
  — quarantined messages with their release lifecycle.
- ``o365_list_threat_submissions(start, end, category=None, limit=100)`` —
  user/admin-reported messages (Graph ``threatSubmission/emailThreats``).

Design notes
------------
* **Mock-first.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true``; mock mode
  serves recorded fixtures from :mod:`._defender_o365_fixtures`. Live mode is
  a guarded placeholder pulling Graph app credentials from ``${secret:…}`` /
  ``${env:…}`` refs (resolved lazily).
* **Circuit breaker + connection pooling.** Re-uses
  :class:`btagent_agents.mcp.registry.MCPConnectionRegistry`.
* **Secret hygiene.** The Graph client secret is never logged, never put in
  exceptions, never returned in MCP envelopes; ``repr()`` omits it.
* **Pure normalisers.** :func:`normalise_email_event`,
  :func:`normalise_quarantine_message`, and
  :func:`normalise_threat_submission` are pure functions — no I/O — so they
  unit-test cleanly against fixture JSON.

Verdict / delivery mapping
--------------------------
``ThreatTypes`` is Defender's comma-separated classification. Precedence:
Malware > Phish > Spam (a message flagged both malware and phish triages as
malware). A ``Phish`` verdict with ``PhishConfidenceLevel == "High"`` maps to
HIGH_CONFIDENCE_PHISH — Defender policy treats it differently (bypasses
allow-lists) and triage priority follows. ``DeliveryAction`` maps via
:data:`O365_DELIVERY_MAP` (exact match on Defender's stable action strings).

Join discipline
---------------
``internet_message_id`` (RFC 5322 Message-ID) joins events ↔ submissions;
``network_message_id`` (Defender's message GUID) joins events ↔ quarantine.
Both ids are carried verbatim on every normalised unit.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.email_hunt import (
    EmailDeliveryAction,
    EmailMessageEvent,
    EmailSecurityProvider,
    EmailThreatSubmission,
    EmailThreatVerdict,
    QuarantinedMessage,
    QuarantineReleaseStatus,
    ThreatSubmissionCategory,
    ThreatSubmissionStatus,
)
from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._defender_o365_fixtures import (
    O365_FIXTURE_EMAIL_EVENTS,
    O365_FIXTURE_QUARANTINE,
    O365_FIXTURE_SUBMISSIONS,
)

logger = logging.getLogger("btagent.mcp.servers.defender_o365")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Provider string → enum maps (exact match on Defender's stable identifiers)
# ---------------------------------------------------------------------------

O365_DELIVERY_MAP: dict[str, EmailDeliveryAction] = {
    "Delivered": EmailDeliveryAction.DELIVERED,
    "Junked": EmailDeliveryAction.DELIVERED_TO_JUNK,
    "Quarantined": EmailDeliveryAction.QUARANTINED,
    "Blocked": EmailDeliveryAction.BLOCKED,
    "Replaced": EmailDeliveryAction.REPLACED,
}

O365_RELEASE_STATUS_MAP: dict[str, QuarantineReleaseStatus] = {
    "notReleased": QuarantineReleaseStatus.NEEDS_REVIEW,
    "requested": QuarantineReleaseStatus.RELEASE_REQUESTED,
    "released": QuarantineReleaseStatus.RELEASED,
    "denied": QuarantineReleaseStatus.DENIED,
    "expired": QuarantineReleaseStatus.EXPIRED,
}

O365_SUBMISSION_CATEGORY_MAP: dict[str, ThreatSubmissionCategory] = {
    "phishing": ThreatSubmissionCategory.PHISHING,
    "spam": ThreatSubmissionCategory.SPAM,
    "malware": ThreatSubmissionCategory.MALWARE,
    "notJunk": ThreatSubmissionCategory.NOT_JUNK,
}

O365_SUBMISSION_STATUS_MAP: dict[str, ThreatSubmissionStatus] = {
    "new": ThreatSubmissionStatus.NEW,
    "notStarted": ThreatSubmissionStatus.NEW,
    "running": ThreatSubmissionStatus.RUNNING,
    "completed": ThreatSubmissionStatus.COMPLETED,
}


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, fully unit-testable
# ---------------------------------------------------------------------------


def _parse_o365_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime``.

    Falls back to the epoch on bad input — the connector contract is
    "best-effort normalisation; bad rows logged + skipped upstream".
    """
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("defender_o365: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def classify_verdict(threat_types: str, phish_confidence: str = "") -> EmailThreatVerdict:
    """Map Defender ``ThreatTypes`` (+ phish confidence) to a verdict.

    Precedence Malware > Phish > Spam; ``Phish`` with a ``High`` confidence
    level upgrades to HIGH_CONFIDENCE_PHISH. Empty / unrecognised types are
    NONE — the clean-mail noise floor.
    """
    types = {t.strip().lower() for t in (threat_types or "").split(",") if t.strip()}
    if "malware" in types:
        return EmailThreatVerdict.MALWARE
    if "phish" in types:
        if (phish_confidence or "").strip().lower() == "high":
            return EmailThreatVerdict.HIGH_CONFIDENCE_PHISH
        return EmailThreatVerdict.PHISH
    if "spam" in types:
        return EmailThreatVerdict.SPAM
    return EmailThreatVerdict.NONE


def normalise_email_event(raw: dict[str, Any], *, org_id: str) -> EmailMessageEvent:
    """Map one Advanced Hunting ``EmailEvents`` row to :class:`EmailMessageEvent`."""
    network_id = str(raw.get("NetworkMessageId") or "")
    return EmailMessageEvent(
        id=f"o365_evt_{network_id or raw.get('Timestamp', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.DEFENDER_O365,
        network_message_id=network_id,
        internet_message_id=str(raw.get("InternetMessageId") or ""),
        timestamp=_parse_o365_timestamp(raw.get("Timestamp")),
        sender=str(raw.get("SenderFromAddress") or ""),
        sender_ip=str(raw.get("SenderIPv4") or raw.get("SenderIPv6") or ""),
        recipient=str(raw.get("RecipientEmailAddress") or ""),
        subject=str(raw.get("Subject") or ""),
        verdict=classify_verdict(
            str(raw.get("ThreatTypes") or ""), str(raw.get("PhishConfidenceLevel") or "")
        ),
        delivery_action=O365_DELIVERY_MAP.get(
            str(raw.get("DeliveryAction") or ""), EmailDeliveryAction.UNKNOWN
        ),
        delivery_location=str(raw.get("DeliveryLocation") or ""),
        threat_names=[n.strip() for n in str(raw.get("ThreatNames") or "").split(",") if n.strip()],
        url_count=int(raw.get("UrlCount") or 0),
        attachment_count=int(raw.get("AttachmentCount") or 0),
        raw=raw,
    )


def normalise_quarantine_message(raw: dict[str, Any], *, org_id: str) -> QuarantinedMessage:
    """Map one quarantine entry to :class:`QuarantinedMessage`.

    ``quarantineReason`` reuses the ThreatTypes vocabulary (plus Defender's
    ``HighConfPhish``) so it feeds the same verdict classifier.
    """
    reason = str(raw.get("quarantineReason") or "")
    if reason.strip().lower() == "highconfphish":
        verdict = EmailThreatVerdict.HIGH_CONFIDENCE_PHISH
    else:
        verdict = classify_verdict(reason)
    expires_raw = raw.get("expiresDateTime")
    return QuarantinedMessage(
        id=f"o365_quar_{raw.get('id', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.DEFENDER_O365,
        network_message_id=str(raw.get("networkMessageId") or ""),
        internet_message_id=str(raw.get("internetMessageId") or ""),
        sender=str(raw.get("senderAddress") or ""),
        recipient=str(raw.get("recipientAddress") or ""),
        subject=str(raw.get("subject") or ""),
        verdict=verdict,
        release_status=O365_RELEASE_STATUS_MAP.get(
            str(raw.get("releaseStatus") or ""), QuarantineReleaseStatus.UNKNOWN
        ),
        received_at=_parse_o365_timestamp(raw.get("receivedDateTime")),
        expires_at=_parse_o365_timestamp(expires_raw) if expires_raw else None,
        raw=raw,
    )


def normalise_threat_submission(
    raw: dict[str, Any], *, org_id: str
) -> EmailThreatSubmission | None:
    """Map one Graph email-threat submission to :class:`EmailThreatSubmission`.

    Returns ``None`` when the submission ``category`` isn't one of the four
    Graph values — callers drop the row (it stays in the raw envelope).
    The post-analysis ``result.category`` reuses the verdict classifier.
    """
    category = O365_SUBMISSION_CATEGORY_MAP.get(str(raw.get("category") or ""))
    if category is None:
        return None
    created_by = ((raw.get("createdBy") or {}).get("user") or {}).get("email") or ""
    result_category = str((raw.get("result") or {}).get("category") or "")
    return EmailThreatSubmission(
        id=f"o365_sub_{raw.get('id', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.DEFENDER_O365,
        submitted_by=str(created_by),
        category=category,
        status=O365_SUBMISSION_STATUS_MAP.get(
            str(raw.get("status") or ""), ThreatSubmissionStatus.UNKNOWN
        ),
        result_verdict=classify_verdict(result_category),
        internet_message_id=str(raw.get("internetMessageId") or ""),
        recipient=str(raw.get("recipientEmailAddress") or ""),
        subject=str(raw.get("subject") or ""),
        submitted_at=_parse_o365_timestamp(raw.get("createdDateTime")),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Graph client secret.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:o365-client-secret:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Defender for Office 365 MCP server class
# ---------------------------------------------------------------------------
class DefenderO365MCPServer:
    """Defender for Office 365 MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls MS Graph unless explicitly opted out AND a client secret
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.

    The Graph client secret is resolved lazily via
    :func:`btagent_shared.utils.secrets.resolve_secret` so an unresolved
    ``${secret:vault:…}`` reference can't break import / boot; it is never
    logged or returned in MCP envelopes.
    """

    server_id: str = "defender_o365"

    DEFAULT_TENANT_REF: str = "${env:BTAGENT_O365_TENANT_ID}"
    DEFAULT_CLIENT_ID_REF: str = "${env:BTAGENT_O365_CLIENT_ID}"
    DEFAULT_CLIENT_SECRET_REF: str = "${secret:vault:defender_o365/graph_client_secret}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_O365_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        graph_base_url: str | None = None,
        tenant_ref: str | None = None,
        client_id_ref: str | None = None,
        client_secret_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.graph_base_url: str = (
            graph_base_url
            or os.getenv("BTAGENT_O365_GRAPH_URL")
            or "https://graph.microsoft.com/v1.0"
        )
        self._tenant_ref: str = tenant_ref or self.DEFAULT_TENANT_REF
        self._client_id_ref: str = client_id_ref or self.DEFAULT_CLIENT_ID_REF
        self._client_secret_ref: str = client_secret_ref or self.DEFAULT_CLIENT_SECRET_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"DefenderO365MCPServer(server_id={self.server_id!r}, "
            f"graph_base_url={self.graph_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_client_secret(self) -> str:
        """Resolve the Graph client secret lazily from the configured ref."""
        resolved: str = resolve_secret(self._client_secret_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised units."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_o365_default"

    # ----- tools -----

    async def o365_email_events_search(
        self,
        start: str,
        end: str,
        sender: str | None = None,
        recipient: str | None = None,
        subject_contains: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Defender EmailEvents (message flow + threat verdicts).

        Args:
            start: ISO-8601 start timestamp (inclusive).
            end:   ISO-8601 end timestamp (exclusive).
            sender: Optional sender-address substring filter.
            recipient: Optional recipient-address substring filter.
            subject_contains: Optional subject substring filter.
            limit: Max events to return.

        Returns:
            Envelope with the raw provider rows and the normalised
            :class:`EmailMessageEvent` list.
        """
        if self.mock_mode:
            return self._mock_email_events_search(
                start, end, sender, recipient, subject_contains, limit
            )
        return await self._real_email_events_search(
            start, end, sender, recipient, subject_contains, limit
        )

    async def o365_list_quarantine(
        self,
        start: str | None = None,
        end: str | None = None,
        recipient: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List quarantined messages with their release lifecycle.

        Args:
            start: Optional ISO-8601 received-at window start (inclusive).
            end: Optional ISO-8601 received-at window end (exclusive).
            recipient: Optional recipient-address substring filter.
            limit: Max messages to return.

        Returns:
            Envelope with raw + normalised :class:`QuarantinedMessage` lists.
        """
        if self.mock_mode:
            return self._mock_list_quarantine(start, end, recipient, limit)
        return await self._real_list_quarantine(start, end, recipient, limit)

    async def o365_list_threat_submissions(
        self,
        start: str,
        end: str,
        category: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List user/admin email-threat submissions (the triage intake queue).

        Args:
            start: ISO-8601 submitted-at window start (inclusive).
            end: ISO-8601 submitted-at window end (exclusive).
            category: Optional Graph category filter
                (phishing | spam | malware | notJunk).
            limit: Max submissions to return.

        Returns:
            Envelope with raw + normalised :class:`EmailThreatSubmission`
            lists. Unknown categories are dropped from the normalised list
            but kept in ``submissions_raw``.
        """
        if self.mock_mode:
            return self._mock_list_threat_submissions(start, end, category, limit)
        return await self._real_list_threat_submissions(start, end, category, limit)

    # ----- mock implementations -----

    def _mock_email_events_search(
        self,
        start: str,
        end: str,
        sender: str | None,
        recipient: str | None,
        subject_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_o365_timestamp(start)
        end_dt = _parse_o365_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in O365_FIXTURE_EMAIL_EVENTS:
            ts = _parse_o365_timestamp(evt.get("Timestamp"))
            if ts < start_dt or ts >= end_dt:
                continue
            if sender and sender not in (evt.get("SenderFromAddress") or ""):
                continue
            if recipient and recipient not in (evt.get("RecipientEmailAddress") or ""):
                continue
            if subject_contains and subject_contains not in (evt.get("Subject") or ""):
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [normalise_email_event(e, org_id=org_id) for e in events_raw]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "sender": sender,
            "recipient": recipient,
            "subject_contains": subject_contains,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_list_quarantine(
        self,
        start: str | None,
        end: str | None,
        recipient: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_o365_timestamp(start) if start else None
        end_dt = _parse_o365_timestamp(end) if end else None
        raws: list[dict[str, Any]] = []
        for msg in O365_FIXTURE_QUARANTINE:
            ts = _parse_o365_timestamp(msg.get("receivedDateTime"))
            if start_dt is not None and ts < start_dt:
                continue
            if end_dt is not None and ts >= end_dt:
                continue
            if recipient and recipient not in (msg.get("recipientAddress") or ""):
                continue
            raws.append(msg)
            if len(raws) >= limit:
                break

        normalised = [normalise_quarantine_message(m, org_id=org_id) for m in raws]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "recipient": recipient,
            "total": len(raws),
            "messages_raw": raws,
            "messages": [m.model_dump(mode="json") for m in normalised],
        }

    def _mock_list_threat_submissions(
        self,
        start: str,
        end: str,
        category: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_o365_timestamp(start)
        end_dt = _parse_o365_timestamp(end)
        raws: list[dict[str, Any]] = []
        for sub in O365_FIXTURE_SUBMISSIONS:
            ts = _parse_o365_timestamp(sub.get("createdDateTime"))
            if ts < start_dt or ts >= end_dt:
                continue
            if category and sub.get("category") != category:
                continue
            raws.append(sub)
            if len(raws) >= limit:
                break

        normalised = [
            s
            for s in (normalise_threat_submission(r, org_id=org_id) for r in raws)
            if s is not None
        ]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "category": category,
            "total": len(raws),
            "submissions_raw": raws,
            "submissions": [s.model_dump(mode="json") for s in normalised],
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_email_events_search(
        self,
        start: str,
        end: str,
        sender: str | None,
        recipient: str | None,
        subject_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "defender_o365: live-mode email-events search refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Defender for O365 live mode requires a resolvable Graph client "
                "secret (wire ${secret:vault:defender_o365/graph_client_secret} "
                "or set BTAGENT_O365_CLIENT_SECRET)."
            )
        raise NotImplementedError("Defender O365 live email_events_search not yet implemented")

    async def _real_list_quarantine(
        self,
        start: str | None,
        end: str | None,
        recipient: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "defender_o365: live-mode quarantine list refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Defender for O365 live mode requires a resolvable Graph client secret"
            )
        raise NotImplementedError("Defender O365 live list_quarantine not yet implemented")

    async def _real_list_threat_submissions(
        self,
        start: str,
        end: str,
        category: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError(
                "Defender for O365 live mode requires a resolvable Graph client secret"
            )
        raise NotImplementedError("Defender O365 live list_threat_submissions not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "o365_email_events_search",
                "description": (
                    "Search Microsoft Defender for Office 365 EmailEvents for a "
                    "time window. Returns raw provider rows plus normalised "
                    "EmailMessageEvent objects (verdict: none/spam/phish/"
                    "high_confidence_phish/malware; delivery outcome) for "
                    "phishing triage and campaign scoping."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "sender": {
                            "type": "string",
                            "description": "Optional sender-address substring",
                        },
                        "recipient": {
                            "type": "string",
                            "description": "Optional recipient-address substring",
                        },
                        "subject_contains": {
                            "type": "string",
                            "description": "Optional subject substring",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max events to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "o365_list_quarantine",
                "description": (
                    "List Defender for Office 365 quarantined messages with "
                    "their release lifecycle (needs_review / release_requested "
                    "/ released / denied). Returns raw + normalised "
                    "QuarantinedMessage objects."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {
                            "type": "string",
                            "description": "Optional ISO-8601 received-at start (inclusive)",
                        },
                        "end": {
                            "type": "string",
                            "description": "Optional ISO-8601 received-at end (exclusive)",
                        },
                        "recipient": {
                            "type": "string",
                            "description": "Optional recipient-address substring",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max messages to return",
                            "default": 100,
                        },
                    },
                },
            },
            {
                "name": "o365_list_threat_submissions",
                "description": (
                    "List user/admin email-threat submissions (reported "
                    "phishing / spam / malware / not-junk) from Defender for "
                    "Office 365 — the phishing-triage intake queue. Returns "
                    "raw + normalised EmailThreatSubmission objects with the "
                    "provider's post-analysis verdict."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "category": {
                            "type": "string",
                            "description": (
                                "Optional category filter: phishing | spam | malware | notJunk"
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max submissions to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = DefenderO365MCPServer()


@tool
async def o365_email_events_search(
    start: str,
    end: str,
    sender: str | None = None,
    recipient: str | None = None,
    subject_contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Defender for Office 365 EmailEvents for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        sender: Optional sender-address substring.
        recipient: Optional recipient-address substring.
        subject_contains: Optional subject substring.
        limit: Max events to return.
    """
    return await _server.o365_email_events_search(
        start, end, sender, recipient, subject_contains, limit
    )


@tool
async def o365_list_quarantine(
    start: str | None = None,
    end: str | None = None,
    recipient: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List Defender for Office 365 quarantined messages.

    Args:
        start: Optional ISO-8601 received-at start (inclusive).
        end: Optional ISO-8601 received-at end (exclusive).
        recipient: Optional recipient-address substring.
        limit: Max messages to return.
    """
    return await _server.o365_list_quarantine(start, end, recipient, limit)


@tool
async def o365_list_threat_submissions(
    start: str,
    end: str,
    category: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List user/admin email-threat submissions (phishing-triage intake).

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        category: Optional category filter (phishing | spam | malware | notJunk).
        limit: Max submissions to return.
    """
    return await _server.o365_list_threat_submissions(start, end, category, limit)
