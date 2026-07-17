"""Mimecast email-gateway MCP server connector — Tier-2 slice (#100).

Second email-gateway connector after Proofpoint. Mimecast is a secure email
gateway with a hold-review (quarantine) queue and URL Protect click logging,
so it exercises **all three** :mod:`btagent_shared.types.email_hunt` units —
message flow, quarantine lifecycle, and post-delivery clicks — under one
provider. Mock-first (``BTAGENT_MOCK_CONNECTORS`` default), lazy
``${secret:…}`` resolution, guarded live mode, pure normalisers.

Capabilities:

- ``mimecast_message_events_search(start, end, sender=None, recipient=None,
  subject_contains=None, limit=100)`` — Message Tracking rows normalised to
  :class:`EmailMessageEvent` (verdict from ``detectionLevel``; delivery action
  from ``status``).
- ``mimecast_list_held_messages(start=None, end=None, recipient=None,
  limit=100)`` — the admin hold-review queue normalised to
  :class:`QuarantinedMessage` (``reason`` → verdict, ``status`` → release
  lifecycle).
- ``mimecast_click_logs_search(start, end, recipient=None, action=None,
  limit=100)`` — URL Protect click rows normalised to
  :class:`EmailClickEvent`. A ``permit`` click on a ``phishing`` / ``malicious``
  URL is the delivered-phish → active-incident signal.

Verdict mapping
---------------
Mimecast ``detectionLevel`` / URL ``category`` values map: ``malware`` /
``malicious`` → MALWARE, ``phishing`` → PHISH, ``impersonation`` (BEC) →
SUSPICIOUS, ``spam`` → SPAM, everything else → NONE (precedence
Malware > Phish > Impersonation > Spam).

Secret hygiene mirrors the sibling connectors: the Mimecast secret key is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.email_hunt import (
    ClickDisposition,
    EmailClickEvent,
    EmailDeliveryAction,
    EmailMessageEvent,
    EmailSecurityProvider,
    EmailThreatVerdict,
    QuarantinedMessage,
    QuarantineReleaseStatus,
)
from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._mimecast_fixtures import (
    MIMECAST_FIXTURE_CLICKS,
    MIMECAST_FIXTURE_HELD,
    MIMECAST_FIXTURE_MESSAGES,
)

logger = logging.getLogger("btagent.mcp.servers.mimecast")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Provider string → enum maps
# ---------------------------------------------------------------------------

MIMECAST_STATUS_MAP: dict[str, EmailDeliveryAction] = {
    "delivered": EmailDeliveryAction.DELIVERED,
    "held": EmailDeliveryAction.QUARANTINED,
    "blocked": EmailDeliveryAction.BLOCKED,
    "bounced": EmailDeliveryAction.BLOCKED,
}

MIMECAST_HELD_STATUS_MAP: dict[str, QuarantineReleaseStatus] = {
    "held": QuarantineReleaseStatus.NEEDS_REVIEW,
    "released": QuarantineReleaseStatus.RELEASED,
    "rejected": QuarantineReleaseStatus.DENIED,
    "expired": QuarantineReleaseStatus.EXPIRED,
}

MIMECAST_CLICK_ACTION_MAP: dict[str, ClickDisposition] = {
    "permit": ClickDisposition.PERMITTED,
    "warn": ClickDisposition.PERMITTED,  # warned but navigation allowed
    "block": ClickDisposition.BLOCKED,
}


def _parse_mimecast_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("mimecast: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def classify_verdict(category: str) -> EmailThreatVerdict:
    """Map a Mimecast ``detectionLevel`` / URL ``category`` to a verdict.

    Precedence Malware > Phish > Impersonation (BEC → suspicious) > Spam;
    unrecognised / ``none`` maps to NONE.
    """
    cat = (category or "").strip().lower()
    if cat in ("malware", "malicious"):
        return EmailThreatVerdict.MALWARE
    if cat in ("phishing", "phish"):
        return EmailThreatVerdict.PHISH
    if cat in ("impersonation", "bec"):
        return EmailThreatVerdict.SUSPICIOUS
    if cat == "spam":
        return EmailThreatVerdict.SPAM
    return EmailThreatVerdict.NONE


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, fully unit-testable
# ---------------------------------------------------------------------------


def normalise_message_event(raw: dict[str, Any], *, org_id: str) -> EmailMessageEvent:
    """Map one Mimecast message-tracking row to :class:`EmailMessageEvent`."""
    message_id = str(raw.get("messageId") or "")
    return EmailMessageEvent(
        id=f"mc_evt_{message_id or raw.get('received', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.MIMECAST,
        internet_message_id=message_id,
        timestamp=_parse_mimecast_timestamp(raw.get("received")),
        sender=str(raw.get("fromEnv") or ""),
        sender_ip=str(raw.get("senderIP") or ""),
        recipient=str(raw.get("to") or ""),
        subject=str(raw.get("subject") or ""),
        verdict=classify_verdict(str(raw.get("detectionLevel") or "")),
        delivery_action=MIMECAST_STATUS_MAP.get(
            str(raw.get("status") or "").lower(), EmailDeliveryAction.UNKNOWN
        ),
        raw=raw,
    )


def normalise_held_message(raw: dict[str, Any], *, org_id: str) -> QuarantinedMessage:
    """Map one Mimecast held-queue row to :class:`QuarantinedMessage`."""
    held_id = str(raw.get("id") or "")
    return QuarantinedMessage(
        id=f"mc_held_{held_id}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.MIMECAST,
        sender=str(raw.get("fromEnv") or ""),
        recipient=str(raw.get("to") or ""),
        subject=str(raw.get("subject") or ""),
        verdict=classify_verdict(str(raw.get("reason") or "")),
        release_status=MIMECAST_HELD_STATUS_MAP.get(
            str(raw.get("status") or "").lower(), QuarantineReleaseStatus.UNKNOWN
        ),
        received_at=_parse_mimecast_timestamp(raw.get("dateReceived")),
        raw=raw,
    )


def normalise_click_event(raw: dict[str, Any], *, org_id: str) -> EmailClickEvent:
    """Map one Mimecast URL Protect click row to :class:`EmailClickEvent`."""
    message_id = str(raw.get("messageId") or "")
    return EmailClickEvent(
        id=f"mc_click_{message_id}_{raw.get('date', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.MIMECAST,
        internet_message_id=message_id,
        url=str(raw.get("url") or ""),
        verdict=classify_verdict(str(raw.get("category") or "")),
        disposition=MIMECAST_CLICK_ACTION_MAP.get(
            str(raw.get("action") or "").lower(), ClickDisposition.PERMITTED
        ),
        sender=str(raw.get("fromUserEmailAddress") or ""),
        recipient=str(raw.get("userEmailAddress") or ""),
        clicked_at=_parse_mimecast_timestamp(raw.get("date")),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Mimecast secret key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:mimecast-secret-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Mimecast MCP server class
# ---------------------------------------------------------------------------
class MimecastMCPServer:
    """Mimecast MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Mimecast API unless explicitly opted out AND a secret key
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "mimecast"

    DEFAULT_APP_ID_REF: str = "${env:BTAGENT_MIMECAST_APP_ID}"
    DEFAULT_APP_KEY_REF: str = "${env:BTAGENT_MIMECAST_APP_KEY}"
    DEFAULT_ACCESS_KEY_REF: str = "${env:BTAGENT_MIMECAST_ACCESS_KEY}"
    DEFAULT_SECRET_KEY_REF: str = "${secret:vault:mimecast/secret_key}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_MIMECAST_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        app_id_ref: str | None = None,
        app_key_ref: str | None = None,
        access_key_ref: str | None = None,
        secret_key_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url or os.getenv("BTAGENT_MIMECAST_API_URL") or "https://api.mimecast.com"
        )
        self._app_id_ref: str = app_id_ref or self.DEFAULT_APP_ID_REF
        self._app_key_ref: str = app_key_ref or self.DEFAULT_APP_KEY_REF
        self._access_key_ref: str = access_key_ref or self.DEFAULT_ACCESS_KEY_REF
        self._secret_key_ref: str = secret_key_ref or self.DEFAULT_SECRET_KEY_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"MimecastMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_secret_key(self) -> str:
        """Resolve the Mimecast secret key lazily from the configured ref."""
        resolved: str = resolve_secret(self._secret_key_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised units."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_mimecast_default"

    # ----- tools -----

    async def mimecast_message_events_search(
        self,
        start: str,
        end: str,
        sender: str | None = None,
        recipient: str | None = None,
        subject_contains: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Mimecast message-tracking events.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            sender: Optional sender-address substring filter.
            recipient: Optional recipient-address substring filter.
            subject_contains: Optional subject substring filter.
            limit: Max events to return.

        Returns:
            Envelope with raw rows + normalised :class:`EmailMessageEvent` list.
        """
        if self.mock_mode:
            return self._mock_message_events_search(
                start, end, sender, recipient, subject_contains, limit
            )
        return await self._real_message_events_search(
            start, end, sender, recipient, subject_contains, limit
        )

    async def mimecast_list_held_messages(
        self,
        start: str | None = None,
        end: str | None = None,
        recipient: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List the Mimecast hold-review (quarantine) queue.

        Args:
            start: Optional ISO-8601 received-at window start (inclusive).
            end: Optional ISO-8601 received-at window end (exclusive).
            recipient: Optional recipient-address substring filter.
            limit: Max messages to return.

        Returns:
            Envelope with raw + normalised :class:`QuarantinedMessage` list.
        """
        if self.mock_mode:
            return self._mock_list_held_messages(start, end, recipient, limit)
        return await self._real_list_held_messages(start, end, recipient, limit)

    async def mimecast_click_logs_search(
        self,
        start: str,
        end: str,
        recipient: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Mimecast URL Protect click logs.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            recipient: Optional recipient-address substring filter.
            action: Optional exact action filter (permit | warn | block).
            limit: Max clicks to return.

        Returns:
            Envelope with raw + normalised :class:`EmailClickEvent` list.
        """
        if self.mock_mode:
            return self._mock_click_logs_search(start, end, recipient, action, limit)
        return await self._real_click_logs_search(start, end, recipient, action, limit)

    # ----- mock implementations -----

    def _mock_message_events_search(
        self,
        start: str,
        end: str,
        sender: str | None,
        recipient: str | None,
        subject_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_mimecast_timestamp(start)
        end_dt = _parse_mimecast_timestamp(end)
        rows: list[dict[str, Any]] = []
        for msg in MIMECAST_FIXTURE_MESSAGES:
            ts = _parse_mimecast_timestamp(msg.get("received"))
            if ts < start_dt or ts >= end_dt:
                continue
            if sender and sender not in str(msg.get("fromEnv") or ""):
                continue
            if recipient and recipient not in str(msg.get("to") or ""):
                continue
            if subject_contains and subject_contains not in str(msg.get("subject") or ""):
                continue
            rows.append(msg)
            if len(rows) >= limit:
                break
        normalised = [normalise_message_event(m, org_id=org_id) for m in rows]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "sender": sender,
            "recipient": recipient,
            "subject_contains": subject_contains,
            "total": len(rows),
            "events_raw": rows,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_list_held_messages(
        self,
        start: str | None,
        end: str | None,
        recipient: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_mimecast_timestamp(start) if start else None
        end_dt = _parse_mimecast_timestamp(end) if end else None
        rows: list[dict[str, Any]] = []
        for held in MIMECAST_FIXTURE_HELD:
            ts = _parse_mimecast_timestamp(held.get("dateReceived"))
            if start_dt is not None and ts < start_dt:
                continue
            if end_dt is not None and ts >= end_dt:
                continue
            if recipient and recipient not in str(held.get("to") or ""):
                continue
            rows.append(held)
            if len(rows) >= limit:
                break
        normalised = [normalise_held_message(m, org_id=org_id) for m in rows]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "recipient": recipient,
            "total": len(rows),
            "messages_raw": rows,
            "messages": [m.model_dump(mode="json") for m in normalised],
        }

    def _mock_click_logs_search(
        self,
        start: str,
        end: str,
        recipient: str | None,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_mimecast_timestamp(start)
        end_dt = _parse_mimecast_timestamp(end)
        rows: list[dict[str, Any]] = []
        for click in MIMECAST_FIXTURE_CLICKS:
            ts = _parse_mimecast_timestamp(click.get("date"))
            if ts < start_dt or ts >= end_dt:
                continue
            if recipient and recipient not in str(click.get("userEmailAddress") or ""):
                continue
            if action and str(click.get("action") or "").lower() != action.lower():
                continue
            rows.append(click)
            if len(rows) >= limit:
                break
        normalised = [normalise_click_event(c, org_id=org_id) for c in rows]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "recipient": recipient,
            "action": action,
            "total": len(rows),
            "clicks_raw": rows,
            "clicks": [c.model_dump(mode="json") for c in normalised],
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_message_events_search(
        self,
        start: str,
        end: str,
        sender: str | None,
        recipient: str | None,
        subject_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "mimecast: live-mode message search refused — no secret key (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Mimecast live mode requires a resolvable secret key (wire "
                "${secret:vault:mimecast/secret_key} or set BTAGENT_MIMECAST_SECRET_KEY)."
            )
        raise NotImplementedError("Mimecast live message_events_search not yet implemented")

    async def _real_list_held_messages(
        self,
        start: str | None,
        end: str | None,
        recipient: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "mimecast: live-mode held-list refused — no secret key (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError("Mimecast live mode requires a resolvable secret key")
        raise NotImplementedError("Mimecast live list_held_messages not yet implemented")

    async def _real_click_logs_search(
        self,
        start: str,
        end: str,
        recipient: str | None,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError("Mimecast live mode requires a resolvable secret key")
        raise NotImplementedError("Mimecast live click_logs_search not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "mimecast_message_events_search",
                "description": (
                    "Search Mimecast message-tracking events for a time window. "
                    "Returns raw rows plus normalised EmailMessageEvent objects "
                    "(verdict none/spam/phish/suspicious/malware; delivery "
                    "outcome) for phishing triage."
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
                "name": "mimecast_list_held_messages",
                "description": (
                    "List the Mimecast hold-review (quarantine) queue with its "
                    "release lifecycle (needs_review / released / denied). "
                    "Returns raw + normalised QuarantinedMessage objects."
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
                "name": "mimecast_click_logs_search",
                "description": (
                    "Search Mimecast URL Protect click logs (permit / warn / "
                    "block). Returns raw rows plus normalised EmailClickEvent "
                    "objects — a permitted click on a phishing/malicious URL is "
                    "the delivered-phish → active-incident signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "recipient": {
                            "type": "string",
                            "description": "Optional recipient-address substring",
                        },
                        "action": {
                            "type": "string",
                            "enum": ["permit", "warn", "block"],
                            "description": "Optional exact click action",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max clicks to return",
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
_server = MimecastMCPServer()


@tool
async def mimecast_message_events_search(
    start: str,
    end: str,
    sender: str | None = None,
    recipient: str | None = None,
    subject_contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Mimecast message-tracking events for a time window.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        sender: Optional sender-address substring.
        recipient: Optional recipient-address substring.
        subject_contains: Optional subject substring.
        limit: Max events to return.
    """
    return await _server.mimecast_message_events_search(
        start, end, sender, recipient, subject_contains, limit
    )


@tool
async def mimecast_list_held_messages(
    start: str | None = None,
    end: str | None = None,
    recipient: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List the Mimecast hold-review (quarantine) queue.

    Args:
        start: Optional ISO-8601 received-at start (inclusive).
        end: Optional ISO-8601 received-at end (exclusive).
        recipient: Optional recipient-address substring.
        limit: Max messages to return.
    """
    return await _server.mimecast_list_held_messages(start, end, recipient, limit)


@tool
async def mimecast_click_logs_search(
    start: str,
    end: str,
    recipient: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Mimecast URL Protect click logs.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        recipient: Optional recipient-address substring.
        action: Optional exact action filter (permit | warn | block).
        limit: Max clicks to return.
    """
    return await _server.mimecast_click_logs_search(start, end, recipient, action, limit)
