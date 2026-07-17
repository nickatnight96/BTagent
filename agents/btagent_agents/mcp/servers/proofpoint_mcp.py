"""Proofpoint TAP MCP server connector — Tier-2 slice (#100).

Second email-security connector after Defender for O365, and the first
email-gateway connector. Surfaces three capabilities to the agent layer; both
raw provider JSON and normalised :mod:`btagent_shared.types.email_hunt` objects
are returned so phishing-triage detectors reason over one schema regardless of
vendor.

Capabilities:

- ``pfpt_message_events_search(start, end, sender=None, recipient=None,
  subject_contains=None, limit=100)`` — TAP SIEM messagesDelivered /
  messagesBlocked rows normalised to :class:`EmailMessageEvent` (verdict from
  ``threatsInfoMap.classification``; delivery action from disposition).
- ``pfpt_click_events_search(start, end, recipient=None, disposition=None,
  limit=100)`` — TAP SIEM clicksPermitted / clicksBlocked rows normalised to
  :class:`EmailClickEvent`. A ``permitted`` click on a ``phish`` / ``malware``
  URL is the delivered-phish → active-incident signal.
- ``pfpt_vap_summary(start, end)`` — Very-Attacked-People rollup by recipient:
  message counts by verdict, permitted-click count, campaigns seen — the "who
  is being targeted, and did anyone click" triage signal (a pure computed
  rollup, mirroring ``aws_cloudtrail_principal_summary``).

Design notes mirror the Defender O365 connector: mock-first
(``BTAGENT_MOCK_CONNECTORS=true``), lazy ``${secret:…}`` service-principal
credential resolution, guarded live mode, pure normalisers, and secret hygiene
(the TAP service secret is never logged / never returned in envelopes; the
fingerprint helper only emits a short suffix).

Verdict mapping
---------------
Proofpoint ``classification`` is one of ``malware`` / ``phish`` / ``spam`` /
``impostor`` (BEC). Precedence Malware > Phish > Impostor > Spam. Proofpoint
does not distinguish a "high confidence phish" tier, so ``phish`` maps to
:data:`EmailThreatVerdict.PHISH`. Empty threat maps map to NONE.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.email_hunt import (
    ClickDisposition,
    EmailClickEvent,
    EmailDeliveryAction,
    EmailMessageEvent,
    EmailSecurityProvider,
    EmailThreatVerdict,
)
from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._proofpoint_fixtures import (
    PFPT_FIXTURE_CLICKS,
    PFPT_FIXTURE_MESSAGES,
)

logger = logging.getLogger("btagent.mcp.servers.proofpoint")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Provider string → enum maps (exact match on Proofpoint's classifications)
# ---------------------------------------------------------------------------

PFPT_DISPOSITION_MAP: dict[str, EmailDeliveryAction] = {
    "delivered": EmailDeliveryAction.DELIVERED,
    "blocked": EmailDeliveryAction.BLOCKED,
}

PFPT_CLICK_DISPOSITION_MAP: dict[str, ClickDisposition] = {
    "permitted": ClickDisposition.PERMITTED,
    "blocked": ClickDisposition.BLOCKED,
}


def _parse_pfpt_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("proofpoint: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def classify_verdict(classifications: list[str]) -> EmailThreatVerdict:
    """Map Proofpoint ``classification`` values to a verdict.

    Precedence Malware > Phish > Impostor > Spam; empty maps to NONE.
    """
    types = {c.strip().lower() for c in classifications if c and c.strip()}
    if "malware" in types:
        return EmailThreatVerdict.MALWARE
    if "phish" in types:
        return EmailThreatVerdict.PHISH
    if "impostor" in types:
        return EmailThreatVerdict.SUSPICIOUS
    if "spam" in types:
        return EmailThreatVerdict.SPAM
    return EmailThreatVerdict.NONE


def _first_recipient(raw: dict[str, Any]) -> str:
    """Proofpoint ``recipient`` is a list on messages, a scalar on clicks."""
    recipient = raw.get("recipient")
    if isinstance(recipient, list):
        return str(recipient[0]) if recipient else ""
    return str(recipient or "")


def normalise_message_event(raw: dict[str, Any], *, org_id: str) -> EmailMessageEvent:
    """Map one Proofpoint TAP message row to :class:`EmailMessageEvent`."""
    message_id = str(raw.get("messageID") or "")
    threats = raw.get("threatsInfoMap") or []
    classifications = [str(t.get("classification") or "") for t in threats]
    threat_names = [str(t.get("threat") or "") for t in threats if t.get("threat")]
    return EmailMessageEvent(
        id=f"pfpt_evt_{message_id or raw.get('messageTime', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.PROOFPOINT,
        internet_message_id=message_id,
        timestamp=_parse_pfpt_timestamp(raw.get("messageTime")),
        sender=str(raw.get("sender") or raw.get("fromAddress") or ""),
        sender_ip=str(raw.get("senderIP") or ""),
        recipient=_first_recipient(raw),
        subject=str(raw.get("subject") or ""),
        verdict=classify_verdict(classifications),
        delivery_action=PFPT_DISPOSITION_MAP.get(
            str(raw.get("_disposition") or ""), EmailDeliveryAction.UNKNOWN
        ),
        threat_names=threat_names,
        url_count=sum(1 for t in threats if t.get("threatType") == "url"),
        attachment_count=sum(1 for t in threats if t.get("threatType") == "attachment"),
        raw=raw,
    )


def normalise_click_event(raw: dict[str, Any], *, org_id: str) -> EmailClickEvent:
    """Map one Proofpoint TAP click row to :class:`EmailClickEvent`."""
    message_id = str(raw.get("messageID") or "")
    return EmailClickEvent(
        id=f"pfpt_click_{message_id}_{raw.get('clickTime', '')}"[:200],
        org_id=org_id,
        provider=EmailSecurityProvider.PROOFPOINT,
        internet_message_id=message_id,
        url=str(raw.get("url") or ""),
        verdict=classify_verdict([str(raw.get("classification") or "")]),
        disposition=PFPT_CLICK_DISPOSITION_MAP.get(
            str(raw.get("_disposition") or ""), ClickDisposition.PERMITTED
        ),
        sender=str(raw.get("sender") or ""),
        recipient=_first_recipient(raw),
        sender_ip=str(raw.get("senderIP") or ""),
        campaign_id=str(raw.get("campaignId") or ""),
        clicked_at=_parse_pfpt_timestamp(raw.get("clickTime")),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the TAP service secret.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:proofpoint-service-secret:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Proofpoint TAP MCP server class
# ---------------------------------------------------------------------------
class ProofpointMCPServer:
    """Proofpoint TAP MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the TAP API unless explicitly opted out AND a service secret
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "proofpoint"

    DEFAULT_SERVICE_PRINCIPAL_REF: str = "${env:BTAGENT_PROOFPOINT_SERVICE_PRINCIPAL}"
    DEFAULT_SERVICE_SECRET_REF: str = "${secret:vault:proofpoint/service_secret}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_PROOFPOINT_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        service_principal_ref: str | None = None,
        service_secret_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url
            or os.getenv("BTAGENT_PROOFPOINT_API_URL")
            or "https://tap-api-v2.proofpoint.com"
        )
        self._service_principal_ref: str = (
            service_principal_ref or self.DEFAULT_SERVICE_PRINCIPAL_REF
        )
        self._service_secret_ref: str = service_secret_ref or self.DEFAULT_SERVICE_SECRET_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"ProofpointMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_service_secret(self) -> str:
        """Resolve the TAP service secret lazily from the configured ref."""
        resolved: str = resolve_secret(self._service_secret_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised units."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_proofpoint_default"

    # ----- tools -----

    async def pfpt_message_events_search(
        self,
        start: str,
        end: str,
        sender: str | None = None,
        recipient: str | None = None,
        subject_contains: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Proofpoint TAP message events (delivered + blocked).

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            sender: Optional sender-address substring filter.
            recipient: Optional recipient-address substring filter.
            subject_contains: Optional subject substring filter.
            limit: Max events to return.

        Returns:
            Envelope with raw provider rows and normalised
            :class:`EmailMessageEvent` list.
        """
        if self.mock_mode:
            return self._mock_message_events_search(
                start, end, sender, recipient, subject_contains, limit
            )
        return await self._real_message_events_search(
            start, end, sender, recipient, subject_contains, limit
        )

    async def pfpt_click_events_search(
        self,
        start: str,
        end: str,
        recipient: str | None = None,
        disposition: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Proofpoint TAP URL-click events (permitted + blocked).

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            recipient: Optional recipient-address substring filter.
            disposition: Optional exact filter (permitted | blocked).
            limit: Max clicks to return.

        Returns:
            Envelope with raw rows and normalised :class:`EmailClickEvent`
            list.
        """
        if self.mock_mode:
            return self._mock_click_events_search(start, end, recipient, disposition, limit)
        return await self._real_click_events_search(start, end, recipient, disposition, limit)

    async def pfpt_vap_summary(self, start: str, end: str) -> dict[str, Any]:
        """Very-Attacked-People rollup by recipient over the window.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with per-recipient message counts by verdict, permitted-
            click count, and campaigns seen — the targeting + did-anyone-click
            triage signal.
        """
        if self.mock_mode:
            return self._mock_vap_summary(start, end)
        return await self._real_vap_summary(start, end)

    # ----- mock implementations -----

    def _messages_in_window(self, start: str, end: str) -> list[dict[str, Any]]:
        start_dt = _parse_pfpt_timestamp(start)
        end_dt = _parse_pfpt_timestamp(end)
        return [
            m
            for m in PFPT_FIXTURE_MESSAGES
            if start_dt <= _parse_pfpt_timestamp(m.get("messageTime")) < end_dt
        ]

    def _clicks_in_window(self, start: str, end: str) -> list[dict[str, Any]]:
        start_dt = _parse_pfpt_timestamp(start)
        end_dt = _parse_pfpt_timestamp(end)
        return [
            c
            for c in PFPT_FIXTURE_CLICKS
            if start_dt <= _parse_pfpt_timestamp(c.get("clickTime")) < end_dt
        ]

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
        rows: list[dict[str, Any]] = []
        for msg in self._messages_in_window(start, end):
            if sender and sender not in str(msg.get("sender") or ""):
                continue
            if recipient and recipient not in _first_recipient(msg):
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

    def _mock_click_events_search(
        self,
        start: str,
        end: str,
        recipient: str | None,
        disposition: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        rows: list[dict[str, Any]] = []
        for click in self._clicks_in_window(start, end):
            if recipient and recipient not in _first_recipient(click):
                continue
            if disposition and str(click.get("_disposition") or "") != disposition:
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
            "disposition": disposition,
            "total": len(rows),
            "clicks_raw": rows,
            "clicks": [c.model_dump(mode="json") for c in normalised],
        }

    def _mock_vap_summary(self, start: str, end: str) -> dict[str, Any]:
        org_id = self._get_org_id()
        messages = [
            normalise_message_event(m, org_id=org_id) for m in self._messages_in_window(start, end)
        ]
        clicks = [
            normalise_click_event(c, org_id=org_id) for c in self._clicks_in_window(start, end)
        ]
        recipients: dict[str, dict[str, Any]] = {}
        for ev in messages:
            entry = recipients.setdefault(
                ev.recipient,
                {
                    "recipient": ev.recipient,
                    "verdict_counts": Counter(),
                    "permitted_clicks": 0,
                    "campaigns": set(),
                },
            )
            entry["verdict_counts"][ev.verdict.value] += 1
        for c in clicks:
            entry = recipients.setdefault(
                c.recipient,
                {
                    "recipient": c.recipient,
                    "verdict_counts": Counter(),
                    "permitted_clicks": 0,
                    "campaigns": set(),
                },
            )
            if c.disposition is ClickDisposition.PERMITTED:
                entry["permitted_clicks"] += 1
            if c.campaign_id:
                entry["campaigns"].add(c.campaign_id)
        vap = [
            {
                "recipient": r["recipient"],
                "verdict_counts": dict(r["verdict_counts"]),
                "permitted_clicks": r["permitted_clicks"],
                "campaigns": sorted(r["campaigns"]),
            }
            for r in recipients.values()
        ]
        # Most-attacked first: permitted clicks, then total malicious messages.
        vap.sort(
            key=lambda r: (
                r["permitted_clicks"],
                sum(v for k, v in r["verdict_counts"].items() if k != "none"),
            ),
            reverse=True,
        )
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "total_recipients": len(vap),
            "vap": vap,
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
        secret = self._get_service_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "proofpoint: live-mode message-events search refused — no service secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Proofpoint live mode requires a resolvable TAP service secret "
                "(wire ${secret:vault:proofpoint/service_secret} or set "
                "BTAGENT_PROOFPOINT_SERVICE_SECRET)."
            )
        raise NotImplementedError("Proofpoint live message_events_search not yet implemented")

    async def _real_click_events_search(
        self,
        start: str,
        end: str,
        recipient: str | None,
        disposition: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_service_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "proofpoint: live-mode click-events search refused — no service secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Proofpoint live mode requires a resolvable TAP service secret"
            )
        raise NotImplementedError("Proofpoint live click_events_search not yet implemented")

    async def _real_vap_summary(self, start: str, end: str) -> dict[str, Any]:
        secret = self._get_service_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError(
                "Proofpoint live mode requires a resolvable TAP service secret"
            )
        raise NotImplementedError("Proofpoint live vap_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "pfpt_message_events_search",
                "description": (
                    "Search Proofpoint TAP message events (delivered + blocked) "
                    "for a time window. Returns raw rows plus normalised "
                    "EmailMessageEvent objects (verdict none/spam/phish/"
                    "suspicious/malware; delivery outcome) for phishing triage."
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
                "name": "pfpt_click_events_search",
                "description": (
                    "Search Proofpoint TAP URL-click events (permitted + "
                    "blocked). Returns raw rows plus normalised EmailClickEvent "
                    "objects — a permitted click on a phish/malware URL is the "
                    "delivered-phish → active-incident signal."
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
                        "disposition": {
                            "type": "string",
                            "enum": ["permitted", "blocked"],
                            "description": "Optional exact click disposition",
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
            {
                "name": "pfpt_vap_summary",
                "description": (
                    "Very-Attacked-People rollup by recipient over a window: "
                    "message counts by verdict, permitted-click count, and "
                    "campaigns seen — the who-is-targeted and did-anyone-click "
                    "triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                    },
                    "required": ["start", "end"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = ProofpointMCPServer()


@tool
async def pfpt_message_events_search(
    start: str,
    end: str,
    sender: str | None = None,
    recipient: str | None = None,
    subject_contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Proofpoint TAP message events (delivered + blocked).

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        sender: Optional sender-address substring.
        recipient: Optional recipient-address substring.
        subject_contains: Optional subject substring.
        limit: Max events to return.
    """
    return await _server.pfpt_message_events_search(
        start, end, sender, recipient, subject_contains, limit
    )


@tool
async def pfpt_click_events_search(
    start: str,
    end: str,
    recipient: str | None = None,
    disposition: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Proofpoint TAP URL-click events (permitted + blocked).

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        recipient: Optional recipient-address substring.
        disposition: Optional exact filter (permitted | blocked).
        limit: Max clicks to return.
    """
    return await _server.pfpt_click_events_search(start, end, recipient, disposition, limit)


@tool
async def pfpt_vap_summary(start: str, end: str) -> dict[str, Any]:
    """Very-Attacked-People rollup by recipient over a window.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.pfpt_vap_summary(start, end)
