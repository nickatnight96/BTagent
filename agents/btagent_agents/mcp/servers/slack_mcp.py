"""Slack MCP server connector — Tier-1 slice (#100, completes the Tier-1 roadmap).

First comms connector ("IC bridge channel — required for Bet 2"). Like the
Jira connector this is a **stateful write surface**: the mock keeps an
in-memory channel/message ledger seeded with one fixture incident channel
and exposes :func:`reset_mock_ledger` for tests.

Capabilities:

- ``slack_create_incident_channel(incident_slug, topic="",
  severity="medium", investigation_id=None)`` — open the incident-commander
  bridge channel (``#inc-<slug>``, Slack-normalised). Channel creation and
  posting are the point of an IC bridge, so neither is HITL-gated — the
  #100 manifest can still opt them into the HITLHook per deployment.
- ``slack_post_message(channel, text, thread_ts=None)`` — post to a channel
  or reply in a thread; returns the message ``ts``.
- ``slack_pin_message(channel, ts)`` — pin a message (the IC status-of-
  record convention).
- ``slack_get_channel_history(channel, limit=50)`` — read messages back,
  newest-first.

Channel-name normalisation (documented so tests and prompts agree)
------------------------------------------------------------------
``incident_slug`` is lowercased; runs of non-alphanumerics collapse to a
single ``-``; the result is prefixed ``inc-`` (unless already so prefixed)
and truncated to Slack's 80-char channel limit. Creating a channel whose
normalised name already exists returns a ``name_taken`` error envelope
carrying the existing name — exactly Slack's behaviour.

Validation is identical to what the live Web API would enforce (blank slug /
text, unknown channels, unknown ``ts``), so swapping in the real API later
doesn't change caller behaviour.

Secret hygiene mirrors the sibling connectors: the bot token is resolved
lazily, never logged (fingerprint only via :func:`_redact_secret`), and
never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import itertools
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.slack")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

VALID_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

# Slack channel names are capped at 80 chars.
_CHANNEL_NAME_MAX = 80
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalise_channel_name(incident_slug: str) -> str:
    """Slack-normalise an incident slug into an ``inc-``-prefixed channel name."""
    slug = _NON_ALNUM.sub("-", (incident_slug or "").lower()).strip("-")
    if not slug:
        return ""
    if not slug.startswith("inc-"):
        slug = f"inc-{slug}"
    return slug[:_CHANNEL_NAME_MAX].rstrip("-")


# ---------------------------------------------------------------------------
# Stateful mock ledger (mirrors jira_mcp.MOCK_TICKET_LEDGER)
# ---------------------------------------------------------------------------

# One seeded bridge channel mid-incident, so history/pin tests have data.
_SEED_CHANNELS: list[dict[str, Any]] = [
    {
        "name": "inc-seed-phish-4471",
        "topic": "IC bridge: invoice #4471 phishing wave",
        "severity": "medium",
        "investigation_id": "inv_seed_phish",
        "created_at": "2026-06-10T08:35:00Z",
        "messages": [
            {
                "ts": "1786000000.000001",
                "text": "Bridge open. IC: @dana. Scope: 3 recipients, 1 delivered.",
                "thread_ts": None,
                "pinned": True,
            },
            {
                "ts": "1786000000.000002",
                "text": "Quarantine purge running for carol@example.com.",
                "thread_ts": None,
                "pinned": False,
            },
        ],
    },
]

MOCK_SLACK_LEDGER: dict[str, dict[str, Any]] = {}
_ts_counter = itertools.count(3)


def reset_mock_ledger() -> None:
    """Restore the mock ledger to its seeded fixture state (test hook)."""
    global _ts_counter
    MOCK_SLACK_LEDGER.clear()
    for seed in _SEED_CHANNELS:
        MOCK_SLACK_LEDGER[seed["name"]] = {
            **seed,
            "messages": [dict(m) for m in seed["messages"]],
        }
    _ts_counter = itertools.count(3)


reset_mock_ledger()


def _next_ts() -> str:
    """Monotonic Slack-shaped message timestamp for the mock ledger."""
    return f"1786000000.{next(_ts_counter):06d}"


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Slack bot token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:slack-bot-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Slack MCP server class
# ---------------------------------------------------------------------------
class SlackMCPServer:
    """Slack MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Slack Web API unless explicitly opted out AND a bot token
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "slack"

    DEFAULT_BOT_TOKEN_REF: str = "${secret:vault:slack/bot_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        workspace_url: str | None = None,
        bot_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.workspace_url: str = (
            workspace_url or os.getenv("BTAGENT_SLACK_WORKSPACE_URL") or "https://acme.slack.com"
        )
        self._bot_token_ref: str = bot_token_ref or self.DEFAULT_BOT_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"SlackMCPServer(server_id={self.server_id!r}, "
            f"workspace_url={self.workspace_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_bot_token(self) -> str:
        """Resolve the bot token lazily from the configured ref."""
        resolved: str = resolve_secret(self._bot_token_ref)
        return resolved

    # ----- tools -----

    async def slack_create_incident_channel(
        self,
        incident_slug: str,
        topic: str = "",
        severity: str = "medium",
        investigation_id: str | None = None,
    ) -> dict[str, Any]:
        """Open the incident-commander bridge channel.

        Args:
            incident_slug: Human slug; normalised to ``#inc-<slug>``.
            topic: Channel topic (IC, scope, severity).
            severity: critical | high | medium | low.
            investigation_id: Optional BTagent investigation to link.

        Returns:
            Envelope with the normalised channel name, or a ``name_taken``
            error when the channel already exists.
        """
        if self.mock_mode:
            return self._mock_create_incident_channel(
                incident_slug, topic, severity, investigation_id
            )
        return await self._real_create_incident_channel(
            incident_slug, topic, severity, investigation_id
        )

    async def slack_post_message(
        self,
        channel: str,
        text: str,
        thread_ts: str | None = None,
    ) -> dict[str, Any]:
        """Post a message to a channel, or reply in a thread.

        Args:
            channel: Channel name (with or without leading "#").
            text: Message text (required, non-blank).
            thread_ts: Optional parent message ``ts`` to reply under.

        Returns:
            Envelope with the new message ``ts``.
        """
        if self.mock_mode:
            return self._mock_post_message(channel, text, thread_ts)
        return await self._real_post_message(channel, text, thread_ts)

    async def slack_pin_message(self, channel: str, ts: str) -> dict[str, Any]:
        """Pin a message — the IC status-of-record convention.

        Args:
            channel: Channel name.
            ts: The message ``ts`` to pin.

        Returns:
            Envelope confirming the pin.
        """
        if self.mock_mode:
            return self._mock_pin_message(channel, ts)
        return await self._real_pin_message(channel, ts)

    async def slack_get_channel_history(self, channel: str, limit: int = 50) -> dict[str, Any]:
        """Read a channel's messages back, newest-first.

        Args:
            channel: Channel name.
            limit: Max messages to return.

        Returns:
            Envelope with the messages (ts, text, thread_ts, pinned).
        """
        if self.mock_mode:
            return self._mock_get_channel_history(channel, limit)
        return await self._real_get_channel_history(channel, limit)

    # ----- mock implementations -----

    @staticmethod
    def _channel(name: str) -> dict[str, Any] | None:
        return MOCK_SLACK_LEDGER.get(name.lstrip("#"))

    def _mock_create_incident_channel(
        self,
        incident_slug: str,
        topic: str,
        severity: str,
        investigation_id: str | None,
    ) -> dict[str, Any]:
        name = normalise_channel_name(incident_slug)
        if not name:
            return {
                "status": "error",
                "is_mock": True,
                "message": "incident_slug must contain at least one alphanumeric character",
            }
        if severity not in VALID_SEVERITIES:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid severity {severity!r} ({'|'.join(VALID_SEVERITIES)})",
            }
        if name in MOCK_SLACK_LEDGER:
            return {
                "status": "name_taken",
                "is_mock": True,
                "channel": name,
                "message": f"Channel '#{name}' already exists",
            }
        MOCK_SLACK_LEDGER[name] = {
            "name": name,
            "topic": topic,
            "severity": severity,
            "investigation_id": investigation_id,
            "created_at": _utcnow_iso(),
            "messages": [],
        }
        logger.info("slack mock: created #%s (%s)", name, severity)
        return {"status": "success", "is_mock": True, "channel": name}

    def _mock_post_message(self, channel: str, text: str, thread_ts: str | None) -> dict[str, Any]:
        chan = self._channel(channel)
        if chan is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Channel '{channel}' not found",
            }
        if not text or not text.strip():
            return {"status": "error", "is_mock": True, "message": "text must be non-blank"}
        if thread_ts is not None and not any(m["ts"] == thread_ts for m in chan["messages"]):
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"thread_ts '{thread_ts}' not found in '#{chan['name']}'",
            }
        ts = _next_ts()
        chan["messages"].append(
            {"ts": ts, "text": text.strip(), "thread_ts": thread_ts, "pinned": False}
        )
        return {"status": "success", "is_mock": True, "channel": chan["name"], "ts": ts}

    def _mock_pin_message(self, channel: str, ts: str) -> dict[str, Any]:
        chan = self._channel(channel)
        if chan is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Channel '{channel}' not found",
            }
        for message in chan["messages"]:
            if message["ts"] == ts:
                message["pinned"] = True
                return {
                    "status": "success",
                    "is_mock": True,
                    "channel": chan["name"],
                    "ts": ts,
                }
        return {
            "status": "not_found",
            "is_mock": True,
            "message": f"Message ts '{ts}' not found in '#{chan['name']}'",
        }

    def _mock_get_channel_history(self, channel: str, limit: int) -> dict[str, Any]:
        chan = self._channel(channel)
        if chan is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Channel '{channel}' not found",
            }
        messages = sorted(chan["messages"], key=lambda m: m["ts"], reverse=True)[:limit]
        return {
            "status": "success",
            "is_mock": True,
            "channel": chan["name"],
            "topic": chan["topic"],
            "total": len(messages),
            "messages": messages,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_create_incident_channel(
        self,
        incident_slug: str,
        topic: str,
        severity: str,
        investigation_id: str | None,
    ) -> dict[str, Any]:
        token = self._get_bot_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "slack: live-mode channel create refused — no bot token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "Slack live mode requires a resolvable bot token (wire "
                "${secret:vault:slack/bot_token} or set BTAGENT_SLACK_BOT_TOKEN)."
            )
        raise NotImplementedError("Slack live create_incident_channel not yet implemented")

    async def _real_post_message(
        self, channel: str, text: str, thread_ts: str | None
    ) -> dict[str, Any]:
        token = self._get_bot_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "slack: live-mode post refused — no bot token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError("Slack live mode requires a resolvable bot token")
        raise NotImplementedError("Slack live post_message not yet implemented")

    async def _real_pin_message(self, channel: str, ts: str) -> dict[str, Any]:
        token = self._get_bot_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Slack live mode requires a resolvable bot token")
        raise NotImplementedError("Slack live pin_message not yet implemented")

    async def _real_get_channel_history(self, channel: str, limit: int) -> dict[str, Any]:
        token = self._get_bot_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Slack live mode requires a resolvable bot token")
        raise NotImplementedError("Slack live get_channel_history not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "slack_create_incident_channel",
                "description": (
                    "Open the incident-commander bridge channel "
                    "(#inc-<slug>, Slack-normalised) for an incident, "
                    "optionally linked to a BTagent investigation."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "incident_slug": {
                            "type": "string",
                            "description": "Human slug; normalised to #inc-<slug>",
                        },
                        "topic": {"type": "string", "description": "Channel topic"},
                        "severity": {
                            "type": "string",
                            "enum": list(VALID_SEVERITIES),
                            "default": "medium",
                        },
                        "investigation_id": {
                            "type": "string",
                            "description": "Optional BTagent investigation id to link",
                        },
                    },
                    "required": ["incident_slug"],
                },
            },
            {
                "name": "slack_post_message",
                "description": (
                    "Post a message to a Slack channel, or reply in a thread "
                    "via thread_ts. Returns the message ts."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel name"},
                        "text": {"type": "string", "description": "Message text"},
                        "thread_ts": {
                            "type": "string",
                            "description": "Optional parent message ts to reply under",
                        },
                    },
                    "required": ["channel", "text"],
                },
            },
            {
                "name": "slack_pin_message",
                "description": (
                    "Pin a message in a channel — the IC status-of-record "
                    "convention for bridge channels."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel name"},
                        "ts": {"type": "string", "description": "Message ts to pin"},
                    },
                    "required": ["channel", "ts"],
                },
            },
            {
                "name": "slack_get_channel_history",
                "description": "Read a Slack channel's messages back, newest-first.",
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel name"},
                        "limit": {
                            "type": "integer",
                            "description": "Max messages to return",
                            "default": 50,
                        },
                    },
                    "required": ["channel"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = SlackMCPServer()


@tool
async def slack_create_incident_channel(
    incident_slug: str,
    topic: str = "",
    severity: str = "medium",
    investigation_id: str | None = None,
) -> dict[str, Any]:
    """Open the incident-commander bridge channel (#inc-<slug>).

    Args:
        incident_slug: Human slug; normalised to #inc-<slug>.
        topic: Channel topic (IC, scope, severity).
        severity: critical | high | medium | low.
        investigation_id: Optional BTagent investigation id to link.
    """
    return await _server.slack_create_incident_channel(
        incident_slug, topic, severity, investigation_id
    )


@tool
async def slack_post_message(
    channel: str,
    text: str,
    thread_ts: str | None = None,
) -> dict[str, Any]:
    """Post a message to a Slack channel or thread.

    Args:
        channel: Channel name (with or without leading "#").
        text: Message text.
        thread_ts: Optional parent message ts to reply under.
    """
    return await _server.slack_post_message(channel, text, thread_ts)


@tool
async def slack_pin_message(channel: str, ts: str) -> dict[str, Any]:
    """Pin a message in a Slack channel (IC status-of-record).

    Args:
        channel: Channel name.
        ts: Message ts to pin.
    """
    return await _server.slack_pin_message(channel, ts)


@tool
async def slack_get_channel_history(channel: str, limit: int = 50) -> dict[str, Any]:
    """Read a Slack channel's messages back, newest-first.

    Args:
        channel: Channel name.
        limit: Max messages to return.
    """
    return await _server.slack_get_channel_history(channel, limit)
