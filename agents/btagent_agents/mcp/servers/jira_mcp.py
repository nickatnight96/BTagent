"""Jira Service Management MCP server connector — Tier-1 slice (#100).

First ticketing connector ("IR ticket sink for ~60% of mid-market"). Built in
the modern Tier-1 style (lazy ``${secret:…}`` resolution, guarded live mode,
full contract tests) — but unlike the telemetry connectors this is a
**stateful write surface**, so the mock keeps an in-memory ticket ledger
(mirroring the Git connector's ``MOCK_PR_LEDGER`` precedent) seeded with two
fixture tickets and exposes :func:`reset_mock_ledger` for tests.

Capabilities:

- ``jira_create_incident(summary, description, severity="medium",
  investigation_id=None, labels=None)`` — open an IR ticket in the security
  project. Ticket creation is the canonical automated sink action (low blast
  radius, fully reversible via close), so it is **not** HITL-gated — the
  #100 manifest can still opt it into the HITLHook per deployment.
- ``jira_add_comment(issue_key, body)`` — append a comment.
- ``jira_transition_issue(issue_key, transition)`` — drive the workflow
  state machine (see :data:`JIRA_TRANSITIONS`); invalid transitions return
  an error envelope naming the legal moves from the current status.
- ``jira_get_issue(issue_key)`` — read a ticket back (fields + comments +
  transition history).

Workflow state machine (documented so tests and prompts agree)
--------------------------------------------------------------
Statuses: ``new`` → ``in_progress`` → ``resolved`` → ``closed``.
Transitions: ``start`` (new → in_progress), ``resolve`` (in_progress →
resolved), ``close`` (resolved → closed), ``reopen`` (resolved | closed →
in_progress). Anything else is rejected with the legal moves listed.

Validation is identical to what a live Jira would enforce (empty summary /
comment body, unknown issue keys), so swapping in the real API later doesn't
change caller behaviour.

Secret hygiene mirrors the sibling connectors: the Jira API token is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import itertools
import logging
import os
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.jira")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

VALID_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

# Workflow state machine: transition name -> (allowed source statuses, target).
JIRA_TRANSITIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "start": (("new",), "in_progress"),
    "resolve": (("in_progress",), "resolved"),
    "close": (("resolved",), "closed"),
    "reopen": (("resolved", "closed"), "in_progress"),
}

# ---------------------------------------------------------------------------
# Stateful mock ledger (mirrors git_mcp.MOCK_PR_LEDGER)
# ---------------------------------------------------------------------------

# Seeded fixture tickets: one mid-workflow phishing incident and one closed
# malware incident, so read/transition tests have history to assert against.
_SEED_TICKETS: list[dict[str, Any]] = [
    {
        "key": "SEC-100",
        "summary": "Malware blocked on WS-JSMITH-PC (Trojan payload via certutil)",
        "description": "Defender blocked certutil-downloaded payload; host scanned clean.",
        "severity": "high",
        "status": "closed",
        "investigation_id": "inv_seed_malware",
        "labels": ["malware", "edr"],
        "created_at": "2026-06-01T10:00:00Z",
        "updated_at": "2026-06-03T09:00:00Z",
        "comments": [
            {"body": "Host isolated and reimaged.", "created_at": "2026-06-02T15:00:00Z"},
        ],
        "history": ["start", "resolve", "close"],
    },
    {
        "key": "SEC-101",
        "summary": "Phishing campaign: invoice #4471 wave hitting finance",
        "description": "Three recipients; one delivered. Quarantine + purge in progress.",
        "severity": "medium",
        "status": "in_progress",
        "investigation_id": "inv_seed_phish",
        "labels": ["phishing", "email"],
        "created_at": "2026-06-10T08:30:00Z",
        "updated_at": "2026-06-10T09:00:00Z",
        "comments": [],
        "history": ["start"],
    },
]

# Live ledger state — reset via reset_mock_ledger().
MOCK_TICKET_LEDGER: dict[str, dict[str, Any]] = {}
_ticket_counter = itertools.count(102)


def reset_mock_ledger() -> None:
    """Restore the mock ledger to its seeded fixture state (test hook)."""
    global _ticket_counter
    MOCK_TICKET_LEDGER.clear()
    for seed in _SEED_TICKETS:
        # Deep-enough copy: comments/history/labels are mutated in place.
        MOCK_TICKET_LEDGER[seed["key"]] = {
            **seed,
            "labels": list(seed["labels"]),
            "comments": [dict(c) for c in seed["comments"]],
            "history": list(seed["history"]),
        }
    _ticket_counter = itertools.count(102)


reset_mock_ledger()


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Jira API token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:jira-api-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Jira Service Management MCP server class
# ---------------------------------------------------------------------------
class JiraMCPServer:
    """Jira Service Management MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls a Jira site unless explicitly opted out AND an API token
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "jira"

    DEFAULT_API_TOKEN_REF: str = "${secret:vault:jira/api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        base_url: str | None = None,
        project_key: str | None = None,
        api_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.base_url: str = (
            base_url or os.getenv("BTAGENT_JIRA_URL") or "https://acme.atlassian.net"
        )
        self.project_key: str = project_key or os.getenv("BTAGENT_JIRA_PROJECT") or "SEC"
        self._api_token_ref: str = api_token_ref or self.DEFAULT_API_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"JiraMCPServer(server_id={self.server_id!r}, base_url={self.base_url!r}, "
            f"project_key={self.project_key!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the Jira API token lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_token_ref)
        return resolved

    # ----- tools -----

    async def jira_create_incident(
        self,
        summary: str,
        description: str = "",
        severity: str = "medium",
        investigation_id: str | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Open an IR ticket in the security project.

        Args:
            summary: One-line ticket summary (required, non-blank).
            description: Longer body.
            severity: critical | high | medium | low.
            investigation_id: Optional BTagent investigation to link.
            labels: Optional label list.

        Returns:
            Envelope with the created issue key + ticket fields.
        """
        if self.mock_mode:
            return self._mock_create_incident(
                summary, description, severity, investigation_id, labels
            )
        return await self._real_create_incident(
            summary, description, severity, investigation_id, labels
        )

    async def jira_add_comment(self, issue_key: str, body: str) -> dict[str, Any]:
        """Append a comment to a ticket.

        Args:
            issue_key: The ticket key (e.g. "SEC-101").
            body: Comment text (required, non-blank).

        Returns:
            Envelope with the updated comment count.
        """
        if self.mock_mode:
            return self._mock_add_comment(issue_key, body)
        return await self._real_add_comment(issue_key, body)

    async def jira_transition_issue(self, issue_key: str, transition: str) -> dict[str, Any]:
        """Drive a ticket through the workflow state machine.

        Args:
            issue_key: The ticket key.
            transition: start | resolve | close | reopen.

        Returns:
            Envelope with the previous and new status; invalid transitions
            return an error envelope naming the legal moves.
        """
        if self.mock_mode:
            return self._mock_transition_issue(issue_key, transition)
        return await self._real_transition_issue(issue_key, transition)

    async def jira_get_issue(self, issue_key: str) -> dict[str, Any]:
        """Read a ticket back (fields + comments + transition history).

        Args:
            issue_key: The ticket key.

        Returns:
            Envelope with the full ticket or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_get_issue(issue_key)
        return await self._real_get_issue(issue_key)

    # ----- mock implementations -----

    def _mock_create_incident(
        self,
        summary: str,
        description: str,
        severity: str,
        investigation_id: str | None,
        labels: list[str] | None,
    ) -> dict[str, Any]:
        if not summary or not summary.strip():
            return {"status": "error", "is_mock": True, "message": "summary must be non-blank"}
        if severity not in VALID_SEVERITIES:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid severity {severity!r} ({'|'.join(VALID_SEVERITIES)})",
            }
        key = f"{self.project_key}-{next(_ticket_counter)}"
        now = _utcnow_iso()
        ticket = {
            "key": key,
            "summary": summary.strip(),
            "description": description,
            "severity": severity,
            "status": "new",
            "investigation_id": investigation_id,
            "labels": list(labels or []),
            "created_at": now,
            "updated_at": now,
            "comments": [],
            "history": [],
        }
        MOCK_TICKET_LEDGER[key] = ticket
        logger.info("jira mock: created %s (%s)", key, severity)
        return {"status": "success", "is_mock": True, "issue_key": key, "ticket": ticket}

    def _mock_add_comment(self, issue_key: str, body: str) -> dict[str, Any]:
        ticket = MOCK_TICKET_LEDGER.get(issue_key)
        if ticket is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Issue '{issue_key}' not found",
            }
        if not body or not body.strip():
            return {"status": "error", "is_mock": True, "message": "comment body must be non-blank"}
        ticket["comments"].append({"body": body.strip(), "created_at": _utcnow_iso()})
        ticket["updated_at"] = _utcnow_iso()
        return {
            "status": "success",
            "is_mock": True,
            "issue_key": issue_key,
            "comment_count": len(ticket["comments"]),
        }

    def _mock_transition_issue(self, issue_key: str, transition: str) -> dict[str, Any]:
        ticket = MOCK_TICKET_LEDGER.get(issue_key)
        if ticket is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Issue '{issue_key}' not found",
            }
        spec = JIRA_TRANSITIONS.get(transition)
        current = ticket["status"]
        if spec is None or current not in spec[0]:
            legal = [name for name, (sources, _t) in JIRA_TRANSITIONS.items() if current in sources]
            return {
                "status": "error",
                "is_mock": True,
                "message": (
                    f"Transition {transition!r} not legal from status {current!r}; "
                    f"legal transitions: {legal or ['<none>']}"
                ),
            }
        ticket["status"] = spec[1]
        ticket["history"].append(transition)
        ticket["updated_at"] = _utcnow_iso()
        return {
            "status": "success",
            "is_mock": True,
            "issue_key": issue_key,
            "previous_status": current,
            "new_status": spec[1],
        }

    def _mock_get_issue(self, issue_key: str) -> dict[str, Any]:
        ticket = MOCK_TICKET_LEDGER.get(issue_key)
        if ticket is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Issue '{issue_key}' not found",
            }
        return {"status": "success", "is_mock": True, "ticket": ticket}

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_create_incident(
        self,
        summary: str,
        description: str,
        severity: str,
        investigation_id: str | None,
        labels: list[str] | None,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "jira: live-mode create refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "Jira live mode requires a resolvable API token (wire "
                "${secret:vault:jira/api_token} or set BTAGENT_JIRA_API_TOKEN)."
            )
        raise NotImplementedError("Jira live create_incident not yet implemented")

    async def _real_add_comment(self, issue_key: str, body: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "jira: live-mode comment refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError("Jira live mode requires a resolvable API token")
        raise NotImplementedError("Jira live add_comment not yet implemented")

    async def _real_transition_issue(self, issue_key: str, transition: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Jira live mode requires a resolvable API token")
        raise NotImplementedError("Jira live transition_issue not yet implemented")

    async def _real_get_issue(self, issue_key: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Jira live mode requires a resolvable API token")
        raise NotImplementedError("Jira live get_issue not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "jira_create_incident",
                "description": (
                    "Open an incident-response ticket in the Jira Service "
                    "Management security project, optionally linked to a "
                    "BTagent investigation."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string", "description": "One-line summary"},
                        "description": {"type": "string", "description": "Ticket body"},
                        "severity": {
                            "type": "string",
                            "enum": list(VALID_SEVERITIES),
                            "default": "medium",
                        },
                        "investigation_id": {
                            "type": "string",
                            "description": "Optional BTagent investigation id to link",
                        },
                        "labels": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional labels",
                        },
                    },
                    "required": ["summary"],
                },
            },
            {
                "name": "jira_add_comment",
                "description": "Append a comment to an existing Jira ticket.",
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string", "description": "Ticket key (SEC-101)"},
                        "body": {"type": "string", "description": "Comment text"},
                    },
                    "required": ["issue_key", "body"],
                },
            },
            {
                "name": "jira_transition_issue",
                "description": (
                    "Drive a Jira ticket through the IR workflow: start (new "
                    "→ in_progress), resolve, close, reopen. Invalid "
                    "transitions return the legal moves."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string", "description": "Ticket key"},
                        "transition": {
                            "type": "string",
                            "enum": sorted(JIRA_TRANSITIONS),
                            "description": "Workflow transition",
                        },
                    },
                    "required": ["issue_key", "transition"],
                },
            },
            {
                "name": "jira_get_issue",
                "description": (
                    "Read a Jira ticket back: fields, comments, and the transition history."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string", "description": "Ticket key"},
                    },
                    "required": ["issue_key"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = JiraMCPServer()


@tool
async def jira_create_incident(
    summary: str,
    description: str = "",
    severity: str = "medium",
    investigation_id: str | None = None,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Open an IR ticket in the Jira Service Management security project.

    Args:
        summary: One-line ticket summary.
        description: Longer body.
        severity: critical | high | medium | low.
        investigation_id: Optional BTagent investigation id to link.
        labels: Optional label list.
    """
    return await _server.jira_create_incident(
        summary, description, severity, investigation_id, labels
    )


@tool
async def jira_add_comment(issue_key: str, body: str) -> dict[str, Any]:
    """Append a comment to an existing Jira ticket.

    Args:
        issue_key: The ticket key (e.g. "SEC-101").
        body: Comment text.
    """
    return await _server.jira_add_comment(issue_key, body)


@tool
async def jira_transition_issue(issue_key: str, transition: str) -> dict[str, Any]:
    """Drive a Jira ticket through the IR workflow state machine.

    Args:
        issue_key: The ticket key.
        transition: start | resolve | close | reopen.
    """
    return await _server.jira_transition_issue(issue_key, transition)


@tool
async def jira_get_issue(issue_key: str) -> dict[str, Any]:
    """Read a Jira ticket back (fields + comments + history).

    Args:
        issue_key: The ticket key.
    """
    return await _server.jira_get_issue(issue_key)
