"""ServiceNow Security Incident Response MCP server connector — Tier-2 slice (#100).

Enterprise SecOps ticketing sink (ServiceNow SIR — ``sn_si_incident``); the
third Tier-2 connector and the second ticketing sink after Jira. Built in the
modern style (lazy ``${secret:…}`` resolution, guarded live mode, full
contract tests) and — like Jira — a **stateful write surface**, so the mock
keeps an in-memory security-incident ledger (mirroring
:mod:`btagent_agents.mcp.servers.jira_mcp`) seeded with two fixture records and
exposes :func:`reset_mock_ledger` for tests.

Capabilities:

- ``snow_create_security_incident(short_description, description="",
  priority="3-moderate", investigation_id=None, category=None)`` — open a
  security incident (SIR) record. Ticket creation is the canonical automated
  sink action (low blast radius, reversible via close), so it is **not**
  HITL-gated — the #100 manifest can still opt it into the HITLHook per
  deployment.
- ``snow_add_work_note(number, note)`` — append a work note.
- ``snow_update_state(number, transition)`` — drive the SIR lifecycle state
  machine (see :data:`SIR_TRANSITIONS`); invalid transitions return an error
  envelope naming the legal moves from the current state.
- ``snow_get_security_incident(number)`` — read a record back (fields + work
  notes + transition history).

SIR lifecycle state machine (documented so tests and prompts agree)
-------------------------------------------------------------------
States: ``analysis`` → ``contain`` → ``eradicate`` → ``recover`` →
``review`` → ``closed``. Transitions: ``contain`` (analysis → contain),
``eradicate`` (contain → eradicate), ``recover`` (eradicate → recover),
``review`` (recover → review), ``close`` (review → closed), ``reopen``
(closed → analysis). Anything else is rejected with the legal moves listed.

Validation matches what a live ServiceNow would enforce (empty
short-description / work-note, unknown record numbers), so swapping in the
real Table API later doesn't change caller behaviour.

Secret hygiene mirrors the sibling connectors: the ServiceNow API password is
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

logger = logging.getLogger("btagent.mcp.servers.servicenow")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

VALID_PRIORITIES: tuple[str, ...] = ("1-critical", "2-high", "3-moderate", "4-low")

# SIR lifecycle: transition name -> (allowed source states, target state).
SIR_TRANSITIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "contain": (("analysis",), "contain"),
    "eradicate": (("contain",), "eradicate"),
    "recover": (("eradicate",), "recover"),
    "review": (("recover",), "review"),
    "close": (("review",), "closed"),
    "reopen": (("closed",), "analysis"),
}

# ---------------------------------------------------------------------------
# Stateful mock ledger (mirrors jira_mcp.MOCK_TICKET_LEDGER)
# ---------------------------------------------------------------------------

# Seeded fixture records: one mid-lifecycle intrusion and one closed
# data-exposure incident, so read/transition tests have history to assert on.
_SEED_INCIDENTS: list[dict[str, Any]] = [
    {
        "number": "SIR0010001",
        "short_description": "Data exposure via misconfigured S3 bucket (finance exports)",
        "description": "Public-read ACL on acme-fin-exports; access logs pulled and reviewed.",
        "priority": "2-high",
        "state": "closed",
        "investigation_id": "inv_seed_exposure",
        "category": "data_exposure",
        "opened_at": "2026-06-02T11:00:00Z",
        "updated_at": "2026-06-05T16:00:00Z",
        "work_notes": [
            {
                "note": "Bucket ACL locked down; owner notified.",
                "created_at": "2026-06-03T10:00:00Z",
            },
        ],
        "history": ["contain", "eradicate", "recover", "review", "close"],
    },
    {
        "number": "SIR0010002",
        "short_description": "Suspected hands-on-keyboard intrusion on WIN10-FIN-07",
        "description": "Cortex XDR C2 beacon + encoded PowerShell; endpoint isolation pending.",
        "priority": "1-critical",
        "state": "contain",
        "investigation_id": "inv_seed_intrusion",
        "category": "malicious_code",
        "opened_at": "2026-07-02T08:30:00Z",
        "updated_at": "2026-07-02T09:15:00Z",
        "work_notes": [],
        "history": ["contain"],
    },
]

# Live ledger state — reset via reset_mock_ledger().
MOCK_SIR_LEDGER: dict[str, dict[str, Any]] = {}
_incident_counter = itertools.count(3)


def reset_mock_ledger() -> None:
    """Restore the mock ledger to its seeded fixture state (test hook)."""
    global _incident_counter
    MOCK_SIR_LEDGER.clear()
    for seed in _SEED_INCIDENTS:
        MOCK_SIR_LEDGER[seed["number"]] = {
            **seed,
            "work_notes": [dict(n) for n in seed["work_notes"]],
            "history": list(seed["history"]),
        }
    _incident_counter = itertools.count(3)


reset_mock_ledger()


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_number() -> str:
    """Allocate the next SIR record number (SIR0010003, …)."""
    return f"SIR001{next(_incident_counter):04d}"


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the ServiceNow API password.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:servicenow-password:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# ServiceNow SecOps MCP server class
# ---------------------------------------------------------------------------
class ServiceNowMCPServer:
    """ServiceNow SIR MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls a ServiceNow instance unless explicitly opted out AND an API
    password resolves. The mock path is what CI exercises; live mode is a
    guarded placeholder.
    """

    server_id: str = "servicenow"

    DEFAULT_PASSWORD_REF: str = "${secret:vault:servicenow/api_password}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        instance_url: str | None = None,
        username: str | None = None,
        password_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.instance_url: str = (
            instance_url or os.getenv("BTAGENT_SERVICENOW_URL") or "https://acme.service-now.com"
        )
        self.username: str = username or os.getenv("BTAGENT_SERVICENOW_USER") or "svc-btagent"
        self._password_ref: str = password_ref or self.DEFAULT_PASSWORD_REF

    # ----- safety: never put the password in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"ServiceNowMCPServer(server_id={self.server_id!r}, "
            f"instance_url={self.instance_url!r}, username={self.username!r}, "
            f"mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_password(self) -> str:
        """Resolve the ServiceNow API password lazily from the configured ref."""
        resolved: str = resolve_secret(self._password_ref)
        return resolved

    # ----- tools -----

    async def snow_create_security_incident(
        self,
        short_description: str,
        description: str = "",
        priority: str = "3-moderate",
        investigation_id: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        """Open a security incident (SIR) record.

        Args:
            short_description: One-line summary (required, non-blank).
            description: Longer body.
            priority: 1-critical | 2-high | 3-moderate | 4-low.
            investigation_id: Optional BTagent investigation to link.
            category: Optional SIR category (e.g. malicious_code).

        Returns:
            Envelope with the created record number + fields.
        """
        if self.mock_mode:
            return self._mock_create(
                short_description, description, priority, investigation_id, category
            )
        return await self._real_create(
            short_description, description, priority, investigation_id, category
        )

    async def snow_add_work_note(self, number: str, note: str) -> dict[str, Any]:
        """Append a work note to a security incident.

        Args:
            number: The SIR record number (e.g. "SIR0010002").
            note: Work-note text (required, non-blank).

        Returns:
            Envelope with the updated work-note count.
        """
        if self.mock_mode:
            return self._mock_add_work_note(number, note)
        return await self._real_add_work_note(number, note)

    async def snow_update_state(self, number: str, transition: str) -> dict[str, Any]:
        """Drive a security incident through the SIR lifecycle.

        Args:
            number: The SIR record number.
            transition: contain | eradicate | recover | review | close | reopen.

        Returns:
            Envelope with the previous and new state; invalid transitions
            return an error envelope naming the legal moves.
        """
        if self.mock_mode:
            return self._mock_update_state(number, transition)
        return await self._real_update_state(number, transition)

    async def snow_get_security_incident(self, number: str) -> dict[str, Any]:
        """Read a security incident back (fields + work notes + history).

        Args:
            number: The SIR record number.

        Returns:
            Envelope with the full record or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_get(number)
        return await self._real_get(number)

    # ----- mock implementations -----

    def _mock_create(
        self,
        short_description: str,
        description: str,
        priority: str,
        investigation_id: str | None,
        category: str | None,
    ) -> dict[str, Any]:
        if not short_description or not short_description.strip():
            return {
                "status": "error",
                "is_mock": True,
                "message": "short_description must be non-blank",
            }
        if priority not in VALID_PRIORITIES:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid priority {priority!r} ({'|'.join(VALID_PRIORITIES)})",
            }
        number = _next_number()
        now = _utcnow_iso()
        record = {
            "number": number,
            "short_description": short_description.strip(),
            "description": description,
            "priority": priority,
            "state": "analysis",
            "investigation_id": investigation_id,
            "category": category,
            "opened_at": now,
            "updated_at": now,
            "work_notes": [],
            "history": [],
        }
        MOCK_SIR_LEDGER[number] = record
        logger.info("servicenow mock: created %s (%s)", number, priority)
        return {"status": "success", "is_mock": True, "number": number, "record": record}

    def _mock_add_work_note(self, number: str, note: str) -> dict[str, Any]:
        record = MOCK_SIR_LEDGER.get(number)
        if record is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Security incident '{number}' not found",
            }
        if not note or not note.strip():
            return {"status": "error", "is_mock": True, "message": "work note must be non-blank"}
        record["work_notes"].append({"note": note.strip(), "created_at": _utcnow_iso()})
        record["updated_at"] = _utcnow_iso()
        return {
            "status": "success",
            "is_mock": True,
            "number": number,
            "work_note_count": len(record["work_notes"]),
        }

    def _mock_update_state(self, number: str, transition: str) -> dict[str, Any]:
        record = MOCK_SIR_LEDGER.get(number)
        if record is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Security incident '{number}' not found",
            }
        spec = SIR_TRANSITIONS.get(transition)
        current = record["state"]
        if spec is None or current not in spec[0]:
            legal = [name for name, (sources, _t) in SIR_TRANSITIONS.items() if current in sources]
            return {
                "status": "error",
                "is_mock": True,
                "message": (
                    f"Transition {transition!r} not legal from state {current!r}; "
                    f"legal transitions: {legal or ['<none>']}"
                ),
            }
        record["state"] = spec[1]
        record["history"].append(transition)
        record["updated_at"] = _utcnow_iso()
        return {
            "status": "success",
            "is_mock": True,
            "number": number,
            "previous_state": current,
            "new_state": spec[1],
        }

    def _mock_get(self, number: str) -> dict[str, Any]:
        record = MOCK_SIR_LEDGER.get(number)
        if record is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Security incident '{number}' not found",
            }
        return {"status": "success", "is_mock": True, "record": record}

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_create(
        self,
        short_description: str,
        description: str,
        priority: str,
        investigation_id: str | None,
        category: str | None,
    ) -> dict[str, Any]:
        pw = self._get_password()
        if not pw or pw.startswith("<unresolved:"):
            logger.warning(
                "servicenow: live-mode create refused — no API password (%s)",
                _redact_secret(pw),
            )
            raise NotImplementedError(
                "ServiceNow live mode requires a resolvable API password (wire "
                "${secret:vault:servicenow/api_password} or set BTAGENT_SERVICENOW_PASSWORD)."
            )
        raise NotImplementedError("ServiceNow live create_security_incident not yet implemented")

    async def _real_add_work_note(self, number: str, note: str) -> dict[str, Any]:
        pw = self._get_password()
        if not pw or pw.startswith("<unresolved:"):
            logger.warning(
                "servicenow: live-mode work note refused — no API password (%s)",
                _redact_secret(pw),
            )
            raise NotImplementedError("ServiceNow live mode requires a resolvable API password")
        raise NotImplementedError("ServiceNow live add_work_note not yet implemented")

    async def _real_update_state(self, number: str, transition: str) -> dict[str, Any]:
        pw = self._get_password()
        if not pw or pw.startswith("<unresolved:"):
            raise NotImplementedError("ServiceNow live mode requires a resolvable API password")
        raise NotImplementedError("ServiceNow live update_state not yet implemented")

    async def _real_get(self, number: str) -> dict[str, Any]:
        pw = self._get_password()
        if not pw or pw.startswith("<unresolved:"):
            raise NotImplementedError("ServiceNow live mode requires a resolvable API password")
        raise NotImplementedError("ServiceNow live get_security_incident not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "snow_create_security_incident",
                "description": (
                    "Open a ServiceNow Security Incident Response (SIR) record, "
                    "optionally linked to a BTagent investigation."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "short_description": {"type": "string", "description": "One-line summary"},
                        "description": {"type": "string", "description": "Record body"},
                        "priority": {
                            "type": "string",
                            "enum": list(VALID_PRIORITIES),
                            "default": "3-moderate",
                        },
                        "investigation_id": {
                            "type": "string",
                            "description": "Optional BTagent investigation id to link",
                        },
                        "category": {
                            "type": "string",
                            "description": "Optional SIR category (e.g. malicious_code)",
                        },
                    },
                    "required": ["short_description"],
                },
            },
            {
                "name": "snow_add_work_note",
                "description": "Append a work note to an existing ServiceNow SIR record.",
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "number": {"type": "string", "description": "SIR number (SIR0010002)"},
                        "note": {"type": "string", "description": "Work-note text"},
                    },
                    "required": ["number", "note"],
                },
            },
            {
                "name": "snow_update_state",
                "description": (
                    "Drive a ServiceNow SIR record through its lifecycle: "
                    "contain, eradicate, recover, review, close, reopen. "
                    "Invalid transitions return the legal moves."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "number": {"type": "string", "description": "SIR number"},
                        "transition": {
                            "type": "string",
                            "enum": sorted(SIR_TRANSITIONS),
                            "description": "Lifecycle transition",
                        },
                    },
                    "required": ["number", "transition"],
                },
            },
            {
                "name": "snow_get_security_incident",
                "description": (
                    "Read a ServiceNow SIR record back: fields, work notes, and transition history."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "number": {"type": "string", "description": "SIR number"},
                    },
                    "required": ["number"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = ServiceNowMCPServer()


@tool
async def snow_create_security_incident(
    short_description: str,
    description: str = "",
    priority: str = "3-moderate",
    investigation_id: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Open a ServiceNow Security Incident Response (SIR) record.

    Args:
        short_description: One-line summary.
        description: Longer body.
        priority: 1-critical | 2-high | 3-moderate | 4-low.
        investigation_id: Optional BTagent investigation id to link.
        category: Optional SIR category.
    """
    return await _server.snow_create_security_incident(
        short_description, description, priority, investigation_id, category
    )


@tool
async def snow_add_work_note(number: str, note: str) -> dict[str, Any]:
    """Append a work note to an existing ServiceNow SIR record.

    Args:
        number: The SIR record number (e.g. "SIR0010002").
        note: Work-note text.
    """
    return await _server.snow_add_work_note(number, note)


@tool
async def snow_update_state(number: str, transition: str) -> dict[str, Any]:
    """Drive a ServiceNow SIR record through its lifecycle state machine.

    Args:
        number: The SIR record number.
        transition: contain | eradicate | recover | review | close | reopen.
    """
    return await _server.snow_update_state(number, transition)


@tool
async def snow_get_security_incident(number: str) -> dict[str, Any]:
    """Read a ServiceNow SIR record back (fields + work notes + history).

    Args:
        number: The SIR record number.
    """
    return await _server.snow_get_security_incident(number)
