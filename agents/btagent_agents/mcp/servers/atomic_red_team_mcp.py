"""Atomic Red Team MCP server connector — adversary-emulation trigger (#118).

Atomic Red Team is a library of small, portable tests that each execute one
MITRE ATT&CK technique. This connector is the *trigger* half of the detection-
validation loop: it lists available atomics, runs one (which in LIVE mode would
fire a real technique on a host), and cleans up the artifacts afterwards.

SAFETY — read before touching this file
---------------------------------------
* **Mock-first, always.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true``. The
  mock path returns deterministic fixture responses and records the run in an
  in-memory ledger (:data:`MOCK_ATOMIC_LEDGER`); it fires ZERO real techniques.
  The live path is an unimplemented, fail-closed placeholder that raises
  ``NotImplementedError`` — wiring a real Atomic Red Team executor is out of
  scope for this foundation PR and requires its own sign-off.
* **Sandbox-gated upstream.** This connector never decides *whether* an
  emulation is allowed. The sandbox-enforcement layer
  (:mod:`btagent_shared.security.sandbox`, enforced by
  ``detection_emulation_service`` and re-asserted by the
  ``ValidationOrchestrator``) refuses any non-sandbox target BEFORE this
  connector is reachable. ``run_atomic`` additionally declares
  ``hitl_required=True`` in its manifest so a trigger is gated the same way a
  containment action is.
* **Deterministic mock telemetry.** In mock mode ``run_atomic`` writes a
  synthetic detection into :data:`MOCK_DETECTION_LEDGER` keyed by technique —
  this is what the orchestrator's observe phase (the mock SIEM/EDR poll) reads
  to close the trigger→observe→score loop without any real SIEM.

Capabilities (manifest ``atomic_red_team``):

- ``list_atomics(technique_id=None)`` — QUERY: available atomic tests, optional
  technique filter.
- ``run_atomic(technique_id, args=None)`` — ACTION (HITL-gated): execute one
  atomic. Mock returns a deterministic run envelope + seeds mock telemetry.
- ``cleanup_atomic(run_id)`` — ACTION: revert the artifacts a run created.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.atomic_red_team")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# In-memory ledger of mock atomic runs — inspectable by tests.
MOCK_ATOMIC_LEDGER: list[dict[str, Any]] = []

# Deterministic mock "detection bus": a run in mock mode drops a synthetic
# detection here keyed by technique so the orchestrator's mock SIEM/EDR observe
# phase can find it. This models "the technique fired → telemetry appeared →
# the detection source saw it" without any real SIEM. Cleared by tests.
MOCK_DETECTION_LEDGER: list[dict[str, Any]] = []


# Deterministic fixture catalog of atomics — a tiny, defensive-facing subset.
# Every entry is metadata only (no payloads); ``run_atomic`` returns a synthetic
# result, it does not execute anything.
_ATOMIC_CATALOG: list[dict[str, Any]] = [
    {
        "technique_id": "T1059.001",
        "name": "PowerShell -EncodedCommand",
        "auto_generated_guid": "art-t1059-001-encodedcommand",
        "expected_rule_id": "encoded_powershell",
        "expected_severity": "high",
        "supported_platforms": ["windows"],
    },
    {
        "technique_id": "T1218.005",
        "name": "Mshta remote payload",
        "auto_generated_guid": "art-t1218-005-mshta",
        "expected_rule_id": "mshta_remote",
        "expected_severity": "high",
        "supported_platforms": ["windows"],
    },
    {
        "technique_id": "T1105",
        "name": "Certutil download",
        "auto_generated_guid": "art-t1105-certutil",
        "expected_rule_id": "certutil_download",
        "expected_severity": "medium",
        "supported_platforms": ["windows"],
    },
    {
        "technique_id": "T1110.003",
        "name": "Password spray (failed logons)",
        "auto_generated_guid": "art-t1110-003-spray",
        "expected_rule_id": "failed_logon_spray",
        "expected_severity": "medium",
        "supported_platforms": ["windows"],
    },
]


def _redact_secret(secret: str) -> str:
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:art-token:…{secret[-4:]}]"


def _catalog_for(technique_id: str) -> dict[str, Any] | None:
    for a in _ATOMIC_CATALOG:
        if a["technique_id"] == technique_id:
            return a
    return None


class AtomicRedTeamMCPServer:
    """Atomic Red Team connector with mock and (guarded) live modes.

    The mock path is what CI exercises; it never touches a host. Live mode is a
    fail-closed placeholder — it requires an executor endpoint token to resolve
    and still raises ``NotImplementedError`` (no real executor in this PR).
    """

    server_id: str = "atomic_red_team"

    DEFAULT_TOKEN_REF: str = "${secret:vault:atomic_red_team/executor_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self._token_ref: str = token_ref or self.DEFAULT_TOKEN_REF

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"AtomicRedTeamMCPServer(server_id={self.server_id!r}, mock_mode={self.mock_mode!r})"

    def _get_token(self) -> str:
        resolved: str = resolve_secret(self._token_ref)
        return resolved

    # ----- tools -----

    async def list_atomics(self, technique_id: str | None = None) -> dict[str, Any]:
        """List available atomic tests, optionally filtered by technique.

        Args:
            technique_id: Optional exact ATT&CK technique filter (e.g. 'T1059.001').

        Returns:
            Envelope with the matched atomic metadata records.
        """
        if self.mock_mode:
            atomics = [
                a
                for a in _ATOMIC_CATALOG
                if technique_id is None or a["technique_id"] == technique_id
            ]
            return {
                "status": "success",
                "is_mock": True,
                "technique_id": technique_id,
                "total": len(atomics),
                "atomics": atomics,
            }
        return await self._real_list_atomics(technique_id)

    async def run_atomic(
        self,
        technique_id: str,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute one atomic test for *technique_id*.

        In mock mode this fires NOTHING: it returns a deterministic run
        envelope and seeds a synthetic detection into :data:`MOCK_DETECTION_LEDGER`
        so the observe phase can correlate. Live mode is fail-closed.

        Args:
            technique_id: ATT&CK technique to emulate.
            args: Optional atomic input arguments (ignored in mock mode).

        Returns:
            Envelope with a deterministic ``run_id``, the technique, and the
            synthetic telemetry marker.
        """
        if not technique_id or not technique_id.strip():
            raise ValueError("run_atomic requires a non-empty technique_id")

        if self.mock_mode:
            return self._mock_run_atomic(technique_id, args or {})
        return await self._real_run_atomic(technique_id, args or {})

    async def cleanup_atomic(self, run_id: str) -> dict[str, Any]:
        """Revert the artifacts an atomic run created.

        Args:
            run_id: The ``run_id`` returned by :meth:`run_atomic`.

        Returns:
            Envelope confirming cleanup. In mock mode this also drops the run's
            synthetic telemetry from the detection ledger so repeated
            mock runs stay isolated.
        """
        if not run_id or not run_id.strip():
            raise ValueError("cleanup_atomic requires a non-empty run_id")
        if self.mock_mode:
            before = len(MOCK_DETECTION_LEDGER)
            MOCK_DETECTION_LEDGER[:] = [
                d for d in MOCK_DETECTION_LEDGER if d.get("run_id") != run_id
            ]
            removed = before - len(MOCK_DETECTION_LEDGER)
            logger.info("atomic(mock): cleaned up run %s (telemetry removed=%d)", run_id, removed)
            return {
                "status": "success",
                "is_mock": True,
                "run_id": run_id,
                "cleaned": True,
                "telemetry_removed": removed,
            }
        return await self._real_cleanup_atomic(run_id)

    # ----- mock implementation -----

    def _mock_run_atomic(self, technique_id: str, args: dict[str, Any]) -> dict[str, Any]:
        catalog = _catalog_for(technique_id)
        # Deterministic run id derived from the technique + ledger position so
        # the same technique run twice is still distinguishable but reproducible
        # within a fresh ledger.
        seq = len(MOCK_ATOMIC_LEDGER) + 1
        digest = hashlib.sha256(f"{technique_id}:{seq}".encode()).hexdigest()[:12]
        run_id = f"art_{digest}"
        now = datetime.now(UTC).isoformat()
        entry = {
            "run_id": run_id,
            "technique_id": technique_id,
            "args": args,
            "started_at": now,
            "is_mock": True,
        }
        MOCK_ATOMIC_LEDGER.append(entry)

        # Seed synthetic detection telemetry the observe phase will poll. Only
        # techniques in the catalog produce a "detectable" firing; an unknown
        # technique produces no telemetry (→ the orchestrator scores silent_gap).
        if catalog is not None:
            MOCK_DETECTION_LEDGER.append(
                {
                    "run_id": run_id,
                    "technique_id": technique_id,
                    "rule_id": catalog["expected_rule_id"],
                    "rule_title": catalog["name"],
                    "severity": catalog["expected_severity"],
                    "source": "mock_edr",
                    "latency_seconds": 12.0,
                }
            )
        logger.info(
            "atomic(mock): ran %s run_id=%s (fired NOTHING; seeded telemetry=%s)",
            technique_id,
            run_id,
            catalog is not None,
        )
        return {
            "status": "success",
            "is_mock": True,
            "run_id": run_id,
            "technique_id": technique_id,
            "executed": False,  # mock never executes a real technique
            "expected_rule_id": catalog["expected_rule_id"] if catalog else None,
            "expected_severity": catalog["expected_severity"] if catalog else None,
        }

    # ----- real implementation (placeholder, fail-safe) -----

    async def _real_list_atomics(self, technique_id: str | None) -> dict[str, Any]:
        token = self._get_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "atomic: live-mode list refused — no executor token (%s)", _redact_secret(token)
            )
        raise NotImplementedError(
            "Atomic Red Team live mode is not implemented. "
            "Set BTAGENT_MOCK_CONNECTORS=true for mock mode."
        )

    async def _real_run_atomic(self, technique_id: str, args: dict[str, Any]) -> dict[str, Any]:
        # Never reachable without a resolvable executor token, and even then a
        # hard stop — a real ATT&CK executor is out of scope for this PR.
        token = self._get_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "atomic: live-mode run refused — no executor token (%s)", _redact_secret(token)
            )
        raise NotImplementedError(
            "Atomic Red Team live run_atomic is not implemented — refusing to fire a "
            "real technique. Set BTAGENT_MOCK_CONNECTORS=true for mock mode."
        )

    async def _real_cleanup_atomic(self, run_id: str) -> dict[str, Any]:
        raise NotImplementedError("Atomic Red Team live cleanup_atomic is not implemented.")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "list_atomics",
                "description": (
                    "List available Atomic Red Team tests (MITRE ATT&CK technique "
                    "emulations), optionally filtered by technique_id. Read-only."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "Optional exact ATT&CK technique filter",
                        },
                    },
                },
            },
            {
                "name": "run_atomic",
                "description": (
                    "Execute one atomic test for an ATT&CK technique (adversary "
                    "emulation trigger). HITL-gated and SANDBOX-ONLY: refused by "
                    "the sandbox-enforcement layer outside an approved sandbox. "
                    "Mock-first — fires nothing in mock mode."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique to emulate (e.g. 'T1059.001')",
                        },
                        "args": {
                            "type": "object",
                            "description": "Optional atomic input arguments",
                        },
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "cleanup_atomic",
                "description": (
                    "Revert the artifacts an atomic run created (restorative). "
                    "Takes the run_id returned by run_atomic."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string", "description": "run_id from run_atomic"},
                    },
                    "required": ["run_id"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = AtomicRedTeamMCPServer()


@tool
async def list_atomics(technique_id: str | None = None) -> dict[str, Any]:
    """List available Atomic Red Team tests, optionally filtered by technique.

    Args:
        technique_id: Optional exact ATT&CK technique filter.
    """
    return await _server.list_atomics(technique_id)


@tool
async def run_atomic(technique_id: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute one atomic test for an ATT&CK technique (SANDBOX-ONLY, HITL-gated).

    Args:
        technique_id: ATT&CK technique to emulate.
        args: Optional atomic input arguments.
    """
    return await _server.run_atomic(technique_id, args)


@tool
async def cleanup_atomic(run_id: str) -> dict[str, Any]:
    """Revert the artifacts an atomic run created.

    Args:
        run_id: The run_id returned by run_atomic.
    """
    return await _server.cleanup_atomic(run_id)
