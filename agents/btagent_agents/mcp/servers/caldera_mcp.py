"""MITRE Caldera MCP server connector — adversary-emulation operations (#118).

MITRE Caldera runs autonomous adversary *operations*: an adversary profile is a
chain of abilities (each mapped to an ATT&CK technique) that Caldera executes
against agents. This connector is the operation-driving counterpart to the
per-technique Atomic Red Team connector.

SAFETY — identical discipline to atomic_red_team_mcp
----------------------------------------------------
* **Mock-first, always** (``BTAGENT_MOCK_CONNECTORS`` default). The mock path
  returns deterministic fixtures, records the operation in
  :data:`MOCK_OPERATION_LEDGER`, seeds synthetic detection telemetry into the
  shared :data:`~btagent_agents.mcp.servers.atomic_red_team_mcp.MOCK_DETECTION_LEDGER`
  (so the same observe phase closes the loop), and fires ZERO real techniques.
  Live mode is a fail-closed ``NotImplementedError`` placeholder.
* **Sandbox-gated upstream + HITL.** ``run_operation`` is refused by the
  sandbox-enforcement layer outside an approved sandbox and declares
  ``hitl_required=True`` in its manifest (blast radius SUBNET — an operation can
  traverse multiple hosts).

Capabilities (manifest ``caldera``):

- ``list_abilities(tactic=None)`` — QUERY: catalog of abilities (ATT&CK-mapped).
- ``run_operation(adversary_profile)`` — ACTION (HITL-gated): run an operation.
- ``get_operation_results(operation_id)`` — QUERY: per-ability results of a run.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers.atomic_red_team_mcp import MOCK_DETECTION_LEDGER

logger = logging.getLogger("btagent.mcp.servers.caldera")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# In-memory ledger of mock operations — inspectable by tests.
MOCK_OPERATION_LEDGER: list[dict[str, Any]] = []

# Deterministic ability catalog (ATT&CK-mapped), defensive-facing metadata only.
_ABILITY_CATALOG: list[dict[str, Any]] = [
    {
        "ability_id": "cal-discovery-whoami",
        "name": "Identify active user",
        "tactic": "discovery",
        "technique_id": "T1033",
        "expected_rule_id": "whoami_execution",
        "expected_severity": "low",
    },
    {
        "ability_id": "cal-execution-encodedps",
        "name": "Encoded PowerShell",
        "tactic": "execution",
        "technique_id": "T1059.001",
        "expected_rule_id": "encoded_powershell",
        "expected_severity": "high",
    },
    {
        "ability_id": "cal-ingress-certutil",
        "name": "Certutil download",
        "tactic": "command-and-control",
        "technique_id": "T1105",
        "expected_rule_id": "certutil_download",
        "expected_severity": "medium",
    },
]

# Named adversary profiles → the ordered technique chain they run.
_ADVERSARY_PROFILES: dict[str, list[str]] = {
    "discovery_chain": ["T1033", "T1059.001"],
    "ingress_chain": ["T1059.001", "T1105"],
}


def _redact_secret(secret: str) -> str:
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:caldera-token:…{secret[-4:]}]"


def _ability_for(technique_id: str) -> dict[str, Any] | None:
    for a in _ABILITY_CATALOG:
        if a["technique_id"] == technique_id:
            return a
    return None


class CalderaMCPServer:
    """MITRE Caldera connector with mock and (guarded) live modes."""

    server_id: str = "caldera"

    DEFAULT_TOKEN_REF: str = "${secret:vault:caldera/api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        server_url: str | None = None,
        token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.server_url: str = (
            server_url or os.getenv("BTAGENT_CALDERA_URL") or "https://caldera.sandbox.local"
        )
        self._token_ref: str = token_ref or self.DEFAULT_TOKEN_REF

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"CalderaMCPServer(server_id={self.server_id!r}, "
            f"server_url={self.server_url!r}, mock_mode={self.mock_mode!r})"
        )

    def _get_token(self) -> str:
        resolved: str = resolve_secret(self._token_ref)
        return resolved

    # ----- tools -----

    async def list_abilities(self, tactic: str | None = None) -> dict[str, Any]:
        """List Caldera abilities (ATT&CK-mapped), optionally filtered by tactic.

        Args:
            tactic: Optional exact tactic filter (e.g. 'execution').

        Returns:
            Envelope with the matched ability metadata records.
        """
        if self.mock_mode:
            abilities = [a for a in _ABILITY_CATALOG if tactic is None or a["tactic"] == tactic]
            return {
                "status": "success",
                "is_mock": True,
                "tactic": tactic,
                "total": len(abilities),
                "abilities": abilities,
            }
        return await self._real_list_abilities(tactic)

    async def run_operation(self, adversary_profile: str) -> dict[str, Any]:
        """Run a Caldera operation for a named adversary profile.

        In mock mode this fires NOTHING: it returns a deterministic operation
        envelope and seeds synthetic detection telemetry (shared with the
        atomic connector) for each technique in the profile's chain.

        Args:
            adversary_profile: Named profile (see :data:`_ADVERSARY_PROFILES`).

        Returns:
            Envelope with a deterministic ``operation_id`` and the technique chain.
        """
        if not adversary_profile or not adversary_profile.strip():
            raise ValueError("run_operation requires a non-empty adversary_profile")
        if self.mock_mode:
            return self._mock_run_operation(adversary_profile)
        return await self._real_run_operation(adversary_profile)

    async def get_operation_results(self, operation_id: str) -> dict[str, Any]:
        """Return the per-ability results of a prior operation.

        Args:
            operation_id: The ``operation_id`` returned by :meth:`run_operation`.

        Returns:
            Envelope with the recorded operation, or a ``not_found`` status.
        """
        if not operation_id or not operation_id.strip():
            raise ValueError("get_operation_results requires a non-empty operation_id")
        if self.mock_mode:
            op = next((o for o in MOCK_OPERATION_LEDGER if o["operation_id"] == operation_id), None)
            if op is None:
                return {
                    "status": "not_found",
                    "is_mock": True,
                    "operation_id": operation_id,
                    "message": f"No mock operation '{operation_id}'",
                }
            return {"status": "success", "is_mock": True, **op}
        return await self._real_get_operation_results(operation_id)

    # ----- mock implementation -----

    def _mock_run_operation(self, adversary_profile: str) -> dict[str, Any]:
        chain = _ADVERSARY_PROFILES.get(adversary_profile, [])
        seq = len(MOCK_OPERATION_LEDGER) + 1
        digest = hashlib.sha256(f"{adversary_profile}:{seq}".encode()).hexdigest()[:12]
        operation_id = f"calop_{digest}"
        now = datetime.now(UTC).isoformat()

        ability_results: list[dict[str, Any]] = []
        for tid in chain:
            ability = _ability_for(tid)
            if ability is None:
                continue
            # Seed the shared detection ledger so the observe phase correlates.
            MOCK_DETECTION_LEDGER.append(
                {
                    "run_id": operation_id,
                    "technique_id": tid,
                    "rule_id": ability["expected_rule_id"],
                    "rule_title": ability["name"],
                    "severity": ability["expected_severity"],
                    "source": "mock_edr",
                    "latency_seconds": 18.0,
                }
            )
            ability_results.append(
                {
                    "ability_id": ability["ability_id"],
                    "technique_id": tid,
                    "name": ability["name"],
                    "status": 0,  # Caldera convention: 0 == success
                    "executed": False,  # mock never executes
                }
            )

        entry = {
            "operation_id": operation_id,
            "adversary_profile": adversary_profile,
            "technique_chain": chain,
            "ability_results": ability_results,
            "started_at": now,
        }
        MOCK_OPERATION_LEDGER.append(entry)
        logger.info(
            "caldera(mock): ran operation %s profile=%s techniques=%s (fired NOTHING)",
            operation_id,
            adversary_profile,
            chain,
        )
        return {
            "status": "success",
            "is_mock": True,
            "operation_id": operation_id,
            "adversary_profile": adversary_profile,
            "technique_chain": chain,
            "executed": False,
        }

    # ----- real implementation (placeholder, fail-safe) -----

    async def _real_list_abilities(self, tactic: str | None) -> dict[str, Any]:
        token = self._get_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "caldera: live-mode list refused — no API token (%s)", _redact_secret(token)
            )
        raise NotImplementedError(
            "Caldera live mode is not implemented. Set BTAGENT_MOCK_CONNECTORS=true for mock mode."
        )

    async def _real_run_operation(self, adversary_profile: str) -> dict[str, Any]:
        token = self._get_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "caldera: live-mode operation refused — no API token (%s)", _redact_secret(token)
            )
        raise NotImplementedError(
            "Caldera live run_operation is not implemented — refusing to run a real "
            "adversary operation. Set BTAGENT_MOCK_CONNECTORS=true for mock mode."
        )

    async def _real_get_operation_results(self, operation_id: str) -> dict[str, Any]:
        raise NotImplementedError("Caldera live get_operation_results is not implemented.")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "list_abilities",
                "description": (
                    "List MITRE Caldera abilities (ATT&CK-mapped operation steps), "
                    "optionally filtered by tactic. Read-only."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tactic": {
                            "type": "string",
                            "description": "Optional exact tactic filter (e.g. 'execution')",
                        },
                    },
                },
            },
            {
                "name": "run_operation",
                "description": (
                    "Run a Caldera adversary operation (a chain of ATT&CK-mapped "
                    "abilities). HITL-gated and SANDBOX-ONLY: refused by the "
                    "sandbox-enforcement layer outside an approved sandbox. "
                    "Mock-first — fires nothing in mock mode."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "adversary_profile": {
                            "type": "string",
                            "description": "Named adversary profile to run",
                        },
                    },
                    "required": ["adversary_profile"],
                },
            },
            {
                "name": "get_operation_results",
                "description": (
                    "Return the per-ability results of a prior Caldera operation. "
                    "Takes the operation_id from run_operation."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "operation_id": {
                            "type": "string",
                            "description": "operation_id from run_operation",
                        },
                    },
                    "required": ["operation_id"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = CalderaMCPServer()


@tool
async def list_abilities(tactic: str | None = None) -> dict[str, Any]:
    """List Caldera abilities (ATT&CK-mapped), optionally filtered by tactic.

    Args:
        tactic: Optional exact tactic filter.
    """
    return await _server.list_abilities(tactic)


@tool
async def run_operation(adversary_profile: str) -> dict[str, Any]:
    """Run a Caldera adversary operation (SANDBOX-ONLY, HITL-gated).

    Args:
        adversary_profile: Named adversary profile to run.
    """
    return await _server.run_operation(adversary_profile)


@tool
async def get_operation_results(operation_id: str) -> dict[str, Any]:
    """Return the per-ability results of a prior Caldera operation.

    Args:
        operation_id: operation_id from run_operation.
    """
    return await _server.get_operation_results(operation_id)
