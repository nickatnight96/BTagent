"""GCP Cloud Audit Logs + Security Command Center MCP server connector — Tier-2 (#100).

Second cloud connector after AWS CloudTrail; the GCP control-plane telemetry
surface. Built in the modern style (fixtures module, lazy ``${secret:…}``
resolution, guarded live mode, full contract tests) and mirroring
:mod:`btagent_agents.mcp.servers.cloudtrail_mcp`.

Cloud Audit Logs / SCC are read-only telemetry surfaces — like CloudTrail and
Zeek there is no mutation / containment capability and therefore no HITL-gated
tool (cloud containment lands with the IAM response playbooks, not the
telemetry connector).

Capabilities:

- ``gcp_audit_log_search(start, end, method_name=None, principal=None,
  limit=100)`` — search Cloud Audit Logs entries (exact
  ``protoPayload.methodName``, exact
  ``protoPayload.authenticationInfo.principalEmail``).
- ``gcp_scc_list_findings(min_severity="LOW", category_contains=None,
  limit=50)`` — Security Command Center findings with a categorical severity
  floor (LOW < MEDIUM < HIGH < CRITICAL) and a category substring filter.
- ``gcp_audit_principal_summary(principal, start, end)`` — behavioral rollup
  for one principal: per-method counts, distinct caller IPs, projects
  touched, and denied calls — the "is this service account acting weird"
  triage signal (mirrors ``aws_cloudtrail_principal_summary``).

Secret hygiene mirrors the sibling connectors: the service-account key is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._gcp_fixtures import (
    GCP_FIXTURE_AUDIT_ENTRIES,
    GCP_FIXTURE_SCC_FINDINGS,
    SCC_SEVERITY_ORDER,
)

logger = logging.getLogger("btagent.mcp.servers.gcp")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


def _parse_gcp_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("gcp: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _entry_principal(entry: dict[str, Any]) -> str:
    """Extract the principal email from a Cloud Audit Logs entry."""
    return str(
        ((entry.get("protoPayload") or {}).get("authenticationInfo") or {}).get("principalEmail")
        or ""
    )


def _entry_method(entry: dict[str, Any]) -> str:
    """Extract the methodName from a Cloud Audit Logs entry."""
    return str((entry.get("protoPayload") or {}).get("methodName") or "")


def _entry_caller_ip(entry: dict[str, Any]) -> str:
    """Extract the caller IP from a Cloud Audit Logs entry."""
    return str(
        ((entry.get("protoPayload") or {}).get("requestMetadata") or {}).get("callerIp") or ""
    )


def _entry_denied(entry: dict[str, Any]) -> bool:
    """True when every authorizationInfo grant on the entry is ``granted=False``."""
    auth = (entry.get("protoPayload") or {}).get("authorizationInfo") or []
    if not auth:
        return False
    return all(not a.get("granted", False) for a in auth)


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the service-account key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:gcp-sa-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# GCP Cloud Audit / SCC MCP server class
# ---------------------------------------------------------------------------
class GCPCloudAuditMCPServer:
    """GCP Cloud Audit Logs + SCC MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls GCP unless explicitly opted out AND a service-account key
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "gcp"

    DEFAULT_SA_KEY_REF: str = "${secret:vault:gcp/service_account_key}"
    DEFAULT_PROJECT_REF: str = "${env:BTAGENT_GCP_PROJECT_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        project_id: str | None = None,
        sa_key_ref: str | None = None,
        project_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.project_id: str = project_id or os.getenv("BTAGENT_GCP_PROJECT_ID") or "acme-prod-1"
        self._sa_key_ref: str = sa_key_ref or self.DEFAULT_SA_KEY_REF
        self._project_ref: str = project_ref or self.DEFAULT_PROJECT_REF

    # ----- safety: never put the key in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"GCPCloudAuditMCPServer(server_id={self.server_id!r}, "
            f"project_id={self.project_id!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_sa_key(self) -> str:
        """Resolve the service-account key lazily from the configured ref."""
        resolved: str = resolve_secret(self._sa_key_ref)
        return resolved

    # ----- tools -----

    async def gcp_audit_log_search(
        self,
        start: str,
        end: str,
        method_name: str | None = None,
        principal: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Cloud Audit Logs entries for a time window.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            method_name: Optional exact methodName filter (e.g. "SetIamPolicy").
            principal: Optional exact principalEmail filter.
            limit: Max entries to return.

        Returns:
            Envelope with the matched audit-log entries.
        """
        if self.mock_mode:
            return self._mock_audit_log_search(start, end, method_name, principal, limit)
        return await self._real_audit_log_search(start, end, method_name, principal, limit)

    async def gcp_scc_list_findings(
        self,
        min_severity: str = "LOW",
        category_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Security Command Center findings.

        Args:
            min_severity: Severity floor (LOW | MEDIUM | HIGH | CRITICAL).
            category_contains: Optional substring over the finding category.
            limit: Max findings to return.

        Returns:
            Envelope with the finding objects (resource + source properties).
        """
        if self.mock_mode:
            return self._mock_scc_list_findings(min_severity, category_contains, limit)
        return await self._real_scc_list_findings(min_severity, category_contains, limit)

    async def gcp_audit_principal_summary(
        self,
        principal: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Behavioral audit-log rollup for one principal.

        Args:
            principal: principalEmail to summarise.
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with per-method counts, distinct caller IPs, projects
            touched, and denied calls.
        """
        if self.mock_mode:
            return self._mock_principal_summary(principal, start, end)
        return await self._real_principal_summary(principal, start, end)

    # ----- mock implementations -----

    def _entries_in_window(self, start: str, end: str) -> list[dict[str, Any]]:
        start_dt = _parse_gcp_timestamp(start)
        end_dt = _parse_gcp_timestamp(end)
        return [
            e
            for e in GCP_FIXTURE_AUDIT_ENTRIES
            if start_dt <= _parse_gcp_timestamp(e.get("timestamp")) < end_dt
        ]

    def _mock_audit_log_search(
        self,
        start: str,
        end: str,
        method_name: str | None,
        principal: str | None,
        limit: int,
    ) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        for entry in self._entries_in_window(start, end):
            if method_name is not None and _entry_method(entry) != method_name:
                continue
            if principal is not None and _entry_principal(entry) != principal:
                continue
            entries.append(entry)
            if len(entries) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "method_name": method_name,
            "principal": principal,
            "total": len(entries),
            "entries": entries,
        }

    def _mock_scc_list_findings(
        self,
        min_severity: str,
        category_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        floor = SCC_SEVERITY_ORDER.get(str(min_severity).upper(), 0)
        findings = [
            f
            for f in GCP_FIXTURE_SCC_FINDINGS
            if SCC_SEVERITY_ORDER.get(str(f.get("severity")).upper(), 0) >= floor
            and (category_contains is None or category_contains in str(f.get("category", "")))
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_severity": min_severity,
            "category_contains": category_contains,
            "total": len(findings),
            "findings": findings,
        }

    def _mock_principal_summary(self, principal: str, start: str, end: str) -> dict[str, Any]:
        entries = [
            e for e in self._entries_in_window(start, end) if _entry_principal(e) == principal
        ]
        if not entries:
            return {
                "status": "not_found",
                "is_mock": True,
                "principal": principal,
                "message": f"No audit activity for principal '{principal}' in the window",
            }
        by_method: Counter[str] = Counter()
        caller_ips: set[str] = set()
        projects: set[str] = set()
        denied: list[dict[str, Any]] = []
        for e in entries:
            by_method[_entry_method(e)] += 1
            caller_ips.add(_entry_caller_ip(e))
            projects.add(str((e.get("resource") or {}).get("labels", {}).get("project_id") or ""))
            if _entry_denied(e):
                denied.append(
                    {
                        "methodName": _entry_method(e),
                        "callerIp": _entry_caller_ip(e),
                        "timestamp": e.get("timestamp"),
                    }
                )
        return {
            "status": "success",
            "is_mock": True,
            "principal": principal,
            "start": start,
            "end": end,
            "total_entries": len(entries),
            "methods_by_name": dict(by_method.most_common()),
            "distinct_caller_ips": sorted(caller_ips),
            "projects": sorted(p for p in projects if p),
            "denied_calls": denied,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_audit_log_search(
        self,
        start: str,
        end: str,
        method_name: str | None,
        principal: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "gcp: live-mode audit-log search refused — no service-account key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError(
                "GCP live mode requires a resolvable service-account key (wire "
                "${secret:vault:gcp/service_account_key} or set BTAGENT_GCP_SA_KEY)."
            )
        raise NotImplementedError("GCP live audit_log_search not yet implemented")

    async def _real_scc_list_findings(
        self,
        min_severity: str,
        category_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "gcp: live-mode SCC list refused — no service-account key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError("GCP live mode requires a resolvable service-account key")
        raise NotImplementedError("GCP live scc_list_findings not yet implemented")

    async def _real_principal_summary(self, principal: str, start: str, end: str) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("GCP live mode requires a resolvable service-account key")
        raise NotImplementedError("GCP live principal_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "gcp_audit_log_search",
                "description": (
                    "Search GCP Cloud Audit Logs entries for a time window with "
                    "exact methodName / principalEmail filters. Entries carry "
                    "the protoPayload authenticationInfo, caller IP, resource, "
                    "and authorizationInfo grant/deny."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "method_name": {
                            "type": "string",
                            "description": "Optional exact methodName (e.g. SetIamPolicy)",
                        },
                        "principal": {
                            "type": "string",
                            "description": "Optional exact principalEmail",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max entries to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "gcp_scc_list_findings",
                "description": (
                    "List GCP Security Command Center findings with a "
                    "categorical severity floor (LOW/MEDIUM/HIGH/CRITICAL) and "
                    "a category substring filter (IAM anomalous grant, service "
                    "account key creation, misconfiguration, …)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_severity": {
                            "type": "string",
                            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            "description": "Severity floor",
                            "default": "LOW",
                        },
                        "category_contains": {
                            "type": "string",
                            "description": "Optional substring over the finding category",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max findings to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "gcp_audit_principal_summary",
                "description": (
                    "Behavioral Cloud Audit Logs rollup for one principal: "
                    "per-method call counts, distinct caller IPs, projects "
                    "touched, denied calls — the compromised-service-account "
                    "triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "principalEmail to summarise",
                        },
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                    },
                    "required": ["principal", "start", "end"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = GCPCloudAuditMCPServer()


@tool
async def gcp_audit_log_search(
    start: str,
    end: str,
    method_name: str | None = None,
    principal: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search GCP Cloud Audit Logs entries for a time window.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        method_name: Optional exact methodName filter (e.g. "SetIamPolicy").
        principal: Optional exact principalEmail filter.
        limit: Max entries to return.
    """
    return await _server.gcp_audit_log_search(start, end, method_name, principal, limit)


@tool
async def gcp_scc_list_findings(
    min_severity: str = "LOW",
    category_contains: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List GCP Security Command Center findings.

    Args:
        min_severity: Severity floor (LOW | MEDIUM | HIGH | CRITICAL).
        category_contains: Optional substring over the finding category.
        limit: Max findings to return.
    """
    return await _server.gcp_scc_list_findings(min_severity, category_contains, limit)


@tool
async def gcp_audit_principal_summary(
    principal: str,
    start: str,
    end: str,
) -> dict[str, Any]:
    """Behavioral Cloud Audit Logs rollup for one principal.

    Args:
        principal: principalEmail to summarise.
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.gcp_audit_principal_summary(principal, start, end)
