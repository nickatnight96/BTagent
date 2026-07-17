"""Wiz CNAPP/CSPM MCP server connector — Tier-2 slice (#100).

First cloud-security-posture (CNAPP) connector — a new connector class beyond
the cloud *audit* connectors (CloudTrail, GCP): Wiz surfaces posture issues,
vulnerability findings, and the toxic-combination join between them. Built in
the modern style (fixtures module, lazy ``${secret:…}`` resolution, guarded
live mode, full contract tests) and mirroring the read-only-telemetry shape of
:mod:`btagent_agents.mcp.servers.cloudtrail_mcp` — no mutation / containment
capability, therefore no HITL-gated tool.

Capabilities:

- ``wiz_list_issues(min_severity="LOW", status=None, category_contains=None,
  limit=50)`` — Wiz Issues (posture / toxic-combination findings) with a
  categorical severity floor, exact status, and control-category substring.
- ``wiz_list_vulnerabilities(min_severity="LOW", has_exploit=None,
  resource_contains=None, limit=50)`` — vulnerability findings with a severity
  floor, an exploit-available filter, and a resource-name substring.
- ``wiz_resource_summary(resource_id)`` — per-resource posture rollup: open
  issues by severity, vulns by severity, exploitable-vuln count, and the
  public-exposure flag — the "is this asset an exposed-plus-exploitable toxic
  combination" triage signal (mirrors ``aws_cloudtrail_principal_summary``).

Secret hygiene mirrors the sibling connectors: the Wiz API client secret is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._wiz_fixtures import (
    WIZ_FIXTURE_ISSUES,
    WIZ_FIXTURE_RESOURCES,
    WIZ_FIXTURE_VULNS,
    WIZ_SEVERITY_ORDER,
)

logger = logging.getLogger("btagent.mcp.servers.wiz")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


def _severity_rank(value: Any) -> int:
    """Rank a Wiz severity string (unknown → 0, below every real floor)."""
    return WIZ_SEVERITY_ORDER.get(str(value).upper(), 0)


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Wiz API client secret.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:wiz-client-secret:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Wiz CNAPP MCP server class
# ---------------------------------------------------------------------------
class WizMCPServer:
    """Wiz CNAPP MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Wiz API unless explicitly opted out AND a client secret
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "wiz"

    DEFAULT_CLIENT_ID_REF: str = "${env:BTAGENT_WIZ_CLIENT_ID}"
    DEFAULT_CLIENT_SECRET_REF: str = "${secret:vault:wiz/client_secret}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        client_id_ref: str | None = None,
        client_secret_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url or os.getenv("BTAGENT_WIZ_API_URL") or "https://api.us1.app.wiz.io/graphql"
        )
        self._client_id_ref: str = client_id_ref or self.DEFAULT_CLIENT_ID_REF
        self._client_secret_ref: str = client_secret_ref or self.DEFAULT_CLIENT_SECRET_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"WizMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_client_secret(self) -> str:
        """Resolve the Wiz API client secret lazily from the configured ref."""
        resolved: str = resolve_secret(self._client_secret_ref)
        return resolved

    # ----- tools -----

    async def wiz_list_issues(
        self,
        min_severity: str = "LOW",
        status: str | None = None,
        category_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Wiz Issues (posture / toxic-combination findings).

        Args:
            min_severity: Severity floor (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL).
            status: Optional exact status filter (OPEN | IN_PROGRESS | RESOLVED).
            category_contains: Optional substring over the control category.
            limit: Max issues to return.

        Returns:
            Envelope with the matched Issue objects.
        """
        if self.mock_mode:
            return self._mock_list_issues(min_severity, status, category_contains, limit)
        return await self._real_list_issues(min_severity, status, category_contains, limit)

    async def wiz_list_vulnerabilities(
        self,
        min_severity: str = "LOW",
        has_exploit: bool | None = None,
        resource_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Wiz vulnerability findings.

        Args:
            min_severity: Severity floor (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL).
            has_exploit: Optional filter for findings with a known exploit.
            resource_contains: Optional substring over the vulnerable asset name.
            limit: Max findings to return.

        Returns:
            Envelope with the matched vulnerability objects.
        """
        if self.mock_mode:
            return self._mock_list_vulnerabilities(
                min_severity, has_exploit, resource_contains, limit
            )
        return await self._real_list_vulnerabilities(
            min_severity, has_exploit, resource_contains, limit
        )

    async def wiz_resource_summary(self, resource_id: str) -> dict[str, Any]:
        """Per-resource posture rollup.

        Args:
            resource_id: The cloud resource provider id (ARN / resource id).

        Returns:
            Envelope with open-issue counts by severity, vuln counts by
            severity, exploitable-vuln count, and the public-exposure flag,
            or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_resource_summary(resource_id)
        return await self._real_resource_summary(resource_id)

    # ----- mock implementations -----

    def _mock_list_issues(
        self,
        min_severity: str,
        status: str | None,
        category_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        floor = _severity_rank(min_severity)
        issues = [
            i
            for i in WIZ_FIXTURE_ISSUES
            if _severity_rank(i.get("severity")) >= floor
            and (status is None or i.get("status") == status)
            and (
                category_contains is None
                or category_contains in str((i.get("sourceRule") or {}).get("category", ""))
            )
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_severity": min_severity,
            "issue_status": status,
            "category_contains": category_contains,
            "total": len(issues),
            "issues": issues,
        }

    def _mock_list_vulnerabilities(
        self,
        min_severity: str,
        has_exploit: bool | None,
        resource_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        floor = _severity_rank(min_severity)
        vulns = [
            v
            for v in WIZ_FIXTURE_VULNS
            if _severity_rank(v.get("severity")) >= floor
            and (has_exploit is None or bool(v.get("hasExploit")) is has_exploit)
            and (
                resource_contains is None
                or resource_contains in str((v.get("vulnerableAsset") or {}).get("name", ""))
            )
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_severity": min_severity,
            "has_exploit": has_exploit,
            "resource_contains": resource_contains,
            "total": len(vulns),
            "vulnerabilities": vulns,
        }

    def _mock_resource_summary(self, resource_id: str) -> dict[str, Any]:
        resource = WIZ_FIXTURE_RESOURCES.get(resource_id)
        if resource is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "resource_id": resource_id,
                "message": f"Resource '{resource_id}' not found in Wiz inventory",
            }
        open_issues = [
            i
            for i in WIZ_FIXTURE_ISSUES
            if (i.get("entitySnapshot") or {}).get("providerId") == resource_id
            and i.get("status") != "RESOLVED"
        ]
        vulns = [
            v
            for v in WIZ_FIXTURE_VULNS
            if (v.get("vulnerableAsset") or {}).get("providerId") == resource_id
        ]
        issue_sev: Counter[str] = Counter(str(i.get("severity")) for i in open_issues)
        vuln_sev: Counter[str] = Counter(str(v.get("severity")) for v in vulns)
        exploitable = sum(1 for v in vulns if v.get("hasExploit"))
        return {
            "status": "success",
            "is_mock": True,
            "resource_id": resource_id,
            "resource_name": resource.get("name"),
            "publicly_exposed": bool(resource.get("publiclyExposed")),
            "open_issue_count": len(open_issues),
            "open_issues_by_severity": dict(issue_sev),
            "vulnerability_count": len(vulns),
            "vulnerabilities_by_severity": dict(vuln_sev),
            "exploitable_vulnerability_count": exploitable,
            # The toxic combination CNAPP exists to surface.
            "exposed_and_exploitable": bool(resource.get("publiclyExposed")) and exploitable > 0,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_list_issues(
        self,
        min_severity: str,
        status: str | None,
        category_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "wiz: live-mode issue list refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Wiz live mode requires a resolvable API client secret (wire "
                "${secret:vault:wiz/client_secret} or set BTAGENT_WIZ_CLIENT_SECRET)."
            )
        raise NotImplementedError("Wiz live list_issues not yet implemented")

    async def _real_list_vulnerabilities(
        self,
        min_severity: str,
        has_exploit: bool | None,
        resource_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "wiz: live-mode vulnerability list refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError("Wiz live mode requires a resolvable API client secret")
        raise NotImplementedError("Wiz live list_vulnerabilities not yet implemented")

    async def _real_resource_summary(self, resource_id: str) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError("Wiz live mode requires a resolvable API client secret")
        raise NotImplementedError("Wiz live resource_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "wiz_list_issues",
                "description": (
                    "List Wiz Issues (cloud-posture / toxic-combination "
                    "findings) with a categorical severity floor, exact status, "
                    "and control-category substring. Issues carry the control "
                    "rule and the affected resource snapshot."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_severity": {
                            "type": "string",
                            "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            "description": "Severity floor",
                            "default": "LOW",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["OPEN", "IN_PROGRESS", "RESOLVED"],
                            "description": "Optional exact issue status",
                        },
                        "category_contains": {
                            "type": "string",
                            "description": "Optional substring over the control category",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max issues to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "wiz_list_vulnerabilities",
                "description": (
                    "List Wiz vulnerability findings with a severity floor, an "
                    "exploit-available filter, and a resource-name substring. "
                    "Findings carry the CVE, CVSS, fixed version, and asset."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_severity": {
                            "type": "string",
                            "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            "description": "Severity floor",
                            "default": "LOW",
                        },
                        "has_exploit": {
                            "type": "boolean",
                            "description": "Optional filter for findings with a known exploit",
                        },
                        "resource_contains": {
                            "type": "string",
                            "description": "Optional substring over the vulnerable asset name",
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
                "name": "wiz_resource_summary",
                "description": (
                    "Per-resource Wiz posture rollup: open issues by severity, "
                    "vulnerabilities by severity, exploitable-vuln count, and "
                    "public-exposure flag — the exposed-plus-exploitable toxic-"
                    "combination triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "resource_id": {
                            "type": "string",
                            "description": "Cloud resource provider id (ARN / resource id)",
                        },
                    },
                    "required": ["resource_id"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = WizMCPServer()


@tool
async def wiz_list_issues(
    min_severity: str = "LOW",
    status: str | None = None,
    category_contains: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List Wiz Issues (posture / toxic-combination findings).

    Args:
        min_severity: Severity floor (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL).
        status: Optional exact status filter (OPEN | IN_PROGRESS | RESOLVED).
        category_contains: Optional substring over the control category.
        limit: Max issues to return.
    """
    return await _server.wiz_list_issues(min_severity, status, category_contains, limit)


@tool
async def wiz_list_vulnerabilities(
    min_severity: str = "LOW",
    has_exploit: bool | None = None,
    resource_contains: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List Wiz vulnerability findings.

    Args:
        min_severity: Severity floor (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL).
        has_exploit: Optional filter for findings with a known exploit.
        resource_contains: Optional substring over the vulnerable asset name.
        limit: Max findings to return.
    """
    return await _server.wiz_list_vulnerabilities(
        min_severity, has_exploit, resource_contains, limit
    )


@tool
async def wiz_resource_summary(resource_id: str) -> dict[str, Any]:
    """Per-resource Wiz posture rollup.

    Args:
        resource_id: The cloud resource provider id (ARN / resource id).
    """
    return await _server.wiz_resource_summary(resource_id)
