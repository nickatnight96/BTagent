"""AWS CloudTrail + GuardDuty MCP server connector — Tier-1 slice (#100).

First cloud connector ("Cloud-IR is the fastest-growing case class"); the
data plane the deferred Cloud Control-Plane Hunter types
(:mod:`btagent_shared.types.cloud_hunt`) point at. Built in the modern
Tier-1 style (fixtures module, lazy ``${secret:…}`` resolution, guarded live
mode, full contract tests).

CloudTrail / GuardDuty are read-only telemetry surfaces — like the Zeek
connector there is no mutation / containment capability and therefore no
HITL-gated tool (cloud containment lands with the IAM response playbooks,
not the telemetry connector).

Capabilities:

- ``aws_cloudtrail_lookup_events(start, end, event_name=None,
  username=None, limit=100)`` — LookupEvents-style search over CloudTrail
  records (exact ``eventName``, exact ``userIdentity.userName``).
- ``aws_guardduty_list_findings(min_severity=0.0, type_contains=None,
  limit=50)`` — GuardDuty findings with a severity floor and a finding-type
  substring filter.
- ``aws_cloudtrail_principal_summary(principal, start, end)`` — behavioral
  rollup for one IAM principal: per-eventName counts, distinct source IPs,
  regions touched, and denied calls — the "is this key acting weird"
  triage signal (mirrors ``zeek_connection_summary``).

Secret hygiene mirrors the sibling connectors: the AWS secret access key is
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

from btagent_agents.mcp.servers._cloudtrail_fixtures import (
    CLOUDTRAIL_FIXTURE_EVENTS,
    GUARDDUTY_FIXTURE_FINDINGS,
)

logger = logging.getLogger("btagent.mcp.servers.cloudtrail")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


def _parse_aws_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("cloudtrail: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the AWS secret access key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:aws-secret-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# AWS CloudTrail / GuardDuty MCP server class
# ---------------------------------------------------------------------------
class CloudTrailMCPServer:
    """AWS CloudTrail + GuardDuty MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls AWS unless explicitly opted out AND a secret access key
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "cloudtrail"

    DEFAULT_ACCESS_KEY_ID_REF: str = "${env:BTAGENT_AWS_ACCESS_KEY_ID}"
    DEFAULT_SECRET_KEY_REF: str = "${secret:vault:aws/secret_access_key}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        region: str | None = None,
        access_key_id_ref: str | None = None,
        secret_key_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.region: str = region or os.getenv("BTAGENT_AWS_REGION") or "us-east-1"
        self._access_key_id_ref: str = access_key_id_ref or self.DEFAULT_ACCESS_KEY_ID_REF
        self._secret_key_ref: str = secret_key_ref or self.DEFAULT_SECRET_KEY_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"CloudTrailMCPServer(server_id={self.server_id!r}, "
            f"region={self.region!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_secret_key(self) -> str:
        """Resolve the AWS secret access key lazily from the configured ref."""
        resolved: str = resolve_secret(self._secret_key_ref)
        return resolved

    # ----- tools -----

    async def aws_cloudtrail_lookup_events(
        self,
        start: str,
        end: str,
        event_name: str | None = None,
        username: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search CloudTrail records for a time window.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            event_name: Optional exact eventName filter (e.g. "CreateUser").
            username: Optional exact userIdentity.userName filter.
            limit: Max records to return.

        Returns:
            Envelope with the matched CloudTrail records.
        """
        if self.mock_mode:
            return self._mock_lookup_events(start, end, event_name, username, limit)
        return await self._real_lookup_events(start, end, event_name, username, limit)

    async def aws_guardduty_list_findings(
        self,
        min_severity: float = 0.0,
        type_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List GuardDuty findings.

        Args:
            min_severity: Severity floor (GuardDuty scale, 0.1–8.9).
            type_contains: Optional substring over the finding type
                (e.g. "CredentialExfiltration", "Recon:").
            limit: Max findings to return.

        Returns:
            Envelope with the finding objects (resource + action details).
        """
        if self.mock_mode:
            return self._mock_list_findings(min_severity, type_contains, limit)
        return await self._real_list_findings(min_severity, type_contains, limit)

    async def aws_cloudtrail_principal_summary(
        self,
        principal: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Behavioral CloudTrail rollup for one IAM principal.

        Args:
            principal: userIdentity.userName to summarise.
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with per-eventName counts, distinct source IPs, regions
            touched, access keys used, and denied calls.
        """
        if self.mock_mode:
            return self._mock_principal_summary(principal, start, end)
        return await self._real_principal_summary(principal, start, end)

    # ----- mock implementations -----

    def _events_in_window(self, start: str, end: str) -> list[dict[str, Any]]:
        start_dt = _parse_aws_timestamp(start)
        end_dt = _parse_aws_timestamp(end)
        return [
            e
            for e in CLOUDTRAIL_FIXTURE_EVENTS
            if start_dt <= _parse_aws_timestamp(e.get("eventTime")) < end_dt
        ]

    def _mock_lookup_events(
        self,
        start: str,
        end: str,
        event_name: str | None,
        username: str | None,
        limit: int,
    ) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        for evt in self._events_in_window(start, end):
            if event_name is not None and evt.get("eventName") != event_name:
                continue
            if username is not None and (evt.get("userIdentity") or {}).get("userName") != username:
                continue
            records.append(evt)
            if len(records) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "event_name": event_name,
            "username": username,
            "total": len(records),
            "records": records,
        }

    def _mock_list_findings(
        self,
        min_severity: float,
        type_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        findings = [
            f
            for f in GUARDDUTY_FIXTURE_FINDINGS
            if float(f.get("severity") or 0) >= min_severity
            and (type_contains is None or type_contains in str(f.get("type", "")))
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_severity": min_severity,
            "type_contains": type_contains,
            "total": len(findings),
            "findings": findings,
        }

    def _mock_principal_summary(self, principal: str, start: str, end: str) -> dict[str, Any]:
        events = [
            e
            for e in self._events_in_window(start, end)
            if (e.get("userIdentity") or {}).get("userName") == principal
        ]
        if not events:
            return {
                "status": "not_found",
                "is_mock": True,
                "principal": principal,
                "message": f"No CloudTrail activity for principal '{principal}' in the window",
            }
        by_event: Counter[str] = Counter()
        source_ips: set[str] = set()
        regions: set[str] = set()
        access_keys: set[str] = set()
        denied: list[dict[str, Any]] = []
        for e in events:
            by_event[str(e.get("eventName"))] += 1
            source_ips.add(str(e.get("sourceIPAddress")))
            regions.add(str(e.get("awsRegion")))
            key = (e.get("userIdentity") or {}).get("accessKeyId")
            if key:
                access_keys.add(str(key))
            if e.get("errorCode"):
                denied.append(
                    {
                        "eventName": e.get("eventName"),
                        "errorCode": e.get("errorCode"),
                        "sourceIPAddress": e.get("sourceIPAddress"),
                        "eventTime": e.get("eventTime"),
                    }
                )
        return {
            "status": "success",
            "is_mock": True,
            "principal": principal,
            "start": start,
            "end": end,
            "total_events": len(events),
            "events_by_name": dict(by_event.most_common()),
            "distinct_source_ips": sorted(source_ips),
            "regions": sorted(regions),
            "access_keys_used": sorted(access_keys),
            "denied_calls": denied,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_lookup_events(
        self,
        start: str,
        end: str,
        event_name: str | None,
        username: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "cloudtrail: live-mode lookup refused — no secret access key (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "AWS live mode requires a resolvable secret access key (wire "
                "${secret:vault:aws/secret_access_key} or set "
                "BTAGENT_AWS_SECRET_ACCESS_KEY)."
            )
        raise NotImplementedError("CloudTrail live lookup_events not yet implemented")

    async def _real_list_findings(
        self,
        min_severity: float,
        type_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "cloudtrail: live-mode GuardDuty list refused — no secret access key (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError("AWS live mode requires a resolvable secret access key")
        raise NotImplementedError("GuardDuty live list_findings not yet implemented")

    async def _real_principal_summary(self, principal: str, start: str, end: str) -> dict[str, Any]:
        secret = self._get_secret_key()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError("AWS live mode requires a resolvable secret access key")
        raise NotImplementedError("CloudTrail live principal_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "aws_cloudtrail_lookup_events",
                "description": (
                    "Search AWS CloudTrail records for a time window with "
                    "exact eventName / userName filters. Records carry the "
                    "full userIdentity, source IP, region, and errorCode."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "event_name": {
                            "type": "string",
                            "description": "Optional exact eventName (e.g. CreateUser)",
                        },
                        "username": {
                            "type": "string",
                            "description": "Optional exact userIdentity.userName",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max records to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "aws_guardduty_list_findings",
                "description": (
                    "List AWS GuardDuty findings with a severity floor and a "
                    "finding-type substring filter (credential exfiltration, "
                    "recon, policy hygiene, …)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_severity": {
                            "type": "number",
                            "description": "Severity floor (GuardDuty 0.1–8.9 scale)",
                            "default": 0.0,
                        },
                        "type_contains": {
                            "type": "string",
                            "description": "Optional substring over the finding type",
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
                "name": "aws_cloudtrail_principal_summary",
                "description": (
                    "Behavioral CloudTrail rollup for one IAM principal: "
                    "per-API call counts, distinct source IPs, regions "
                    "touched, access keys used, denied calls — the "
                    "compromised-credential triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "principal": {
                            "type": "string",
                            "description": "userIdentity.userName to summarise",
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
_server = CloudTrailMCPServer()


@tool
async def aws_cloudtrail_lookup_events(
    start: str,
    end: str,
    event_name: str | None = None,
    username: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search AWS CloudTrail records for a time window.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        event_name: Optional exact eventName filter (e.g. "CreateUser").
        username: Optional exact userIdentity.userName filter.
        limit: Max records to return.
    """
    return await _server.aws_cloudtrail_lookup_events(start, end, event_name, username, limit)


@tool
async def aws_guardduty_list_findings(
    min_severity: float = 0.0,
    type_contains: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List AWS GuardDuty findings.

    Args:
        min_severity: Severity floor (GuardDuty 0.1–8.9 scale).
        type_contains: Optional substring over the finding type.
        limit: Max findings to return.
    """
    return await _server.aws_guardduty_list_findings(min_severity, type_contains, limit)


@tool
async def aws_cloudtrail_principal_summary(
    principal: str,
    start: str,
    end: str,
) -> dict[str, Any]:
    """Behavioral CloudTrail rollup for one IAM principal.

    Args:
        principal: userIdentity.userName to summarise.
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.aws_cloudtrail_principal_summary(principal, start, end)
