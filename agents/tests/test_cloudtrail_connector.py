"""Unit tests for the AWS CloudTrail / GuardDuty MCP connector (#100 Tier-1 slice).

First cloud connector — mirrors the Zeek suite (read-only telemetry, no HITL
action) so the modern Tier-1 connectors stay exercised symmetrically.

Coverage:
- CloudTrail lookup: window filtering, exact eventName / userName filters,
  limit.
- GuardDuty findings: severity floor, type-substring filter, composition.
- Principal summary: per-eventName counts, distinct IP / region / access-key
  accounting, denied-call extraction, not-found envelope, window narrowing.
- Cross-surface joins: GuardDuty access-key findings ↔ CloudTrail records on
  userName / accessKeyId / attacker IP; the compromised-key story coheres.
- Live mode refuses without a secret access key; secret redaction; lazy
  secret resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._cloudtrail_fixtures import (
    ATTACKER_IP,
    CLOUDTRAIL_FIXTURE_EVENTS,
    GUARDDUTY_FIXTURE_FINDINGS,
    STOLEN_ACCESS_KEY_ID,
)
from btagent_agents.mcp.servers.cloudtrail_mcp import (
    CloudTrailMCPServer,
    _redact_secret,
)

# Fixture window covering every recorded CloudTrail event.
WINDOW_START = "2026-06-25T00:00:00Z"
WINDOW_END = "2026-06-26T00:00:00Z"

PRINCIPAL = "ci-deploy"


def _server() -> CloudTrailMCPServer:
    return CloudTrailMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# CloudTrail lookup mock
# ---------------------------------------------------------------------------


class TestLookupEvents:
    async def test_bare_lookup_returns_all_in_window(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(CLOUDTRAIL_FIXTURE_EVENTS)

    async def test_event_name_filter_exact(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(
            WINDOW_START, WINDOW_END, event_name="CreateUser"
        )
        assert out["total"] == 1
        assert out["records"][0]["requestParameters"]["userName"] == "svc-maint"

    async def test_username_filter_exact(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(
            WINDOW_START, WINDOW_END, username="ops-admin"
        )
        assert out["total"] == 1
        assert out["records"][0]["eventName"] == "DescribeInstances"

    async def test_filters_compose(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(
            WINDOW_START, WINDOW_END, event_name="PutObject", username=PRINCIPAL
        )
        assert out["total"] == 1
        assert out["records"][0]["sourceIPAddress"] == "10.0.9.5"

    async def test_time_window_excludes_records(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(
            "2026-06-25T11:00:00Z", "2026-06-25T11:06:00Z"
        )
        assert out["total"] == 3  # GetCallerIdentity, ListBuckets, denied CreateAccessKey

    async def test_limit_caps_records(self) -> None:
        out = await _server().aws_cloudtrail_lookup_events(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# GuardDuty findings mock
# ---------------------------------------------------------------------------


class TestGuardDutyFindings:
    async def test_all_findings_by_default(self) -> None:
        out = await _server().aws_guardduty_list_findings()
        assert out["total"] == len(GUARDDUTY_FIXTURE_FINDINGS)

    async def test_severity_floor(self) -> None:
        out = await _server().aws_guardduty_list_findings(min_severity=7.0)
        assert out["total"] == 1
        assert "CredentialExfiltration" in out["findings"][0]["type"]

    async def test_type_contains_filter(self) -> None:
        out = await _server().aws_guardduty_list_findings(type_contains="Recon:")
        assert out["total"] == 1
        assert out["findings"][0]["severity"] == 5.1

    async def test_filters_compose_to_empty(self) -> None:
        out = await _server().aws_guardduty_list_findings(min_severity=7.0, type_contains="Policy:")
        assert out["total"] == 0

    async def test_limit_caps_findings(self) -> None:
        out = await _server().aws_guardduty_list_findings(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Principal summary
# ---------------------------------------------------------------------------


class TestPrincipalSummary:
    async def test_summary_counts_and_regions(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(PRINCIPAL, WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["total_events"] == 7
        assert set(out["regions"]) == {"us-east-1", "eu-west-3"}
        assert out["distinct_source_ips"] == sorted(["10.0.9.5", ATTACKER_IP])

    async def test_denied_calls_extracted(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(PRINCIPAL, WINDOW_START, WINDOW_END)
        denied = out["denied_calls"]
        assert {d["eventName"] for d in denied} == {"CreateAccessKey", "RunInstances"}
        assert all(d["errorCode"] == "AccessDenied" for d in denied)
        assert all(d["sourceIPAddress"] == ATTACKER_IP for d in denied)

    async def test_events_by_name_rollup(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(PRINCIPAL, WINDOW_START, WINDOW_END)
        by_name = out["events_by_name"]
        assert by_name["PutObject"] == 1
        assert by_name["CreateUser"] == 1
        assert sum(by_name.values()) == out["total_events"]

    async def test_access_keys_used(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(PRINCIPAL, WINDOW_START, WINDOW_END)
        assert out["access_keys_used"] == [STOLEN_ACCESS_KEY_ID]

    async def test_unknown_principal_not_found(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(
            "ghost-user", WINDOW_START, WINDOW_END
        )
        assert out["status"] == "not_found"

    async def test_window_narrows_summary_to_baseline(self) -> None:
        out = await _server().aws_cloudtrail_principal_summary(
            PRINCIPAL, "2026-06-25T08:00:00Z", "2026-06-25T09:00:00Z"
        )
        assert out["total_events"] == 1
        assert out["regions"] == ["us-east-1"]
        assert out["denied_calls"] == []


# ---------------------------------------------------------------------------
# Cross-surface joins — the compromised-key story
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_guardduty_key_findings_join_cloudtrail_on_username_and_key(self) -> None:
        key_findings = [
            f for f in GUARDDUTY_FIXTURE_FINDINGS if f["resource"]["resourceType"] == "AccessKey"
        ]
        assert key_findings
        ct_users = {
            (e["userIdentity"]["userName"], e["userIdentity"]["accessKeyId"])
            for e in CLOUDTRAIL_FIXTURE_EVENTS
        }
        for f in key_findings:
            details = f["resource"]["accessKeyDetails"]
            assert (details["userName"], details["accessKeyId"]) in ct_users

    def test_guardduty_remote_ip_matches_cloudtrail_attacker_ip(self) -> None:
        for f in GUARDDUTY_FIXTURE_FINDINGS:
            if f["resource"]["resourceType"] != "AccessKey":
                continue
            remote = f["service"]["action"]["awsApiCallAction"]["remoteIpDetails"]["ipAddressV4"]
            assert remote == ATTACKER_IP

    async def test_story_coheres_finding_api_to_cloudtrail_record(self) -> None:
        """The exfiltration finding's triggering API appears in CloudTrail."""
        exfil = GUARDDUTY_FIXTURE_FINDINGS[0]
        api = exfil["service"]["action"]["awsApiCallAction"]["api"]
        out = await _server().aws_cloudtrail_lookup_events(
            WINDOW_START, WINDOW_END, event_name=api, username=PRINCIPAL
        )
        assert out["total"] == 1
        assert out["records"][0]["sourceIPAddress"] == ATTACKER_IP


# ---------------------------------------------------------------------------
# Live mode refuses without a secret access key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_AWS_SECRET_ACCESS_KEY", raising=False)
        server = CloudTrailMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_AWS_SECRET_ACCESS_KEY}"
        )
        with pytest.raises(NotImplementedError):
            await server.aws_cloudtrail_lookup_events(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.aws_guardduty_list_findings()
        with pytest.raises(NotImplementedError):
            await server.aws_cloudtrail_principal_summary(PRINCIPAL, WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_AWS_SECRET_ACCESS_KEY", "aws-secret-0123456789abcdef")
        server = CloudTrailMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_AWS_SECRET_ACCESS_KEY}"
        )
        with pytest.raises(NotImplementedError):
            await server.aws_guardduty_list_findings()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = CloudTrailMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_AWS_SECRET_ACCESS_KEY}"
        )
        assert "aws-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("aws-secret-0123456789abcdef")
        assert out.startswith("[redacted:aws-secret-key:")
        assert "aws-secret-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_AWS_SECRET_ACCESS_KEY", "aws-secret-0123456789abcdef")
        server = CloudTrailMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_AWS_SECRET_ACCESS_KEY}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.cloudtrail"):
            with pytest.raises(NotImplementedError):
                await server.aws_cloudtrail_lookup_events(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "aws-secret-0123456789abcdef" not in record.getMessage()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def setup_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    def teardown_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    async def test_breaker_opens_after_failures_and_blocks(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="cloudtrail",
            description="cloudtrail test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("cloudtrail", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("cloudtrail", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_cloudtrail_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "cloudtrail" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["cloudtrail"] is CloudTrailMCPServer

    def test_tool_metadata_marks_cloudtrail_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "aws_cloudtrail_lookup_events",
            "aws_guardduty_list_findings",
            "aws_cloudtrail_principal_summary",
        }
        assert all(m["server_id"] == "cloudtrail" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.cloudtrail_mcp.resolve_secret", _spy)
    CloudTrailMCPServer(mock_mode=False)
    assert calls == []
