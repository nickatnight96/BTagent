"""Unit tests for the Wiz CNAPP MCP connector (#100 Tier-2 slice).

First cloud-security-posture connector — mirrors the CloudTrail/GCP suites
(read-only telemetry, no HITL action) so the cloud connectors stay exercised
symmetrically.

Coverage:
- Issue list: categorical severity floor, exact status, category substring,
  composition, limit.
- Vulnerability list: severity floor, exploit-available filter, resource
  substring, limit.
- Resource summary: open-issue / vuln severity rollups, exploitable count,
  the exposed-plus-exploitable toxic-combination flag, not-found envelope.
- Cross-surface joins: issues ↔ vulns ↔ inventory on providerId; the toxic-
  combination story coheres on vm-web-01.
- Live mode refuses without a client secret; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
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
from btagent_agents.mcp.servers._wiz_fixtures import (
    EXPOSED_RESOURCE_ID,
    WIZ_FIXTURE_ISSUES,
    WIZ_FIXTURE_VULNS,
)
from btagent_agents.mcp.servers.wiz_mcp import (
    WizMCPServer,
    _redact_secret,
)


def _server() -> WizMCPServer:
    return WizMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Issue list mock
# ---------------------------------------------------------------------------


class TestListIssues:
    async def test_all_issues_by_default(self) -> None:
        out = await _server().wiz_list_issues()
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(WIZ_FIXTURE_ISSUES)

    async def test_severity_floor(self) -> None:
        out = await _server().wiz_list_issues(min_severity="HIGH")
        assert out["total"] == 1
        assert out["issues"][0]["severity"] == "HIGH"

    async def test_status_filter(self) -> None:
        out = await _server().wiz_list_issues(status="OPEN")
        assert out["total"] == 2
        assert all(i["status"] == "OPEN" for i in out["issues"])

    async def test_category_contains_filter(self) -> None:
        out = await _server().wiz_list_issues(category_contains="Data Exposure")
        assert out["total"] == 1
        assert out["issues"][0]["entitySnapshot"]["name"] == "s3-analytics-raw"

    async def test_filters_compose_to_empty(self) -> None:
        out = await _server().wiz_list_issues(min_severity="CRITICAL", status="OPEN")
        assert out["total"] == 0

    async def test_limit_caps_issues(self) -> None:
        out = await _server().wiz_list_issues(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Vulnerability list mock
# ---------------------------------------------------------------------------


class TestListVulnerabilities:
    async def test_all_vulns_by_default(self) -> None:
        out = await _server().wiz_list_vulnerabilities()
        assert out["total"] == len(WIZ_FIXTURE_VULNS)

    async def test_severity_floor(self) -> None:
        out = await _server().wiz_list_vulnerabilities(min_severity="HIGH")
        assert out["total"] == 1
        assert out["vulnerabilities"][0]["name"] == "CVE-2026-1337"

    async def test_has_exploit_filter(self) -> None:
        out = await _server().wiz_list_vulnerabilities(has_exploit=True)
        assert out["total"] == 1
        assert out["vulnerabilities"][0]["cvssScore"] == 9.8

    async def test_has_exploit_false_filter(self) -> None:
        out = await _server().wiz_list_vulnerabilities(has_exploit=False)
        assert out["total"] == 1
        assert out["vulnerabilities"][0]["name"] == "CVE-2025-4521"

    async def test_resource_contains_filter(self) -> None:
        out = await _server().wiz_list_vulnerabilities(resource_contains="vm-web-01")
        assert out["total"] == 1

    async def test_limit_caps_vulns(self) -> None:
        out = await _server().wiz_list_vulnerabilities(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Resource summary
# ---------------------------------------------------------------------------


class TestResourceSummary:
    async def test_exposed_and_exploitable_flagged(self) -> None:
        out = await _server().wiz_resource_summary(EXPOSED_RESOURCE_ID)
        assert out["status"] == "success"
        assert out["publicly_exposed"] is True
        assert out["exploitable_vulnerability_count"] == 1
        assert out["exposed_and_exploitable"] is True
        assert out["open_issues_by_severity"]["HIGH"] == 1

    async def test_clean_resource_not_toxic(self) -> None:
        out = await _server().wiz_resource_summary(
            "arn:aws:ec2:us-east-1:123456789012:instance/i-0batch07"
        )
        assert out["status"] == "success"
        assert out["publicly_exposed"] is False
        # The resolved LOW issue is excluded; one non-exploitable vuln remains.
        assert out["open_issue_count"] == 0
        assert out["exploitable_vulnerability_count"] == 0
        assert out["exposed_and_exploitable"] is False

    async def test_exposed_bucket_without_vuln_not_toxic(self) -> None:
        out = await _server().wiz_resource_summary("arn:aws:s3:::s3-analytics-raw")
        assert out["publicly_exposed"] is True
        assert out["vulnerability_count"] == 0
        assert out["exposed_and_exploitable"] is False

    async def test_unknown_resource_not_found(self) -> None:
        out = await _server().wiz_resource_summary("arn:aws:ec2:us-east-1:0:instance/i-ghost")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Cross-surface joins — the toxic-combination story
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_issues_join_inventory_on_provider_id(self) -> None:
        from btagent_agents.mcp.servers._wiz_fixtures import WIZ_FIXTURE_RESOURCES

        resource_ids = set(WIZ_FIXTURE_RESOURCES)
        for issue in WIZ_FIXTURE_ISSUES:
            assert issue["entitySnapshot"]["providerId"] in resource_ids

    def test_vulns_join_inventory_on_provider_id(self) -> None:
        from btagent_agents.mcp.servers._wiz_fixtures import WIZ_FIXTURE_RESOURCES

        resource_ids = set(WIZ_FIXTURE_RESOURCES)
        for vuln in WIZ_FIXTURE_VULNS:
            assert vuln["vulnerableAsset"]["providerId"] in resource_ids

    async def test_story_coheres_exposed_host_has_exploitable_vuln(self) -> None:
        issues = await _server().wiz_list_issues(category_contains="Network Exposure")
        vulns = await _server().wiz_list_vulnerabilities(has_exploit=True)
        exposed_rid = issues["issues"][0]["entitySnapshot"]["providerId"]
        exploit_rid = vulns["vulnerabilities"][0]["vulnerableAsset"]["providerId"]
        assert exposed_rid == exploit_rid == EXPOSED_RESOURCE_ID


# ---------------------------------------------------------------------------
# Live mode refuses without a client secret
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_WIZ_CLIENT_SECRET", raising=False)
        server = WizMCPServer(mock_mode=False, client_secret_ref="${env:BTAGENT_WIZ_CLIENT_SECRET}")
        with pytest.raises(NotImplementedError):
            await server.wiz_list_issues()
        with pytest.raises(NotImplementedError):
            await server.wiz_list_vulnerabilities()
        with pytest.raises(NotImplementedError):
            await server.wiz_resource_summary(EXPOSED_RESOURCE_ID)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_WIZ_CLIENT_SECRET", "wiz-secret-0123456789abcdef")
        server = WizMCPServer(mock_mode=False, client_secret_ref="${env:BTAGENT_WIZ_CLIENT_SECRET}")
        with pytest.raises(NotImplementedError):
            await server.wiz_list_issues()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = WizMCPServer(mock_mode=False, client_secret_ref="${env:BTAGENT_WIZ_CLIENT_SECRET}")
        assert "wiz-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("wiz-secret-0123456789abcdef")
        assert out.startswith("[redacted:wiz-client-secret:")
        assert "wiz-secret-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_WIZ_CLIENT_SECRET", "wiz-secret-0123456789abcdef")
        server = WizMCPServer(mock_mode=False, client_secret_ref="${env:BTAGENT_WIZ_CLIENT_SECRET}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.wiz"):
            with pytest.raises(NotImplementedError):
                await server.wiz_list_issues()
        for record in caplog.records:
            assert "wiz-secret-0123456789abcdef" not in record.getMessage()


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
            name="wiz",
            description="wiz test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("wiz", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("wiz", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_wiz_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "wiz" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["wiz"] is WizMCPServer

    def test_tool_metadata_marks_wiz_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "wiz_list_issues",
            "wiz_list_vulnerabilities",
            "wiz_resource_summary",
        }
        assert all(m["server_id"] == "wiz" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.wiz_mcp.resolve_secret", _spy)
    WizMCPServer(mock_mode=False)
    assert calls == []
