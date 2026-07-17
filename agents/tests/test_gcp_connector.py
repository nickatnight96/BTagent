"""Unit tests for the GCP Cloud Audit Logs / SCC MCP connector (#100 Tier-2 slice).

Second cloud connector — mirrors the CloudTrail suite (read-only telemetry, no
HITL action) so the cloud connectors stay exercised symmetrically.

Coverage:
- Audit-log search: window filtering, exact methodName / principalEmail
  filters, limit.
- SCC findings: categorical severity floor, category-substring filter,
  composition.
- Principal summary: per-method counts, distinct caller-IP / project
  accounting, denied-call extraction, not-found envelope, window narrowing.
- Cross-surface joins: SCC findings ↔ audit entries on principalEmail / caller
  IP; the service-account-key-abuse story coheres.
- Live mode refuses without a service-account key; secret redaction; lazy
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
from btagent_agents.mcp.servers._gcp_fixtures import (
    ATTACKER_IP,
    GCP_FIXTURE_AUDIT_ENTRIES,
    GCP_FIXTURE_SCC_FINDINGS,
    SERVICE_ACCOUNT,
)
from btagent_agents.mcp.servers.gcp_mcp import (
    GCPCloudAuditMCPServer,
    _redact_secret,
)

# Fixture window covering every recorded audit entry.
WINDOW_START = "2026-07-05T00:00:00Z"
WINDOW_END = "2026-07-06T00:00:00Z"


def _server() -> GCPCloudAuditMCPServer:
    return GCPCloudAuditMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Audit-log search mock
# ---------------------------------------------------------------------------


class TestAuditLogSearch:
    async def test_bare_search_returns_all_in_window(self) -> None:
        out = await _server().gcp_audit_log_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(GCP_FIXTURE_AUDIT_ENTRIES)

    async def test_method_name_filter_exact(self) -> None:
        out = await _server().gcp_audit_log_search(
            WINDOW_START, WINDOW_END, method_name="storage.buckets.get"
        )
        assert out["total"] == 1
        assert out["entries"][0]["protoPayload"]["authenticationInfo"]["principalEmail"] == (
            "jvega@acme.com"
        )

    async def test_principal_filter_exact(self) -> None:
        out = await _server().gcp_audit_log_search(
            WINDOW_START, WINDOW_END, principal=SERVICE_ACCOUNT
        )
        assert out["total"] == 4

    async def test_filters_compose(self) -> None:
        out = await _server().gcp_audit_log_search(
            WINDOW_START, WINDOW_END, method_name="SetIamPolicy", principal=SERVICE_ACCOUNT
        )
        assert out["total"] == 2

    async def test_time_window_excludes_entries(self) -> None:
        # The four SA-abuse entries fall in 02:11–02:13; jvega's is at 09:30.
        out = await _server().gcp_audit_log_search("2026-07-05T02:00:00Z", "2026-07-05T03:00:00Z")
        assert out["total"] == 4

    async def test_limit_caps_entries(self) -> None:
        out = await _server().gcp_audit_log_search(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# SCC findings mock
# ---------------------------------------------------------------------------


class TestSccFindings:
    async def test_all_findings_by_default(self) -> None:
        out = await _server().gcp_scc_list_findings()
        assert out["total"] == len(GCP_FIXTURE_SCC_FINDINGS)

    async def test_severity_floor(self) -> None:
        out = await _server().gcp_scc_list_findings(min_severity="HIGH")
        # HIGH priv-esc + CRITICAL key-creation clear the floor; LOW hygiene doesn't.
        assert out["total"] == 2
        assert all(f["severity"] in ("HIGH", "CRITICAL") for f in out["findings"])

    async def test_category_contains_filter(self) -> None:
        out = await _server().gcp_scc_list_findings(category_contains="Service Account Key")
        assert out["total"] == 1
        assert out["findings"][0]["severity"] == "CRITICAL"

    async def test_filters_compose_to_empty(self) -> None:
        out = await _server().gcp_scc_list_findings(
            min_severity="CRITICAL", category_contains="Misconfiguration"
        )
        assert out["total"] == 0

    async def test_limit_caps_findings(self) -> None:
        out = await _server().gcp_scc_list_findings(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Principal summary
# ---------------------------------------------------------------------------


class TestPrincipalSummary:
    async def test_summary_counts_and_ips(self) -> None:
        out = await _server().gcp_audit_principal_summary(SERVICE_ACCOUNT, WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["total_entries"] == 4
        assert out["distinct_caller_ips"] == [ATTACKER_IP]
        assert out["projects"] == ["acme-prod-1"]

    async def test_denied_calls_extracted(self) -> None:
        out = await _server().gcp_audit_principal_summary(SERVICE_ACCOUNT, WINDOW_START, WINDOW_END)
        denied = out["denied_calls"]
        assert len(denied) == 1
        assert denied[0]["methodName"] == "SetIamPolicy"
        assert denied[0]["callerIp"] == ATTACKER_IP

    async def test_methods_by_name_rollup(self) -> None:
        out = await _server().gcp_audit_principal_summary(SERVICE_ACCOUNT, WINDOW_START, WINDOW_END)
        by_name = out["methods_by_name"]
        assert by_name["SetIamPolicy"] == 2
        assert sum(by_name.values()) == out["total_entries"]

    async def test_unknown_principal_not_found(self) -> None:
        out = await _server().gcp_audit_principal_summary(
            "ghost@acme.com", WINDOW_START, WINDOW_END
        )
        assert out["status"] == "not_found"

    async def test_window_narrows_summary(self) -> None:
        out = await _server().gcp_audit_principal_summary(
            "jvega@acme.com", "2026-07-05T09:00:00Z", "2026-07-05T10:00:00Z"
        )
        assert out["total_entries"] == 1
        assert out["denied_calls"] == []


# ---------------------------------------------------------------------------
# Cross-surface joins — the service-account-key-abuse story
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_scc_findings_join_audit_on_principal(self) -> None:
        audit_principals = {
            e["protoPayload"]["authenticationInfo"]["principalEmail"]
            for e in GCP_FIXTURE_AUDIT_ENTRIES
        }
        finding_principals = {
            f["sourceProperties"]["principalEmail"]
            for f in GCP_FIXTURE_SCC_FINDINGS
            if "principalEmail" in f["sourceProperties"]
        }
        assert finding_principals
        assert finding_principals <= audit_principals

    def test_scc_caller_ip_matches_audit_attacker_ip(self) -> None:
        for f in GCP_FIXTURE_SCC_FINDINGS:
            ip = f["sourceProperties"].get("callerIp")
            if ip is not None:
                assert ip == ATTACKER_IP

    async def test_story_coheres_finding_to_audit_entry(self) -> None:
        """The priv-esc finding's principal shows a SetIamPolicy in the audit log."""
        out = await _server().gcp_audit_log_search(
            WINDOW_START, WINDOW_END, method_name="SetIamPolicy", principal=SERVICE_ACCOUNT
        )
        assert out["total"] == 2
        assert all(
            e["protoPayload"]["requestMetadata"]["callerIp"] == ATTACKER_IP for e in out["entries"]
        )


# ---------------------------------------------------------------------------
# Live mode refuses without a service-account key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutKey:
    async def test_live_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_GCP_SA_KEY", raising=False)
        server = GCPCloudAuditMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GCP_SA_KEY}")
        with pytest.raises(NotImplementedError):
            await server.gcp_audit_log_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.gcp_scc_list_findings()
        with pytest.raises(NotImplementedError):
            await server.gcp_audit_principal_summary(SERVICE_ACCOUNT, WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_GCP_SA_KEY", "gcp-sa-key-0123456789abcdef")
        server = GCPCloudAuditMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GCP_SA_KEY}")
        with pytest.raises(NotImplementedError):
            await server.gcp_scc_list_findings()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = GCPCloudAuditMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GCP_SA_KEY}")
        assert "gcp-sa-key" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("gcp-sa-key-0123456789abcdef")
        assert out.startswith("[redacted:gcp-sa-key:")
        assert "gcp-sa-key-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_GCP_SA_KEY", "gcp-sa-key-0123456789abcdef")
        server = GCPCloudAuditMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GCP_SA_KEY}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.gcp"):
            with pytest.raises(NotImplementedError):
                await server.gcp_audit_log_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "gcp-sa-key-0123456789abcdef" not in record.getMessage()


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
            name="gcp",
            description="gcp test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("gcp", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("gcp", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_gcp_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "gcp" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["gcp"] is GCPCloudAuditMCPServer

    def test_tool_metadata_marks_gcp_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "gcp_audit_log_search",
            "gcp_scc_list_findings",
            "gcp_audit_principal_summary",
        }
        assert all(m["server_id"] == "gcp" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.gcp_mcp.resolve_secret", _spy)
    GCPCloudAuditMCPServer(mock_mode=False)
    assert calls == []
