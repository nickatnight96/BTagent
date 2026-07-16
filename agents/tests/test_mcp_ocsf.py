"""OCSF claim validation for MCP router results (#100 Layer 2).

Engine-parity contract for the router: same three claim-extraction
shapes, same skip semantics (no tags / empty declaration), loud refusal
on declared-vs-actual drift.
"""

from __future__ import annotations

from btagent_agents.mcp.discovery import mcp_router_tool
from btagent_agents.mcp.ocsf import extract_ocsf_claims, validate_ocsf_claims

# ---------------------------------------------------------------------------
# Claim extraction — the engine's three shapes
# ---------------------------------------------------------------------------


class TestClaimExtraction:
    def test_top_level_event_class(self) -> None:
        assert extract_ocsf_claims({"ocsf_event_class": "authentication"}) == ["authentication"]

    def test_top_level_emits_list(self) -> None:
        claims = extract_ocsf_claims({"ocsf_emits": ["authentication", "audit_activity", 7]})
        assert claims == ["authentication", "audit_activity"]

    def test_per_event_class(self) -> None:
        payload = {
            "events": [
                {"class": "authentication", "kind": "login_success"},
                {"class": "authentication"},
                {"kind": "untagged event"},
            ]
        }
        assert extract_ocsf_claims(payload) == ["authentication"]

    def test_shapes_combine_and_dedupe_preserving_order(self) -> None:
        payload = {
            "ocsf_event_class": "detection_finding",
            "ocsf_emits": ["authentication"],
            "events": [{"class": "detection_finding"}],
        }
        assert extract_ocsf_claims(payload) == ["detection_finding", "authentication"]

    def test_non_dict_payloads_have_no_claims(self) -> None:
        assert extract_ocsf_claims(None) == []
        assert extract_ocsf_claims("nope") == []
        assert extract_ocsf_claims([{"ocsf_event_class": "authentication"}]) == []


# ---------------------------------------------------------------------------
# Validation semantics
# ---------------------------------------------------------------------------


class TestValidation:
    def test_untagged_result_passes(self) -> None:
        assert validate_ocsf_claims("splunk_search", {"status": "success"}) is None

    def test_declared_claim_passes(self) -> None:
        result = {"status": "success", "ocsf_event_class": "authentication"}
        assert validate_ocsf_claims("okta_system_log_search", result) is None

    def test_per_event_declared_claims_pass(self) -> None:
        result = {"events": [{"class": "authentication"}, {"class": "audit_activity"}]}
        assert validate_ocsf_claims("okta_system_log_search", result) is None

    def test_undeclared_claim_is_a_violation(self) -> None:
        result = {"status": "success", "ocsf_event_class": "process_activity"}
        violation = validate_ocsf_claims("okta_system_log_search", result)
        assert violation is not None
        assert violation["status"] == "ocsf_violation"
        assert violation["server_id"] == "okta"
        assert violation["undeclared_seen"] == ["process_activity"]
        assert "authentication" in violation["declared"]

    def test_off_spec_class_string_is_a_violation(self) -> None:
        result = {"ocsf_event_class": "made_up_class"}
        violation = validate_ocsf_claims("okta_system_log_search", result)
        assert violation is not None
        assert violation["undeclared_seen"] == ["made_up_class"]

    def test_empty_declaration_skips_validation(self) -> None:
        # jira_get_issue declares ocsf_emits=[] (raw ticket data by contract).
        result = {"status": "success", "ocsf_event_class": "authentication"}
        assert validate_ocsf_claims("jira_get_issue", result) is None

    def test_unknown_tool_skips_validation(self) -> None:
        # Unknown tools never reach dispatch (policy fails closed first);
        # the validator itself doesn't guess.
        assert validate_ocsf_claims("totally_new_tool", {"ocsf_event_class": "x"}) is None


# ---------------------------------------------------------------------------
# Router integration
# ---------------------------------------------------------------------------


class TestRouterIntegration:
    async def test_vendor_shaped_mock_result_passes_through(self) -> None:
        """Identity-event dumps carry no 'class' key — untagged, untouched."""
        out = await mcp_router_tool.ainvoke(
            {
                "tool_name": "okta_system_log_search",
                "arguments": '{"start": "2026-06-01T00:00:00Z", "end": "2026-06-02T00:00:00Z"}',
            }
        )
        assert out["status"] == "success" and out["is_mock"] is True

    async def test_violating_result_is_refused(self, monkeypatch) -> None:
        from btagent_agents.mcp import discovery

        server, method_name = discovery._TOOL_DISPATCH.get("okta_system_log_search") or (
            None,
            None,
        )
        if server is None:
            discovery.discover_tools()
            server, method_name = discovery._TOOL_DISPATCH["okta_system_log_search"]

        async def _tagged_wrong(*args, **kwargs):
            return {"status": "success", "ocsf_event_class": "process_activity"}

        monkeypatch.setattr(server, method_name, _tagged_wrong)
        out = await mcp_router_tool.ainvoke(
            {"tool_name": "okta_system_log_search", "arguments": "{}"}
        )
        assert out["status"] == "ocsf_violation"
        assert out["undeclared_seen"] == ["process_activity"]

    async def test_correctly_tagged_result_passes(self, monkeypatch) -> None:
        from btagent_agents.mcp import discovery

        if "okta_system_log_search" not in discovery._TOOL_DISPATCH:
            discovery.discover_tools()
        server, method_name = discovery._TOOL_DISPATCH["okta_system_log_search"]

        async def _tagged_right(*args, **kwargs):
            return {"status": "success", "ocsf_event_class": "authentication"}

        monkeypatch.setattr(server, method_name, _tagged_right)
        out = await mcp_router_tool.ainvoke(
            {"tool_name": "okta_system_log_search", "arguments": "{}"}
        )
        assert out["status"] == "success"
        assert out["ocsf_event_class"] == "authentication"
