"""Phase 3 UAT -- Coordination, Report, and Mitigation features.

Run with: pytest tests/uat/test_phase3_uat.py -v

Tests cover:
- Coordination plugin: loading, tools, system prompt, summarizer
- Report plugin: loading, tools, templates, report generation
- Mitigation plugin: loading, tools, remediation, detection content
- Reports API: endpoint registration
- RBAC: report/remediation permissions
- Orchestrator wiring: new nodes in graph
- All plugins: complete registry (7 plugins)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml


# ── Coordination Plugin Tests ─────────────────────────────────────────────


class TestCoordinationPlugin:
    """Verify the Coordination plugin loads and functions correctly."""

    def test_coordination_plugin_registered(self):
        """'coordination' is in the plugin list."""
        from btagent_agents.plugins import list_plugins

        plugins = list_plugins()
        assert "coordination" in plugins, (
            f"'coordination' not in plugin list: {plugins}"
        )

    def test_coordination_plugin_loads(self):
        """Coordination plugin loads successfully."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("coordination")
        assert plugin is not None
        assert plugin.name == "coordination"

    def test_coordination_plugin_has_tools(self):
        """Coordination plugin provides 3 tools."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("coordination")
        assert plugin is not None
        tools = plugin.get_tools()
        assert len(tools) == 3
        tool_names = {t.name for t in tools}
        assert "summarize_investigation" in tool_names
        assert "summarize_multiple" in tool_names
        assert "format_agency_report" in tool_names

    def test_coordination_system_prompt_has_org_profile(self):
        """System prompt contains {org_profile} placeholder."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("coordination")
        assert plugin is not None
        prompt = plugin.get_system_prompt()
        assert "{org_profile}" in prompt

    def test_coordination_system_prompt_mentions_agencies(self):
        """System prompt mentions CISA, FBI IC3, and ISAC."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("coordination")
        assert plugin is not None
        prompt = plugin.get_system_prompt()
        assert "CISA" in prompt
        assert "FBI" in prompt or "IC3" in prompt
        assert "ISAC" in prompt

    def test_coordination_metadata(self):
        """Metadata has correct fields."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("coordination")
        assert plugin is not None
        meta = plugin.get_metadata()
        assert meta.name == "coordination"
        assert meta.version == "1.0.0"
        assert len(meta.capabilities) > 0


class TestSummarizer:
    """Verify summarization tools work correctly."""

    def test_summarize_investigation_returns_sections(self):
        """summarize_investigation returns all expected sections."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            summarize_investigation,
        )

        result = summarize_investigation.invoke({"investigation_id": "inv_mock_001"})
        assert result["status"] == "success"
        assert "executive_summary" in result
        assert "technical_summary" in result
        assert "ioc_list" in result
        assert "mitre_techniques" in result
        assert "recommendations" in result
        assert result["ioc_count"] > 0

    def test_summarize_investigation_not_found(self):
        """summarize_investigation returns error for unknown ID."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            summarize_investigation,
        )

        result = summarize_investigation.invoke({"investigation_id": "inv_nonexistent"})
        assert result["status"] == "failed"
        assert "error" in result

    def test_summarize_multiple_map_reduce(self):
        """summarize_multiple aggregates across investigations."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            summarize_multiple,
        )

        result = summarize_multiple.invoke({
            "investigation_ids": "inv_mock_001,inv_mock_002",
        })
        assert result["status"] == "success"
        assert result["investigation_count"] == 2
        assert result["aggregated_ioc_count"] > 0
        assert len(result["mitre_techniques"]) > 0
        assert len(result["merged_timeline"]) > 0
        assert len(result["individual_summaries"]) == 2

    def test_format_agency_report_cisa(self):
        """format_agency_report produces CISA-formatted output."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            format_agency_report,
            summarize_investigation,
        )

        summary = summarize_investigation.invoke({"investigation_id": "inv_mock_001"})
        result = format_agency_report.invoke({
            "summary_json": json.dumps(summary),
            "format": "cisa",
        })
        assert result["status"] == "success"
        assert result["format"] == "cisa"
        sections = result["sections"]
        assert "header" in sections
        assert "CISA" in sections["header"]

    def test_format_agency_report_fbi(self):
        """format_agency_report produces FBI IC3-formatted output."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            format_agency_report,
            summarize_investigation,
        )

        summary = summarize_investigation.invoke({"investigation_id": "inv_mock_001"})
        result = format_agency_report.invoke({
            "summary_json": json.dumps(summary),
            "format": "fbi_ic3",
        })
        assert result["status"] == "success"
        assert result["format"] == "fbi_ic3"
        sections = result["sections"]
        assert "header" in sections
        assert "IC3" in sections["header"]

    def test_format_agency_report_isac(self):
        """format_agency_report produces ISAC-formatted output."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            format_agency_report,
            summarize_investigation,
        )

        summary = summarize_investigation.invoke({"investigation_id": "inv_mock_001"})
        result = format_agency_report.invoke({
            "summary_json": json.dumps(summary),
            "format": "isac",
        })
        assert result["status"] == "success"
        assert result["format"] == "isac"

    def test_format_agency_report_invalid_format(self):
        """format_agency_report rejects invalid format."""
        from btagent_agents.plugins.coordination.tools.summarizer import (
            format_agency_report,
        )

        result = format_agency_report.invoke({
            "summary_json": "{}",
            "format": "invalid_format",
        })
        assert result["status"] == "failed"


# ── Report Plugin Tests ───────────────────────────────────────────────────


class TestReportPlugin:
    """Verify the Report plugin loads and functions correctly."""

    def test_report_plugin_registered(self):
        """'report' is in the plugin list."""
        from btagent_agents.plugins import list_plugins

        assert "report" in list_plugins()

    def test_report_plugin_loads(self):
        """Report plugin loads successfully."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("report")
        assert plugin is not None
        assert plugin.name == "report"

    def test_report_plugin_has_tools(self):
        """Report plugin provides 3 tools."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("report")
        assert plugin is not None
        tools = plugin.get_tools()
        assert len(tools) == 3
        tool_names = {t.name for t in tools}
        assert "generate_report" in tool_names
        assert "generate_section" in tool_names
        assert "list_templates" in tool_names

    def test_report_templates_listed(self):
        """list_templates returns available templates."""
        from btagent_agents.plugins.report.tools.report_generator import (
            list_templates,
        )

        result = list_templates.invoke({})
        assert result["status"] == "success"
        assert result["count"] >= 4
        template_names = [t["name"] for t in result["templates"]]
        assert "incident_report" in template_names
        assert "ioc_report" in template_names
        assert "executive_briefing" in template_names
        assert "regulatory_notification" in template_names

    def test_report_system_prompt_has_org_profile(self):
        """System prompt contains {org_profile} placeholder."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("report")
        assert plugin is not None
        prompt = plugin.get_system_prompt()
        assert "{org_profile}" in prompt


class TestReportGenerator:
    """Verify report generation tools work correctly."""

    def test_generate_report_incident_report(self):
        """generate_report produces sections for incident_report template."""
        from btagent_agents.plugins.report.tools.report_generator import (
            generate_report,
        )

        result = generate_report.invoke({
            "investigation_id": "inv_mock_001",
            "template": "incident_report",
        })
        assert result["status"] == "success"
        sections = result["sections"]
        assert "executive_summary" in sections
        assert "findings" in sections
        assert "iocs" in sections
        assert "timeline" in sections
        assert "recommendations" in sections

    def test_generate_report_executive_briefing(self):
        """generate_report works with executive_briefing template."""
        from btagent_agents.plugins.report.tools.report_generator import (
            generate_report,
        )

        result = generate_report.invoke({
            "investigation_id": "inv_mock_001",
            "template": "executive_briefing",
        })
        assert result["status"] == "success"
        assert result["section_count"] >= 3

    def test_generate_section_individual(self):
        """generate_section produces a single section."""
        from btagent_agents.plugins.report.tools.report_generator import (
            generate_section,
        )

        result = generate_section.invoke({
            "investigation_id": "inv_mock_001",
            "section": "executive_summary",
        })
        assert result["status"] == "success"
        assert "content" in result
        assert len(result["content"]) > 20

    def test_generate_section_unknown(self):
        """generate_section returns error for unknown section."""
        from btagent_agents.plugins.report.tools.report_generator import (
            generate_section,
        )

        result = generate_section.invoke({
            "investigation_id": "inv_mock_001",
            "section": "nonexistent_section",
        })
        assert result["status"] == "failed"


class TestReportTemplates:
    """Verify all 4 report templates parse correctly."""

    _TEMPLATE_DIR = (
        Path(__file__).resolve().parents[2]
        / "agents"
        / "btagent_agents"
        / "plugins"
        / "report"
        / "templates"
    )

    def test_incident_report_template(self):
        """incident_report.yaml parses and has required fields."""
        with (self._TEMPLATE_DIR / "incident_report.yaml").open() as f:
            tmpl = yaml.safe_load(f)
        assert tmpl["title"] == "Incident Response Report"
        assert len(tmpl["sections"]) >= 7
        section_names = [s["name"] for s in tmpl["sections"]]
        assert "executive_summary" in section_names
        assert "findings" in section_names

    def test_ioc_report_template(self):
        """ioc_report.yaml parses and has required fields."""
        with (self._TEMPLATE_DIR / "ioc_report.yaml").open() as f:
            tmpl = yaml.safe_load(f)
        assert tmpl["title"] == "IOC Analysis Report"
        section_names = [s["name"] for s in tmpl["sections"]]
        assert "iocs" in section_names
        assert "sharing_guidance" in section_names

    def test_executive_briefing_template(self):
        """executive_briefing.yaml parses and has required fields."""
        with (self._TEMPLATE_DIR / "executive_briefing.yaml").open() as f:
            tmpl = yaml.safe_load(f)
        assert tmpl["title"] == "Executive Briefing"
        assert len(tmpl["sections"]) >= 3

    def test_regulatory_notification_template(self):
        """regulatory_notification.yaml parses and has required fields."""
        with (self._TEMPLATE_DIR / "regulatory_notification.yaml").open() as f:
            tmpl = yaml.safe_load(f)
        assert tmpl["title"] == "Regulatory Breach Notification"
        section_names = [s["name"] for s in tmpl["sections"]]
        assert "data_affected" in section_names
        assert "timeline" in section_names


# ── Mitigation Plugin Tests ───────────────────────────────────────────────


class TestMitigationPlugin:
    """Verify the Mitigation plugin loads and functions correctly."""

    def test_mitigation_plugin_registered(self):
        """'mitigation' is in the plugin list."""
        from btagent_agents.plugins import list_plugins

        assert "mitigation" in list_plugins()

    def test_mitigation_plugin_loads(self):
        """Mitigation plugin loads successfully."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("mitigation")
        assert plugin is not None
        assert plugin.name == "mitigation"

    def test_mitigation_plugin_has_tools(self):
        """Mitigation plugin provides 3 tools."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("mitigation")
        assert plugin is not None
        tools = plugin.get_tools()
        assert len(tools) == 3
        tool_names = {t.name for t in tools}
        assert "generate_remediation" in tool_names
        assert "generate_detection_content" in tool_names
        assert "generate_hardening_recommendations" in tool_names

    def test_mitigation_system_prompt_has_org_profile(self):
        """System prompt contains {org_profile} placeholder."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("mitigation")
        assert plugin is not None
        prompt = plugin.get_system_prompt()
        assert "{org_profile}" in prompt

    def test_mitigation_system_prompt_mentions_audiences(self):
        """System prompt mentions all three audiences."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("mitigation")
        assert plugin is not None
        prompt = plugin.get_system_prompt()
        assert "executive" in prompt.lower()
        assert "technical" in prompt.lower()
        assert "compliance" in prompt.lower()


class TestRemediationGenerator:
    """Verify remediation generation produces audience-appropriate content."""

    def test_executive_remediation(self):
        """Executive audience gets business-focused guidance."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_remediation,
        )

        result = generate_remediation.invoke({
            "investigation_id": "inv_mock_001",
            "audience": "executive",
        })
        assert result["status"] == "success"
        assert result["audience"] == "executive"
        assert "business_impact" in result
        assert "actions" in result
        assert len(result["actions"]) > 0
        # Executive actions should have business_owner
        for action in result["actions"]:
            assert "business_owner" in action

    def test_technical_remediation(self):
        """Technical audience gets step-by-step commands."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_remediation,
        )

        result = generate_remediation.invoke({
            "investigation_id": "inv_mock_001",
            "audience": "technical",
        })
        assert result["status"] == "success"
        assert result["audience"] == "technical"
        assert "actions" in result
        # Technical actions should have commands
        has_commands = any(
            "commands" in action for action in result["actions"]
        )
        assert has_commands

    def test_compliance_remediation(self):
        """Compliance audience gets regulatory guidance."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_remediation,
        )

        result = generate_remediation.invoke({
            "investigation_id": "inv_mock_001",
            "audience": "compliance",
        })
        assert result["status"] == "success"
        assert result["audience"] == "compliance"
        assert "regulatory_considerations" in result
        # Should mention GDPR or HIPAA
        frameworks = [
            r["framework"]
            for r in result["regulatory_considerations"]
        ]
        assert "GDPR" in frameworks or "HIPAA" in frameworks

    def test_invalid_audience(self):
        """Invalid audience returns error."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_remediation,
        )

        result = generate_remediation.invoke({
            "investigation_id": "inv_mock_001",
            "audience": "invalid",
        })
        assert result["status"] == "failed"

    def test_hardening_recommendations(self):
        """Hardening recommendations map to NIST CSF."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_hardening_recommendations,
        )

        result = generate_hardening_recommendations.invoke({
            "investigation_id": "inv_mock_001",
        })
        assert result["status"] == "success"
        assert result["recommendation_count"] > 0
        assert len(result["nist_csf_functions_covered"]) > 0
        # Each recommendation should have nist_csf and cis_control
        for rec in result["recommendations"]:
            assert "nist_csf" in rec
            assert "cis_control" in rec
            assert "priority" in rec


class TestDetectionContent:
    """Verify detection content generation produces valid rules."""

    def test_splunk_detection_rules(self):
        """Splunk rules use SPL syntax."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_detection_content,
        )

        result = generate_detection_content.invoke({
            "investigation_id": "inv_mock_001",
            "platform": "splunk",
        })
        assert result["status"] == "success"
        assert result["platform"] == "splunk"
        assert result["rule_count"] > 0
        for rule in result["rules"]:
            assert rule["language"] == "spl"
            assert "index=" in rule["rule"] or "index=*" in rule["rule"]

    def test_elastic_detection_rules(self):
        """Elastic rules use KQL syntax."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_detection_content,
        )

        result = generate_detection_content.invoke({
            "investigation_id": "inv_mock_001",
            "platform": "elastic",
        })
        assert result["status"] == "success"
        assert result["platform"] == "elastic"
        assert result["rule_count"] > 0
        for rule in result["rules"]:
            assert rule["language"] == "kql"

    def test_sentinel_detection_rules(self):
        """Sentinel rules use KQL syntax."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_detection_content,
        )

        result = generate_detection_content.invoke({
            "investigation_id": "inv_mock_001",
            "platform": "sentinel",
        })
        assert result["status"] == "success"
        assert result["platform"] == "sentinel"
        assert result["rule_count"] > 0
        for rule in result["rules"]:
            assert rule["language"] == "kql"

    def test_invalid_platform(self):
        """Invalid platform returns error."""
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_detection_content,
        )

        result = generate_detection_content.invoke({
            "investigation_id": "inv_mock_001",
            "platform": "invalid_platform",
        })
        assert result["status"] == "failed"


# ── Reports API Tests ─────────────────────────────────────────────────────


class TestReportsAPI:
    """Verify reports API router is mounted and has all endpoints."""

    def test_reports_router_imported(self):
        """Reports router is importable."""
        from btagent_backend.api.v1.reports import router

        assert router is not None
        assert router.prefix == "/reports"

    def test_reports_router_in_v1(self):
        """Reports router is included in the v1 API router."""
        from btagent_backend.api.v1.router import api_v1_router

        route_paths = [r.path for r in api_v1_router.routes if hasattr(r, "path")]
        # FastAPI includes the prefix in route paths
        has_reports = any("/reports" in p for p in route_paths)
        assert has_reports, f"No /reports routes in: {route_paths}"

    def test_generate_endpoint_exists(self):
        """POST /reports/generate endpoint exists."""
        from btagent_backend.api.v1.reports import router

        paths_and_methods = [
            (r.path, list(r.methods)) for r in router.routes
            if hasattr(r, "methods")
        ]
        assert any(
            "/generate" in p and "POST" in m
            for p, m in paths_and_methods
        ), f"POST /generate not found in: {paths_and_methods}"

    def test_templates_endpoint_exists(self):
        """GET /reports/templates endpoint exists."""
        from btagent_backend.api.v1.reports import router

        paths_and_methods = [
            (r.path, list(r.methods)) for r in router.routes
            if hasattr(r, "methods")
        ]
        assert any(
            "/templates" in p and "GET" in m
            for p, m in paths_and_methods
        ), f"GET /templates not found in: {paths_and_methods}"

    def test_summarize_endpoint_exists(self):
        """POST /reports/summarize endpoint exists."""
        from btagent_backend.api.v1.reports import router

        paths_and_methods = [
            (r.path, list(r.methods)) for r in router.routes
            if hasattr(r, "methods")
        ]
        assert any(
            "/summarize" in p and "POST" in m
            for p, m in paths_and_methods
        ), f"POST /summarize not found in: {paths_and_methods}"

    def test_remediation_endpoint_exists(self):
        """POST /reports/remediation endpoint exists."""
        from btagent_backend.api.v1.reports import router

        paths_and_methods = [
            (r.path, list(r.methods)) for r in router.routes
            if hasattr(r, "methods")
        ]
        assert any(
            "/remediation" in p and "POST" in m
            for p, m in paths_and_methods
        ), f"POST /remediation not found in: {paths_and_methods}"

    def test_detection_content_endpoint_exists(self):
        """POST /reports/detection-content endpoint exists."""
        from btagent_backend.api.v1.reports import router

        paths_and_methods = [
            (r.path, list(r.methods)) for r in router.routes
            if hasattr(r, "methods")
        ]
        assert any(
            "/detection-content" in p and "POST" in m
            for p, m in paths_and_methods
        ), f"POST /detection-content not found in: {paths_and_methods}"


# ── RBAC Tests ────────────────────────────────────────────────────────────


class TestRBAC:
    """Verify report/remediation permissions are defined."""

    def test_report_view_permission(self):
        """report:view permission exists and allows analyst."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "report:view")

    def test_report_generate_permission(self):
        """report:generate permission exists and allows analyst."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "report:generate")

    def test_report_summarize_permission(self):
        """report:summarize requires senior_analyst."""
        from btagent_backend.auth.rbac import has_permission

        assert not has_permission("analyst", "report:summarize")
        assert has_permission("senior_analyst", "report:summarize")

    def test_remediation_generate_permission(self):
        """remediation:generate permission exists."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "remediation:generate")


# ── Orchestrator Wiring Tests ─────────────────────────────────────────────


class TestOrchestratorWiring:
    """Verify report/coordination/mitigation are wired into the graph."""

    def test_report_in_task_keywords(self):
        """'report' task type has routing keywords."""
        from btagent_agents.orchestrator.nodes import _TASK_KEYWORDS

        assert "report" in _TASK_KEYWORDS
        assert len(_TASK_KEYWORDS["report"]) > 0

    def test_coordination_in_task_keywords(self):
        """'coordination' task type has routing keywords."""
        from btagent_agents.orchestrator.nodes import _TASK_KEYWORDS

        assert "coordination" in _TASK_KEYWORDS
        assert len(_TASK_KEYWORDS["coordination"]) > 0

    def test_mitigation_in_task_keywords(self):
        """'mitigation' task type has routing keywords."""
        from btagent_agents.orchestrator.nodes import _TASK_KEYWORDS

        assert "mitigation" in _TASK_KEYWORDS
        assert len(_TASK_KEYWORDS["mitigation"]) > 0

    def test_graph_has_report_node(self):
        """Compiled graph includes 'report' node."""
        from btagent_agents.orchestrator.graph import create_investigation_graph

        graph = create_investigation_graph()
        node_names = set(graph.get_graph().nodes.keys())
        assert "report" in node_names

    def test_graph_has_coordination_node(self):
        """Compiled graph includes 'coordination' node."""
        from btagent_agents.orchestrator.graph import create_investigation_graph

        graph = create_investigation_graph()
        node_names = set(graph.get_graph().nodes.keys())
        assert "coordination" in node_names

    def test_graph_has_mitigation_node(self):
        """Compiled graph includes 'mitigation' node."""
        from btagent_agents.orchestrator.graph import create_investigation_graph

        graph = create_investigation_graph()
        node_names = set(graph.get_graph().nodes.keys())
        assert "mitigation" in node_names

    def test_route_to_agent_handles_new_types(self):
        """route_to_agent correctly routes coordination and mitigation."""
        from btagent_agents.orchestrator.edges import route_to_agent

        assert route_to_agent({"task_type": "coordination"}) == "coordination"
        assert route_to_agent({"task_type": "mitigation"}) == "mitigation"
        assert route_to_agent({"task_type": "report"}) == "report"

    def test_coordination_node_function(self):
        """coordination_node runs without error."""
        from btagent_agents.orchestrator.nodes import coordination_node

        result = coordination_node({
            "investigation_id": "inv_mock_001",
            "messages": [],
            "timeline": [],
        })
        assert "messages" in result
        assert result["current_agent"] == "coordination"

    def test_mitigation_node_function(self):
        """mitigation_node runs without error."""
        from btagent_agents.orchestrator.nodes import mitigation_node

        result = mitigation_node({
            "investigation_id": "inv_mock_001",
            "messages": [],
            "timeline": [],
        })
        assert "messages" in result
        assert result["current_agent"] == "mitigation"


# ── Event Types Tests ─────────────────────────────────────────────────────


class TestEventTypes:
    """Verify Phase 3 event types are defined."""

    def test_report_generation_started_event(self):
        """REPORT_GENERATION_STARTED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "REPORT_GENERATION_STARTED")
        assert EventType.REPORT_GENERATION_STARTED == "report_generation_started"

    def test_report_generation_complete_event(self):
        """REPORT_GENERATION_COMPLETE event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "REPORT_GENERATION_COMPLETE")
        assert EventType.REPORT_GENERATION_COMPLETE == "report_generation_complete"

    def test_remediation_generated_event(self):
        """REMEDIATION_GENERATED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "REMEDIATION_GENERATED")
        assert EventType.REMEDIATION_GENERATED == "remediation_generated"


# ── All Plugins Integration Test ──────────────────────────────────────────


class TestAllPlugins:
    """Verify all 7 plugins load correctly."""

    EXPECTED_PLUGINS = [
        "triage",
        "query",
        "enrichment",
        "knowledge",
        "coordination",
        "report",
        "mitigation",
    ]

    def test_all_seven_plugins_registered(self):
        """All 7 plugins are registered in PLUGIN_MODULES."""
        from btagent_agents.plugins import list_plugins

        plugins = list_plugins()
        for name in self.EXPECTED_PLUGINS:
            assert name in plugins, f"Plugin '{name}' not in registry: {plugins}"

    def test_all_seven_plugins_load(self):
        """All 7 plugins load successfully."""
        from btagent_agents.plugins import load_plugin

        for name in self.EXPECTED_PLUGINS:
            plugin = load_plugin(name)
            assert plugin is not None, f"Plugin '{name}' failed to load"
            assert plugin.name == name

    def test_all_plugins_have_tools(self):
        """All 7 plugins provide at least 2 tools."""
        from btagent_agents.plugins import load_plugin

        for name in self.EXPECTED_PLUGINS:
            plugin = load_plugin(name)
            assert plugin is not None
            tools = plugin.get_tools()
            assert len(tools) >= 2, (
                f"Plugin '{name}' has only {len(tools)} tool(s)"
            )

    def test_all_plugins_have_system_prompts(self):
        """All 7 plugins have non-empty system prompts."""
        from btagent_agents.plugins import load_plugin

        for name in self.EXPECTED_PLUGINS:
            plugin = load_plugin(name)
            assert plugin is not None
            prompt = plugin.get_system_prompt()
            assert len(prompt) > 50, (
                f"Plugin '{name}' system prompt too short ({len(prompt)} chars)"
            )

    def test_all_plugins_have_metadata(self):
        """All 7 plugins return valid metadata."""
        from btagent_agents.plugins import load_plugin

        for name in self.EXPECTED_PLUGINS:
            plugin = load_plugin(name)
            assert plugin is not None
            meta = plugin.get_metadata()
            assert meta.name == name
            assert meta.version
            assert meta.description


# ── Subgraph Tests ────────────────────────────────────────────────────────


class TestSubgraphs:
    """Verify Phase 3 subgraphs compile and run."""

    def test_coordination_graph_compiles(self):
        """Coordination subgraph compiles successfully."""
        from btagent_agents.coordination.graph import create_coordination_graph

        graph = create_coordination_graph()
        assert graph is not None
        node_names = set(graph.get_graph().nodes.keys())
        assert "collect_data" in node_names
        assert "summarize" in node_names
        assert "format" in node_names
        assert "review" in node_names

    def test_report_graph_compiles(self):
        """Report subgraph compiles successfully."""
        from btagent_agents.report.graph import create_report_graph

        graph = create_report_graph()
        assert graph is not None
        node_names = set(graph.get_graph().nodes.keys())
        assert "select_template" in node_names
        assert "gather_data" in node_names
        assert "generate_sections" in node_names
        assert "review_consistency" in node_names
        assert "compile" in node_names

    def test_mitigation_graph_compiles(self):
        """Mitigation subgraph compiles successfully."""
        from btagent_agents.mitigation.graph import create_mitigation_graph

        graph = create_mitigation_graph()
        assert graph is not None
        node_names = set(graph.get_graph().nodes.keys())
        assert "analyze_attack" in node_names
        assert "generate_remediation" in node_names
        assert "generate_detection" in node_names
        assert "compile_playbook" in node_names
