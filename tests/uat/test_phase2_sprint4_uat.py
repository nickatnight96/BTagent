"""Phase 2 Sprint 4 UAT -- Integration, E2E, and cross-cutting validation.

Run with: pytest tests/uat/test_phase2_sprint4_uat.py -v

Tests cover:
- Plugin registration and loading (enrichment, knowledge)
- Playbook template validation
- API endpoint existence (IOC, MITRE, Knowledge, Playbook)
- Event type completeness
- RBAC permission completeness
- Plugin and MCP server importability
- Knowledge injector and MITRE mapper integration
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml


# ── Plugin Registration Tests ──────────────────────────────────────────────


class TestPluginRegistration:
    """Verify Phase 2 plugins are registered and loadable."""

    def test_enrichment_plugin_registered(self):
        """'enrichment' is in the plugin list."""
        from btagent_agents.plugins import list_plugins

        plugins = list_plugins()
        assert "enrichment" in plugins, (
            f"'enrichment' not in plugin list: {plugins}"
        )

    def test_knowledge_plugin_registered(self):
        """'knowledge' is in the plugin list."""
        from btagent_agents.plugins import list_plugins

        plugins = list_plugins()
        assert "knowledge" in plugins, (
            f"'knowledge' not in plugin list: {plugins}"
        )

    def test_triage_plugin_registered(self):
        """'triage' is in the plugin list (Phase 1 baseline)."""
        from btagent_agents.plugins import list_plugins

        assert "triage" in list_plugins()

    def test_query_plugin_registered(self):
        """'query' is in the plugin list (Phase 1 baseline)."""
        from btagent_agents.plugins import list_plugins

        assert "query" in list_plugins()


# ── Playbook Template Tests ────────────────────────────────────────────────


class TestPlaybookTemplates:
    """Verify all 3 pre-built playbooks parse and validate."""

    def _template_dir(self) -> Path:
        return (
            Path(__file__).resolve().parents[2]
            / "agents"
            / "btagent_agents"
            / "playbook"
            / "templates"
        )

    def test_playbook_templates_loadable(self):
        """All 3 pre-built playbooks parse as valid YAML and validate."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        template_dir = self._template_dir()

        template_names = [
            "phishing_response.yaml",
            "ransomware_containment.yaml",
            "credential_compromise.yaml",
        ]

        for name in template_names:
            path = template_dir / name
            assert path.exists(), f"Template not found: {path}"

            yaml_str = path.read_text()
            data = yaml.safe_load(yaml_str)
            assert isinstance(data, dict), f"{name} did not parse as dict"
            assert "name" in data, f"{name} missing 'name' field"
            assert "steps" in data, f"{name} missing 'steps' field"

            result = svc.validate_playbook(yaml_str)
            assert result.valid is True, (
                f"Template {name} validation failed: {result.errors}"
            )


# ── Playbook Execution Record ─────────────────────────────────────────────


class TestPlaybookExecution:
    """Verify playbook execution creates expected records."""

    def test_playbook_execution_creates_record(self):
        """PlaybookExecutionRow can be instantiated with required fields."""
        from btagent_backend.db.models_playbook import PlaybookExecutionRow

        row = PlaybookExecutionRow(
            id="pbe_test_001",
            playbook_id="pb_test_001",
            investigation_id="inv_test_001",
            status="running",
            trigger_data={"type": "manual"},
            step_results=[],
        )
        assert row.id == "pbe_test_001"
        assert row.status == "running"
        assert row.step_results == []


# ── API Endpoint Existence Tests ───────────────────────────────────────────


class TestKnowledgeAPI:
    """Verify Knowledge API endpoints exist."""

    def test_knowledge_ingest_api(self):
        """POST /knowledge/ingest endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods))
            for r in router.routes
            if hasattr(r, "methods")
        }
        assert ("/knowledge/ingest", ("POST",)) in routes

    def test_knowledge_query_api(self):
        """POST /knowledge/query endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods))
            for r in router.routes
            if hasattr(r, "methods")
        }
        assert ("/knowledge/query", ("POST",)) in routes


class TestIOCAPI:
    """Verify IOC API endpoints exist."""

    def test_ioc_enrichment_api(self):
        """POST /iocs/{ioc_id}/enrich endpoint is defined."""
        from btagent_backend.api.v1.iocs import router

        route_paths = [r.path for r in router.routes]
        assert "/iocs/{ioc_id}/enrich" in route_paths, (
            f"Enrich endpoint not found. Routes: {route_paths}"
        )


class TestMitreAPI:
    """Verify MITRE ATT&CK API endpoints exist."""

    def test_mitre_techniques_api(self):
        """GET /mitre/techniques endpoint is defined."""
        from btagent_backend.api.v1.mitre import router

        route_paths = [r.path for r in router.routes]
        assert "/mitre/techniques" in route_paths, (
            f"Techniques endpoint not found. Routes: {route_paths}"
        )


class TestPlaybookAPICRUD:
    """Verify playbook CRUD endpoints exist."""

    def test_playbook_api_crud(self):
        """Playbook router has create/list/get/delete endpoints."""
        from btagent_backend.api.v1.playbooks import router

        routes = {
            (r.path, tuple(r.methods))
            for r in router.routes
            if hasattr(r, "methods")
        }

        # Create
        assert ("/playbooks", ("POST",)) in routes, "Missing POST /playbooks"
        # List
        assert ("/playbooks", ("GET",)) in routes, "Missing GET /playbooks"
        # Get detail
        route_paths = [r.path for r in router.routes]
        assert "/playbooks/{playbook_id}" in route_paths, (
            "Missing GET /playbooks/{playbook_id}"
        )
        # Delete
        assert ("/playbooks/{playbook_id}", ("DELETE",)) in routes, (
            "Missing DELETE /playbooks/{playbook_id}"
        )


# ── Event Type Completeness ───────────────────────────────────────────────


class TestEventTypes:
    """Verify all Phase 2 event types are defined."""

    def test_all_event_types_defined(self):
        """All Phase 2 event types exist in EventType enum."""
        from btagent_shared.types.events import EventType

        required_events = [
            # Investigation lifecycle
            "INVESTIGATION_INIT",
            "INVESTIGATION_COMPLETE",
            "INVESTIGATION_FAILED",
            "INVESTIGATION_PAUSED",
            "INVESTIGATION_RESUMED",
            # IOC enrichment events
            "IOC_DISCOVERED",
            "IOC_ENRICHED",
            "IOC_ENRICHMENT_STARTED",
            "IOC_ENRICHMENT_COMPLETE",
            # Knowledge events
            "KNOWLEDGE_INDEXED",
            "KNOWLEDGE_QUERIED",
            # Playbook events
            "PLAYBOOK_STARTED",
            "PLAYBOOK_STEP_COMPLETE",
            "PLAYBOOK_COMPLETE",
            "PLAYBOOK_FAILED",
            "PLAYBOOK_HITL_GATE",
            # Agent events
            "THINKING",
            "OUTPUT",
            "TOOL_START",
            "TOOL_END",
            "HITL_CHECKPOINT",
            "HITL_RESPONSE",
            # Defensive events
            "ALERT_CLASSIFIED",
            "CONTAINMENT_PROPOSED",
            "CONTAINMENT_APPROVED",
            "CONTAINMENT_EXECUTED",
            "QUERY_GENERATED",
        ]

        for event_name in required_events:
            assert hasattr(EventType, event_name), (
                f"Missing EventType.{event_name}"
            )


# ── RBAC Permission Completeness ──────────────────────────────────────────


class TestRBACPermissions:
    """Verify all Phase 2 permissions are defined."""

    def test_all_rbac_permissions_defined(self):
        """All Phase 2 permissions exist in the PERMISSIONS dict."""
        from btagent_backend.auth.rbac import PERMISSIONS

        required_permissions = [
            # IOC permissions
            "ioc:view",
            "ioc:create",
            "ioc:edit",
            "ioc:delete",
            "ioc:enrich",
            "ioc:export",
            # Knowledge permissions
            "knowledge:query",
            "knowledge:ingest",
            "knowledge:delete",
            # Playbook permissions
            "playbook:view",
            "playbook:create",
            "playbook:edit",
            "playbook:delete",
            "playbook:execute",
            "playbook:execute_containment",
            # Investigation permissions
            "investigation:view",
            "investigation:create",
            "investigation:chat",
            "investigation:pause",
            "investigation:resume",
            "investigation:stop",
            "investigation:delete",
            # HITL permissions
            "hitl:approve",
            "hitl:reject",
            # Containment permissions
            "containment:propose",
            "containment:approve",
            "containment:execute",
            # Config permissions
            "config:view",
            "config:edit",
            "config:org_profile",
            # User permissions
            "user:view",
            "user:create",
            "user:edit",
            "user:delete",
            # Webhook
            "webhook:manage",
        ]

        for perm in required_permissions:
            assert perm in PERMISSIONS, f"Missing RBAC permission: {perm}"


# ── Plugin Load Tests ─────────────────────────────────────────────────────


class TestPluginLoad:
    """Verify all 4 plugins load successfully."""

    def test_all_plugins_load(self):
        """All 4 plugins (triage, query, enrichment, knowledge) load."""
        from btagent_agents.plugins import load_plugin

        expected_plugins = ["triage", "query", "enrichment", "knowledge"]

        for name in expected_plugins:
            plugin = load_plugin(name)
            assert plugin is not None, f"Plugin '{name}' failed to load"
            assert hasattr(plugin, "name"), (
                f"Plugin '{name}' missing 'name' property"
            )
            assert hasattr(plugin, "get_tools"), (
                f"Plugin '{name}' missing 'get_tools' method"
            )


# ── MCP Server Import Tests ───────────────────────────────────────────────


class TestMCPServerImport:
    """Verify all MCP servers are importable."""

    def test_all_mcp_servers_importable(self):
        """All 9 MCP servers import without errors."""
        mcp_server_modules = [
            "btagent_agents.mcp.servers.splunk_mcp",
            "btagent_agents.mcp.servers.crowdstrike_mcp",
            "btagent_agents.mcp.servers.sentinel_mcp",
            "btagent_agents.mcp.servers.elastic_mcp",
            "btagent_agents.mcp.servers.virustotal_mcp",
            "btagent_agents.mcp.servers.shodan_mcp",
            "btagent_agents.mcp.servers.greynoise_mcp",
            "btagent_agents.mcp.servers.abuseipdb_mcp",
            "btagent_agents.mcp.servers.misp_mcp",
        ]

        import importlib

        for module_path in mcp_server_modules:
            try:
                mod = importlib.import_module(module_path)
                assert mod is not None, f"Module {module_path} returned None"
            except ImportError as exc:
                pytest.fail(
                    f"MCP server module {module_path} failed to import: {exc}"
                )


# ── Integration Wiring Tests ──────────────────────────────────────────────


class TestIntegrationWiring:
    """Verify Phase 2 integration wiring is in place."""

    def test_mitre_mapper_importable(self):
        """MitreMapper can be imported and instantiated."""
        from btagent_agents.mitre import MitreMapper

        mapper = MitreMapper()
        assert mapper is not None

    def test_mitre_mapper_suggests_techniques(self):
        """MitreMapper returns suggestions for known keywords."""
        from btagent_agents.mitre import MitreMapper

        mapper = MitreMapper()
        results = mapper.suggest_techniques("phishing email with malware attachment")
        assert len(results) > 0
        technique_ids = [r.technique_id for r in results]
        # Phishing should match T1566.*
        assert any(t.startswith("T1566") for t in technique_ids), (
            f"Expected T1566.* in results, got: {technique_ids}"
        )

    def test_knowledge_injector_importable(self):
        """Knowledge injector can be imported."""
        from btagent_agents.orchestrator.knowledge_injector import (
            inject_knowledge_context,
        )

        assert callable(inject_knowledge_context)

    def test_knowledge_injector_no_url_returns_empty(self):
        """Knowledge injector with no URL returns empty context."""
        from btagent_agents.orchestrator.knowledge_injector import (
            inject_knowledge_context,
        )

        state: dict[str, Any] = {
            "investigation_id": "inv_test",
            "iocs": [],
            "severity": "medium",
            "task_type": "triage",
            "messages": [],
        }
        result = inject_knowledge_context(state, knowledge_service_url="")
        assert result["knowledge_context"] == ""

    def test_investigation_state_has_knowledge_context(self):
        """InvestigationState TypedDict includes knowledge_context field."""
        from btagent_agents.orchestrator.state import InvestigationState

        annotations = InvestigationState.__annotations__
        assert "knowledge_context" in annotations, (
            "knowledge_context field missing from InvestigationState"
        )

    def test_graph_knowledge_route_exists(self):
        """The should_continue edge supports 'knowledge' routing."""
        from btagent_agents.orchestrator.edges import should_continue

        # Verify the function handles the knowledge routing path
        import inspect

        source = inspect.getsource(should_continue)
        assert "knowledge" in source, (
            "should_continue does not contain 'knowledge' routing"
        )
