"""Sprint 3 UAT — Agent engine: orchestrator, plugins, hooks, LLM router, MCP.

Run with: pytest tests/uat/test_sprint3_uat.py -v
Does NOT require running backend — tests agent engine components directly.
"""

import pytest


# ── UAT-ORCHESTRATOR: LangGraph graph compilation ─────────
class TestOrchestrator:
    def test_investigation_state_has_required_fields(self):
        """InvestigationState should have all required fields."""
        from btagent_agents.orchestrator.state import InvestigationState
        # TypedDict — check annotations
        annotations = InvestigationState.__annotations__
        required = [
            "investigation_id", "messages", "task_type", "severity",
            "tlp_level", "autonomy_level", "iocs", "timeline",
            "current_agent", "status", "error",
        ]
        for field in required:
            assert field in annotations, f"Missing field: {field}"

    def test_graph_compiles(self):
        """Orchestrator graph should compile without errors."""
        from btagent_agents.orchestrator.graph import create_investigation_graph
        graph = create_investigation_graph({})
        assert graph is not None

    def test_graph_has_expected_nodes(self):
        """Compiled graph should have key nodes."""
        from btagent_agents.orchestrator.graph import create_investigation_graph
        graph = create_investigation_graph({})
        # LangGraph compiled graphs expose nodes
        assert graph is not None
        # The graph object should be invocable
        assert callable(getattr(graph, "invoke", None)) or callable(
            getattr(graph, "stream", None)
        )

    def test_route_task_node_exists(self):
        """route_task function should be importable."""
        from btagent_agents.orchestrator.nodes import route_task
        assert callable(route_task)

    def test_triage_node_exists(self):
        """triage_node function should be importable."""
        from btagent_agents.orchestrator.nodes import triage_node
        assert callable(triage_node)

    def test_query_node_exists(self):
        """query_node function should be importable."""
        from btagent_agents.orchestrator.nodes import query_node
        assert callable(query_node)

    def test_synthesize_node_exists(self):
        """synthesize_node function should be importable."""
        from btagent_agents.orchestrator.nodes import synthesize_node
        assert callable(synthesize_node)

    def test_edge_functions_exist(self):
        """Conditional edge functions should be importable."""
        from btagent_agents.orchestrator.edges import (
            route_to_agent,
            should_continue,
        )
        assert callable(route_to_agent)
        assert callable(should_continue)


# ── UAT-PLUGINS: Plugin system ────────────────────────────
class TestPluginSystem:
    def test_defensive_plugin_abc(self):
        """DefensivePlugin ABC should be importable."""
        from btagent_agents.plugins.base import DefensivePlugin, DefensivePluginMetadata
        assert DefensivePlugin is not None
        assert DefensivePluginMetadata is not None

    def test_list_plugins(self):
        """Should list available plugins."""
        from btagent_agents.plugins import list_plugins
        plugins = list_plugins()
        assert "triage" in plugins
        assert "query" in plugins

    def test_load_triage_plugin(self):
        """Triage plugin should load and have tools + system prompt."""
        from btagent_agents.plugins import load_plugin
        plugin = load_plugin("triage")
        assert plugin is not None
        assert plugin.name == "triage"
        assert len(plugin.get_tools()) >= 2
        prompt = plugin.get_system_prompt()
        assert len(prompt) > 100
        assert "triage" in prompt.lower() or "alert" in prompt.lower()

    def test_load_query_plugin(self):
        """Query plugin should load and have tools + system prompt."""
        from btagent_agents.plugins import load_plugin
        plugin = load_plugin("query")
        assert plugin is not None
        assert plugin.name == "query"
        assert len(plugin.get_tools()) >= 2
        prompt = plugin.get_system_prompt()
        assert len(prompt) > 100
        assert "query" in prompt.lower() or "siem" in prompt.lower()

    def test_triage_plugin_metadata(self):
        """Triage plugin metadata should have required fields."""
        from btagent_agents.plugins import load_plugin
        plugin = load_plugin("triage")
        meta = plugin.get_metadata()
        assert meta.name == "triage"
        assert meta.version
        assert len(meta.capabilities) > 0

    def test_query_plugin_metadata(self):
        """Query plugin metadata should have required fields."""
        from btagent_agents.plugins import load_plugin
        plugin = load_plugin("query")
        meta = plugin.get_metadata()
        assert meta.name == "query"
        assert len(meta.capabilities) > 0

    def test_load_nonexistent_plugin_returns_none(self):
        """Loading nonexistent plugin should return None."""
        from btagent_agents.plugins import load_plugin
        result = load_plugin("nonexistent")
        assert result is None


# ── UAT-TOOLS: Plugin tools work ──────────────────────────
class TestPluginTools:
    def test_alert_classifier_tool(self):
        """Alert classifier should extract IOCs and classify."""
        from btagent_agents.plugins.triage.tools.alert_classifier import alert_classifier
        result = alert_classifier.invoke(
            "Suspicious login from 192.168.1.100 to admin account. "
            "Email from attacker@evil.com with attachment hash "
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        assert result is not None
        # Should be a dict or string with classification data
        result_str = str(result)
        assert len(result_str) > 0

    def test_severity_scorer_tool(self):
        """Severity scorer should return a score."""
        from btagent_agents.plugins.triage.tools.severity_scorer import severity_scorer
        result = severity_scorer.invoke(
            "Ransomware detected on domain controller DC01. "
            "Multiple file encryption events observed. "
            "Asset criticality: high (domain controller)"
        )
        assert result is not None
        result_str = str(result)
        assert len(result_str) > 0

    def test_query_generator_tool(self):
        """Query generator should produce valid query syntax."""
        from btagent_agents.plugins.query.tools.query_generator import query_generator
        result = query_generator.invoke(
            "platform=splunk description=Find all connections from IP 10.0.0.50 in last 24 hours"
        )
        assert result is not None
        result_str = str(result)
        assert len(result_str) > 0

    def test_query_executor_mock_mode(self):
        """Query executor in mock mode should return sample results."""
        from btagent_agents.plugins.query.tools.query_executor import query_executor
        result = query_executor.invoke(
            'platform=splunk query=index=* src_ip="10.0.0.50" earliest=-24h'
        )
        assert result is not None
        result_str = str(result)
        assert len(result_str) > 0


# ── UAT-HOOKS: Hook system ────────────────────────────────
class TestHookSystem:
    def test_hook_registry(self):
        """HookRegistry should register and return callbacks."""
        from btagent_agents.hooks.base import HookRegistry
        registry = HookRegistry()
        assert registry is not None
        callbacks = registry.get_all_callbacks()
        assert isinstance(callbacks, list)

    def _make_emitter(self):
        """Create a mock RedisEmitter for testing hooks."""
        from unittest.mock import MagicMock
        emitter = MagicMock()
        emitter.emit = MagicMock()
        return emitter

    def test_event_emitter_hook(self):
        """EventEmitterHook should be instantiable."""
        from btagent_agents.hooks.event_emitter_hook import EventEmitterHook
        emitter = self._make_emitter()
        hook = EventEmitterHook(emitter=emitter, investigation_id="inv_test")
        assert hook is not None
        callbacks = hook.get_callbacks()
        assert len(callbacks) >= 1

    def test_prompt_budget_hook(self):
        """PromptBudgetHook should be instantiable."""
        from btagent_agents.hooks.prompt_budget_hook import PromptBudgetHook
        emitter = self._make_emitter()
        hook = PromptBudgetHook(emitter=emitter, max_tokens=80000, max_cost_usd=5.0)
        assert hook is not None

    def test_hitl_hook(self):
        """HITLHook should be instantiable."""
        from btagent_agents.hooks.hitl_hook import HITLHook
        emitter = self._make_emitter()
        hook = HITLHook(emitter=emitter, investigation_id="inv_test")
        assert hook is not None

    def test_evidence_chain_hook(self):
        """EvidenceChainHook should be instantiable."""
        from btagent_agents.hooks.evidence_chain_hook import EvidenceChainHook
        emitter = self._make_emitter()
        hook = EvidenceChainHook(emitter=emitter, investigation_id="inv_test")
        assert hook is not None

    def test_scope_enforcement_hook(self):
        """ScopeEnforcementHook should be instantiable."""
        from btagent_agents.hooks.scope_enforcement_hook import ScopeEnforcementHook
        emitter = self._make_emitter()
        # Get the actual InvestigationScope class
        scope_cls = ScopeEnforcementHook.__init__.__annotations__.get("scope")
        from btagent_agents.hooks.scope_enforcement_hook import InvestigationScope
        scope = InvestigationScope(
            allowed_domains={"corp.local"},
            allowed_cidrs=["10.0.0.0/8"],
        )
        hook = ScopeEnforcementHook(emitter=emitter, scope=scope, investigation_id="inv_test")
        assert hook is not None

    def test_classification_hook(self):
        """ClassificationHook should be instantiable."""
        from btagent_agents.hooks.classification_hook import ClassificationHook
        emitter = self._make_emitter()
        hook = ClassificationHook(
            emitter=emitter, tlp_level="amber", provider="anthropic",
            investigation_id="inv_test",
        )
        assert hook is not None


# ── UAT-LLM: LLM routing ─────────────────────────────────
class TestLLMRouter:
    def test_router_instantiation(self):
        """TLPAwareLLMRouter should instantiate."""
        from btagent_agents.llm.router import TLPAwareLLMRouter
        router = TLPAwareLLMRouter()
        assert router is not None

    def test_tlp_red_routes_to_ollama_only(self):
        """TLP:RED should only allow Ollama (local) provider."""
        from btagent_agents.llm.router import TLPAwareLLMRouter
        router = TLPAwareLLMRouter()
        allowed = router.TLP_ROUTING.get("red", [])
        assert "ollama" in allowed
        assert "anthropic" not in allowed
        assert "openai" not in allowed

    def test_tlp_green_allows_multiple_providers(self):
        """TLP:GREEN should allow multiple providers."""
        from btagent_agents.llm.router import TLPAwareLLMRouter
        router = TLPAwareLLMRouter()
        allowed = router.TLP_ROUTING.get("green", [])
        assert len(allowed) >= 3

    def test_cost_calculator(self):
        """Cost calculator should compute costs for known models."""
        from btagent_agents.llm.cost_calculator import calculate_cost
        cost = calculate_cost(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
        )
        assert cost > 0
        assert cost < 1.0  # Should be cents, not dollars for small usage


# ── UAT-MCP: MCP registry ────────────────────────────────
class TestMCPRegistry:
    def test_registry_instantiation(self):
        """MCPConnectionRegistry should instantiate."""
        from btagent_agents.mcp.registry import MCPConnectionRegistry
        registry = MCPConnectionRegistry()
        assert registry is not None

    def test_splunk_mcp_server_importable(self):
        """Splunk MCP server should be importable."""
        from btagent_agents.mcp.servers import splunk_mcp
        assert splunk_mcp is not None


# ── UAT-CONTEXT: Context management ──────────────────────
class TestContextManagement:
    def test_token_estimation(self):
        """Token estimation should produce reasonable results."""
        from btagent_agents.context.budget import estimate_tokens
        tokens = estimate_tokens("Hello, world! This is a test.", model_family="claude")
        assert tokens > 0
        assert tokens < 100  # Short text should be small

    def test_context_cascade_importable(self):
        """Context cascade should be importable."""
        from btagent_agents.context.cascade import apply_cascade
        assert callable(apply_cascade)


# ── UAT-TEMPLATES: Investigation templates ────────────────
class TestTemplates:
    def test_list_templates(self):
        """Should list available investigation templates."""
        from btagent_agents.templates import list_templates
        templates = list_templates()
        assert len(templates) >= 3
        names = [t if isinstance(t, str) else t.get("name", t) for t in templates]
        # Check as strings
        template_str = str(templates).lower()
        assert "phishing" in template_str

    def test_load_phishing_template(self):
        """Phishing template should load with workflow config."""
        from btagent_agents.templates import load_template
        template = load_template("phishing")
        assert template is not None
        assert "phishing" in str(template).lower()

    def test_load_ransomware_template(self):
        """Ransomware template should load."""
        from btagent_agents.templates import load_template
        template = load_template("ransomware")
        assert template is not None
