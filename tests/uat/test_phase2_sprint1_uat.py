"""Phase 2 Sprint 1 UAT — IOC enrichment plugin, subgraph, and API.

Run with: pytest tests/uat/test_phase2_sprint1_uat.py -v

Tests cover:
- Enrichment plugin loads and provides tools
- Enrichment subgraph compiles and runs
- IOC CRUD API endpoints
- Enrichment trigger endpoints
- Cross-investigation search
- STIX 2.1 import/export
- Confidence scoring logic
- IOC deduplication logic
- RBAC permissions for IOC operations
- Event types for enrichment lifecycle
"""

import json

import pytest


# ── UAT-ENRICHMENT-PLUGIN: Plugin imports and structure ───────
class TestEnrichmentPlugin:
    def test_plugin_importable(self):
        """Enrichment plugin can be imported."""
        from btagent_agents.plugins.enrichment import EnrichmentPlugin

        assert EnrichmentPlugin is not None

    def test_plugin_instantiates(self):
        """Enrichment plugin instantiates without errors."""
        from btagent_agents.plugins.enrichment import EnrichmentPlugin

        plugin = EnrichmentPlugin()
        assert plugin.name == "enrichment"
        assert plugin.version == "1.0.0"
        assert "ioc_enrichment" in plugin.get_metadata().capabilities
        assert "confidence_scoring" in plugin.get_metadata().capabilities
        assert "deduplication" in plugin.get_metadata().capabilities
        assert "mitre_tagging" in plugin.get_metadata().capabilities

    def test_plugin_returns_four_tools(self):
        """Plugin provides enrich_ioc, bulk_enrich, score_confidence, deduplicate_iocs."""
        from btagent_agents.plugins.enrichment import EnrichmentPlugin

        plugin = EnrichmentPlugin()
        tools = plugin.get_tools()
        assert len(tools) == 4
        tool_names = {t.name for t in tools}
        assert "enrich_ioc" in tool_names
        assert "bulk_enrich" in tool_names
        assert "score_confidence" in tool_names
        assert "deduplicate_iocs" in tool_names

    def test_plugin_system_prompt_has_org_profile(self):
        """System prompt contains {org_profile} placeholder."""
        from btagent_agents.plugins.enrichment import EnrichmentPlugin

        plugin = EnrichmentPlugin()
        prompt = plugin.get_system_prompt()
        assert "{org_profile}" in prompt
        assert "enrich" in prompt.lower()
        assert "<external-data>" in prompt

    def test_plugin_registered_in_registry(self):
        """Enrichment plugin is registered in PLUGIN_MODULES."""
        from btagent_agents.plugins import PLUGIN_MODULES

        assert "enrichment" in PLUGIN_MODULES
        assert PLUGIN_MODULES["enrichment"] == "btagent_agents.plugins.enrichment"

    def test_plugin_loads_via_registry(self):
        """Plugin loads through the standard plugin loader."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("enrichment")
        assert plugin is not None
        assert plugin.name == "enrichment"


# ── UAT-ENRICHMENT-TOOLS: Individual tool functionality ──────
class TestEnrichmentTools:
    def test_enrich_ip(self):
        """enrich_ioc returns combined results for IP with 4 sources."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            enrich_ioc,
        )

        result = enrich_ioc.invoke({"ioc_type": "ip", "ioc_value": "192.168.1.100"})
        assert result["ioc_type"] == "ip"
        assert result["ioc_value"] == "192.168.1.100"
        assert len(result["sources_queried"]) == 4  # VT, Shodan, GreyNoise, AbuseIPDB
        assert len(result["source_results"]) == 4
        assert 0.0 <= result["confidence"] <= 1.0
        assert "enriched_at" in result

    def test_enrich_domain(self):
        """enrich_ioc returns results for domain with 2 sources."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            enrich_ioc,
        )

        result = enrich_ioc.invoke({"ioc_type": "domain", "ioc_value": "evil.example.com"})
        assert result["ioc_type"] == "domain"
        assert len(result["sources_queried"]) == 2  # VT, Shodan

    def test_enrich_hash(self):
        """enrich_ioc returns results for hash with VT only."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            enrich_ioc,
        )

        sha256 = "a" * 64
        result = enrich_ioc.invoke({"ioc_type": "hash_sha256", "ioc_value": sha256})
        assert result["ioc_type"] == "hash_sha256"
        assert len(result["sources_queried"]) == 1  # VT only

    def test_enrich_url(self):
        """enrich_ioc returns results for URL with VT + URLhaus."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            enrich_ioc,
        )

        result = enrich_ioc.invoke({
            "ioc_type": "url",
            "ioc_value": "http://evil.example.com/malware.exe",
        })
        assert result["ioc_type"] == "url"
        assert len(result["sources_queried"]) == 2  # VT, URLhaus

    def test_bulk_enrich(self):
        """bulk_enrich processes a JSON list of IOCs."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            bulk_enrich,
        )

        iocs = json.dumps([
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "domain", "value": "test.example.com"},
        ])
        result = bulk_enrich.invoke({"iocs_json": iocs})
        assert result["total"] == 2
        assert result["enriched"] == 2
        assert len(result["results"]) == 2

    def test_bulk_enrich_invalid_json(self):
        """bulk_enrich handles invalid JSON gracefully."""
        from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
            bulk_enrich,
        )

        result = bulk_enrich.invoke({"iocs_json": "not valid json"})
        assert "error" in result
        assert result["enriched"] == 0


# ── UAT-CONFIDENCE: Confidence scoring ───────────────────────
class TestConfidenceScoring:
    def test_score_confidence_from_enrichment(self):
        """score_confidence returns confidence and justification."""
        from btagent_agents.plugins.enrichment.tools.confidence_scorer import (
            score_confidence,
        )

        enrichment = {
            "ioc_type": "ip",
            "ioc_value": "10.0.0.1",
            "source_results": [
                {"source": "virustotal", "verdict": "malicious", "details": {
                    "detection_ratio": "45/72",
                }},
                {"source": "abuseipdb", "verdict": "malicious", "details": {
                    "abuse_confidence_score": 85,
                }},
                {"source": "greynoise", "verdict": "malicious", "details": {
                    "classification": "malicious",
                }},
                {"source": "shodan", "verdict": "informational", "details": {
                    "open_ports": [80, 443],
                    "country": "RU",
                }},
            ],
        }
        result = score_confidence.invoke({
            "enrichment_json": json.dumps(enrichment),
        })
        assert result["confidence"] > 0.8  # 3 sources agree malicious
        assert result["recommended_action"] == "block"
        assert len(result["justification"]) > 0

    def test_score_conflicting_signals(self):
        """Conflicting signals clamp confidence to 0.4-0.6."""
        from btagent_agents.plugins.enrichment.tools.confidence_scorer import (
            score_confidence,
        )

        enrichment = {
            "source_results": [
                {"source": "virustotal", "verdict": "malicious", "details": {}},
                {"source": "greynoise", "verdict": "benign", "details": {}},
            ],
        }
        result = score_confidence.invoke({
            "enrichment_json": json.dumps(enrichment),
        })
        assert 0.4 <= result["confidence"] <= 0.6


# ── UAT-DEDUP: IOC deduplication ─────────────────────────────
class TestDeduplication:
    def test_deduplicate_merges_duplicates(self):
        """deduplicate_iocs merges same type+value IOCs."""
        from btagent_agents.plugins.enrichment.tools.dedup import deduplicate_iocs

        iocs = [
            {
                "ioc_type": "ip",
                "ioc_value": "10.0.0.1",
                "confidence": 0.5,
                "source_results": [
                    {"source": "virustotal", "verdict": "malicious"},
                ],
                "mitre_techniques": ["T1071"],
                "sources_queried": ["virustotal"],
            },
            {
                "ioc_type": "ip",
                "ioc_value": "10.0.0.1",
                "confidence": 0.8,
                "source_results": [
                    {"source": "abuseipdb", "verdict": "malicious"},
                ],
                "mitre_techniques": ["T1071.001"],
                "sources_queried": ["abuseipdb"],
            },
        ]
        result = deduplicate_iocs.invoke({"iocs_json": json.dumps(iocs)})
        assert result["original_count"] == 2
        assert result["deduped_count"] == 1
        assert result["duplicates_merged"] == 1

        merged = result["deduplicated"][0]
        assert merged["confidence"] == 0.8  # highest
        assert len(merged["source_results"]) == 2  # combined
        assert "T1071" in merged["mitre_techniques"]
        assert "T1071.001" in merged["mitre_techniques"]


# ── UAT-SUBGRAPH: Enrichment LangGraph subgraph ──────────────
class TestEnrichmentSubgraph:
    def test_subgraph_compiles(self):
        """Enrichment subgraph compiles without errors."""
        from btagent_agents.enrichment import create_enrichment_graph

        graph = create_enrichment_graph()
        assert graph is not None

    def test_subgraph_runs_pipeline(self):
        """Enrichment subgraph processes IOCs through full pipeline."""
        from btagent_agents.enrichment import create_enrichment_graph

        graph = create_enrichment_graph()
        result = graph.invoke({
            "investigation_id": "inv_test123",
            "raw_iocs": [
                {"type": "ip", "value": "10.0.0.1"},
                {"type": "domain", "value": "evil.example.com"},
            ],
            "selected_iocs": [],
            "enriched_iocs": [],
            "scored_iocs": [],
            "deduplicated_iocs": [],
            "stored": False,
            "errors": [],
            "status": "pending",
        })
        assert result["status"] == "complete"
        assert result["stored"] is True
        assert len(result["deduplicated_iocs"]) == 2
        assert len(result["enriched_iocs"]) == 2


# ── UAT-STIX: STIX 2.1 conversion ───────────────────────────
class TestSTIXService:
    def test_ioc_to_stix_indicator(self):
        """Converts a BTagent IOC to STIX 2.1 Indicator."""
        from btagent_backend.services.stix_service import ioc_to_stix_indicator

        ioc = {
            "type": "ip",
            "value": "10.0.0.1",
            "confidence": 0.85,
            "context": "C2 server",
        }
        indicator = ioc_to_stix_indicator(ioc, tlp_level="green")
        assert indicator["type"] == "indicator"
        assert indicator["spec_version"] == "2.1"
        assert "ipv4-addr:value = '10.0.0.1'" in indicator["pattern"]
        assert indicator["confidence"] == 85  # 0.85 * 100

    def test_stix_bundle_from_iocs(self):
        """Builds a valid STIX bundle from IOC list."""
        from btagent_backend.services.stix_service import stix_bundle_from_iocs

        iocs = [
            {"type": "ip", "value": "10.0.0.1", "confidence": 0.8, "tlp_level": "green"},
            {"type": "domain", "value": "evil.com", "confidence": 0.7, "tlp_level": "green"},
        ]
        bundle = stix_bundle_from_iocs(iocs, tlp_level="green")
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2

    def test_stix_bundle_excludes_tlp_red(self):
        """TLP:RED IOCs are excluded from STIX export."""
        from btagent_backend.services.stix_service import stix_bundle_from_iocs

        iocs = [
            {"type": "ip", "value": "10.0.0.1", "confidence": 0.8, "tlp_level": "red"},
            {"type": "domain", "value": "evil.com", "confidence": 0.7, "tlp_level": "green"},
        ]
        bundle = stix_bundle_from_iocs(iocs, tlp_level="green")
        assert len(bundle["objects"]) == 1  # Red IOC excluded

    def test_stix_roundtrip(self):
        """IOC -> STIX -> IOC roundtrip preserves type and value."""
        from btagent_backend.services.stix_service import (
            ioc_to_stix_indicator,
            stix_to_iocs,
        )

        original = {"type": "domain", "value": "test.example.com", "confidence": 0.75}
        indicator = ioc_to_stix_indicator(original)
        bundle = {"type": "bundle", "objects": [indicator]}

        imported = stix_to_iocs(bundle, investigation_id="inv_test")
        assert len(imported) == 1
        assert imported[0]["type"] == "domain"
        assert imported[0]["value"] == "test.example.com"
        assert imported[0]["confidence"] == 0.75


# ── UAT-EVENTS: Enrichment event types ───────────────────────
class TestEnrichmentEvents:
    def test_enrichment_event_types_exist(self):
        """IOC_ENRICHMENT_STARTED and IOC_ENRICHMENT_COMPLETE events exist."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "IOC_ENRICHMENT_STARTED")
        assert hasattr(EventType, "IOC_ENRICHMENT_COMPLETE")
        assert EventType.IOC_ENRICHMENT_STARTED == "ioc_enrichment_started"
        assert EventType.IOC_ENRICHMENT_COMPLETE == "ioc_enrichment_complete"

    def test_enrichment_event_envelope(self):
        """Can create EventEnvelope with enrichment event types."""
        from btagent_shared.types.events import EventEnvelope, EventType

        evt = EventEnvelope(
            type=EventType.IOC_ENRICHMENT_STARTED,
            investigation_id="inv_test",
            data={"ioc_id": "ioc_123", "sources": ["virustotal", "shodan"]},
        )
        assert evt.type == "ioc_enrichment_started"
        assert evt.id.startswith("evt_")


# ── UAT-RBAC: IOC permissions ────────────────────────────────
class TestIOCPermissions:
    def test_ioc_permissions_registered(self):
        """IOC permissions are registered in RBAC."""
        from btagent_backend.auth.rbac import PERMISSIONS

        assert "ioc:view" in PERMISSIONS
        assert "ioc:create" in PERMISSIONS
        assert "ioc:edit" in PERMISSIONS
        assert "ioc:delete" in PERMISSIONS
        assert "ioc:enrich" in PERMISSIONS
        assert "ioc:export" in PERMISSIONS

    def test_analyst_can_view_and_create_iocs(self):
        """Analyst role has ioc:view and ioc:create permissions."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "ioc:view")
        assert has_permission("analyst", "ioc:create")
        assert has_permission("analyst", "ioc:enrich")

    def test_analyst_cannot_delete_iocs(self):
        """Analyst role cannot delete IOCs (requires senior_analyst)."""
        from btagent_backend.auth.rbac import has_permission

        assert not has_permission("analyst", "ioc:delete")
        assert has_permission("senior_analyst", "ioc:delete")


# ── UAT-IOC-API: Router importable ───────────────────────────
class TestIOCAPIImports:
    def test_ioc_router_importable(self):
        """IOC router can be imported."""
        from btagent_backend.api.v1.iocs import router

        assert router is not None
        assert router.prefix == "/iocs"

    def test_ioc_service_importable(self):
        """IOC service module can be imported."""
        from btagent_backend.services import ioc_service

        assert hasattr(ioc_service, "create_ioc")
        assert hasattr(ioc_service, "search_cross_investigation")
        assert hasattr(ioc_service, "trigger_enrichment")

    def test_stix_service_importable(self):
        """STIX service module can be imported."""
        from btagent_backend.services import stix_service

        assert hasattr(stix_service, "ioc_to_stix_indicator")
        assert hasattr(stix_service, "stix_bundle_from_iocs")
        assert hasattr(stix_service, "stix_to_iocs")
