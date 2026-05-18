"""Tests for HunterPlugin (#99 Phase A)."""

from __future__ import annotations

from btagent_agents.plugins.hunter import HunterPlugin


def test_metadata_loads_from_module_yaml():
    plugin = HunterPlugin()
    assert plugin.name == "hunter"
    assert plugin.version == "0.1.0"
    assert "threat-hunting" in plugin.description.lower()


def test_capabilities_include_hypothesis_generation():
    plugin = HunterPlugin()
    meta = plugin.get_metadata()
    assert "hypothesis_generation" in meta.capabilities
    assert "hunt_plan_compilation" in meta.capabilities


def test_supported_data_sources_include_misp_and_siems():
    plugin = HunterPlugin()
    meta = plugin.get_metadata()
    # Hunting requires CTI (MISP) for adversary -> TTP resolution and
    # at least one SIEM/EDR for query execution.
    assert "misp" in meta.supported_data_sources
    assert any(
        ds in meta.supported_data_sources
        for ds in ("splunk", "sentinel", "elastic", "crowdstrike")
    )


def test_system_prompt_has_org_profile_placeholder():
    plugin = HunterPlugin()
    prompt = plugin.get_system_prompt()
    assert "{org_profile}" in prompt
    # Sanity checks on key safety guarantees the prompt enforces.
    assert "containment" in prompt.lower()
    assert "tlp" in prompt.lower()


def test_phase_a_ships_no_langchain_tools():
    # Phase A composes the workflow in the engine, not via LangChain
    # tools. Confirm the tools list is empty so a future Phase B
    # commit can extend it without surprises.
    plugin = HunterPlugin()
    assert plugin.get_tools() == []
