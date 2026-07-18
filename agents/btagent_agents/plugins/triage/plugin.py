"""Triage plugin — alert classification and severity scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from btagent_agents.plugins.base import DefensivePlugin, DefensivePluginMetadata
from btagent_agents.plugins.triage.tools.alert_classifier import alert_classifier
from btagent_agents.plugins.triage.tools.phishing_correlator import phishing_triage
from btagent_agents.plugins.triage.tools.severity_scorer import severity_scorer

_PLUGIN_DIR = Path(__file__).resolve().parent


class TriagePlugin(DefensivePlugin):
    """Alert triage and initial classification plugin.

    Provides tools for classifying security alerts by category and severity,
    extracting IOCs, and mapping to MITRE ATT&CK techniques.
    """

    def __init__(self) -> None:
        self._metadata = self._load_metadata()
        self._system_prompt = self._load_system_prompt()

    # -- Abstract property implementations --------------------------------- #

    @property
    def name(self) -> str:
        return self._metadata.name

    @property
    def description(self) -> str:
        return self._metadata.description

    @property
    def version(self) -> str:
        return self._metadata.version

    # -- Abstract method implementations ----------------------------------- #

    def get_tools(self) -> list[Any]:
        """Return LangChain tool instances for triage operations."""
        return [alert_classifier, severity_scorer, phishing_triage]

    def get_system_prompt(self) -> str:
        """Return the triage agent system prompt.

        Contains an ``{org_profile}`` placeholder that should be filled in
        by the orchestrator before injection into the LLM call.
        """
        return self._system_prompt

    def get_metadata(self) -> DefensivePluginMetadata:
        return self._metadata

    # -- Internal helpers -------------------------------------------------- #

    @staticmethod
    def _load_metadata() -> DefensivePluginMetadata:
        yaml_path = _PLUGIN_DIR / "module.yaml"
        with yaml_path.open() as f:
            data = yaml.safe_load(f)
        return DefensivePluginMetadata(**data)

    @staticmethod
    def _load_system_prompt() -> str:
        prompt_path = _PLUGIN_DIR / "system_prompt.md"
        return prompt_path.read_text(encoding="utf-8")
