"""Knowledge plugin — RAG-powered knowledge base search and retrieval."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from btagent_agents.plugins.base import DefensivePlugin, DefensivePluginMetadata
from btagent_agents.plugins.knowledge.tools.knowledge_search import (
    get_investigation_context,
    search_knowledge_base,
)

_PLUGIN_DIR = Path(__file__).resolve().parent


class KnowledgePlugin(DefensivePlugin):
    """Knowledge base search and retrieval plugin.

    Provides tools for searching the organisation's knowledge base using
    hybrid vector + keyword search, retrieving investigation context,
    and augmenting agent responses with organisational knowledge.
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
        """Return LangChain tool instances for knowledge operations."""
        return [search_knowledge_base, get_investigation_context]

    def get_system_prompt(self) -> str:
        """Return the knowledge agent system prompt.

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
