"""HunterPlugin — proactive threat-hunting agent (#99 Phase A).

The plugin doesn't ship its own LangChain tools yet — the hunt
workflow is composed in the engine from HypothesisGenNode +
(future) QuerySynth + NoiseBaseline + RunbookCompilerNode. The
plugin's role is:

1. Surface the right system prompt to the orchestrator when an
   analyst kicks off a hunt.
2. Expose metadata (capabilities, supported data sources) so the
   plugin registry can show "Hunter" alongside Triage / Query /
   Enrichment / Knowledge / Mitigation in the agent surface.

Phase B will add a small set of LangChain tools (resolve_adversary,
build_hunt_plan) that wrap the engine nodes so the agent surface
can invoke them by name. Until then this is intentionally a thin
plugin shell.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from btagent_agents.plugins.base import DefensivePlugin, DefensivePluginMetadata

_PLUGIN_DIR = Path(__file__).resolve().parent


class HunterPlugin(DefensivePlugin):
    """Threat-hunting agent — adversary/TTP/IOC -> hunt plan with runbook."""

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
        """LangChain tools for the hunter surface.

        Phase A returns an empty list — the hunt workflow is composed
        in the engine from HypothesisGen + RunbookCompiler nodes, not
        from LangChain tools called inside an agent loop. Phase B will
        add tool wrappers (resolve_adversary, build_hunt_plan) so the
        agent surface can invoke the engine by name.
        """
        return []

    def get_system_prompt(self) -> str:
        """Return the hunter system prompt.

        Contains an ``{org_profile}`` placeholder filled by the
        orchestrator before LLM injection.
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
