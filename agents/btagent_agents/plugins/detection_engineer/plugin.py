"""DetectionEngineerPlugin — agentic CTI → Detection persona (#113 "do both").

The plugin is the agent-surface wiring for the shared pure-logic core in
:mod:`btagent_shared.hunt.detection_engineer` (CTIExtractor → RuleDrafter →
DataSourceMatcher). Like :class:`~btagent_agents.plugins.hunter.plugin.HunterPlugin`
it ships no LangChain tools yet — the drafting workflow is driven from the
service layer / engine — but it:

1. Surfaces the detection-engineer system prompt + metadata to the orchestrator
   and the plugin registry (so it appears alongside Triage / Query / Hunter).
2. Exposes :meth:`draft_from_report`, the single call site that binds the shared
   orchestrator to the *agents-side* connector manifests, so a caller can choose
   deterministic (default) or agentic drafting and get data-source-reconciled
   :class:`~btagent_shared.types.detection_engineer.DetectionDraft` objects back.

The deterministic STIX → Sigma pipeline
(:mod:`btagent_shared.hunt.cti_to_detection`) stays the default path; this is the
LLM-authored counterpart that degrades gracefully when no model is injected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from btagent_agents.plugins.base import DefensivePlugin, DefensivePluginMetadata

_PLUGIN_DIR = Path(__file__).resolve().parent


class DetectionEngineerPlugin(DefensivePlugin):
    """Agentic detection engineer — intel report → drafted, matched Sigma rules."""

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
        """No LangChain tools yet — drafting is driven from the service layer.

        The workflow is composed from the shared CTIExtractor → RuleDrafter →
        DataSourceMatcher core (see :meth:`draft_from_report`), not from tools
        called inside an agent loop. Kept empty + explicit, mirroring the
        Hunter plugin's Phase-A shell.
        """
        return []

    def get_system_prompt(self) -> str:
        """Detection-engineer system prompt (carries an ``{org_profile}`` slot)."""
        return self._system_prompt

    def get_metadata(self) -> DefensivePluginMetadata:
        return self._metadata

    # -- Wiring ------------------------------------------------------------ #

    async def draft_from_report(
        self,
        report: Any,
        *,
        agentic: bool = False,
        llm: Any | None = None,
        connected: list[str] | None = None,
    ) -> list[Any]:
        """Draft detections from a prose intel report.

        Binds the shared orchestrator to the agents-side connector manifests so
        the returned drafts have ``data_sources_required`` populated. ``agentic``
        selects LLM-authored drafting (deterministic templating is the default);
        with no ``llm`` the agentic path degrades to templating. Returns
        :class:`DetectionDraft` objects — never opens a PR (HITL-gated upstream).
        """
        from btagent_shared.hunt.detection_engineer import draft_detections_from_report
        from btagent_shared.types.detection_engineer import DraftMethod

        from btagent_agents.mcp.manifests import MANIFESTS

        method = DraftMethod.AGENTIC if agentic else DraftMethod.DETERMINISTIC
        return await draft_detections_from_report(
            report,
            method=method,
            llm=llm,
            connected=connected,
            manifests=dict(MANIFESTS),
        )

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


# Registry hook — ``plugins.load_plugin('detection_engineer')`` instantiates this.
plugin = DetectionEngineerPlugin
