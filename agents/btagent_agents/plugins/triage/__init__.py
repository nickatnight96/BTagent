"""Triage plugin package — alert classification and severity scoring."""

from btagent_agents.plugins.triage.plugin import TriagePlugin

# Expose a singleton for the plugin loader.
plugin = TriagePlugin

__all__ = ["TriagePlugin", "plugin"]
