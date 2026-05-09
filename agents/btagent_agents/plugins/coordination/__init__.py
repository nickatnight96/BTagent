"""Coordination plugin package — multi-report summarization for agency submissions."""

from btagent_agents.plugins.coordination.plugin import CoordinationPlugin

# Expose a singleton for the plugin loader.
plugin = CoordinationPlugin

__all__ = ["CoordinationPlugin", "plugin"]
