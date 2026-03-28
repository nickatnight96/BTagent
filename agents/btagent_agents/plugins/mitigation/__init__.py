"""Mitigation plugin package — customer-facing remediation guidance."""

from btagent_agents.plugins.mitigation.plugin import MitigationPlugin

# Expose a singleton for the plugin loader.
plugin = MitigationPlugin

__all__ = ["MitigationPlugin", "plugin"]
