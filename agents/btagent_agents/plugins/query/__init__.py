"""Query plugin package — SIEM/EDR query generation and execution."""

from btagent_agents.plugins.query.plugin import QueryPlugin

# Expose a singleton for the plugin loader.
plugin = QueryPlugin

__all__ = ["QueryPlugin", "plugin"]
