"""Report plugin package — document generation from investigation data."""

from btagent_agents.plugins.report.plugin import ReportPlugin

# Expose a singleton for the plugin loader.
plugin = ReportPlugin

__all__ = ["ReportPlugin", "plugin"]
