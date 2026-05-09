"""Enrichment plugin package — IOC enrichment and CTI correlation."""

from btagent_agents.plugins.enrichment.plugin import EnrichmentPlugin

# Expose a singleton for the plugin loader.
plugin = EnrichmentPlugin

__all__ = ["EnrichmentPlugin", "plugin"]
