"""Knowledge plugin package — RAG-powered knowledge base search and retrieval."""

from btagent_agents.plugins.knowledge.plugin import KnowledgePlugin

# Expose a singleton for the plugin loader.
plugin = KnowledgePlugin

__all__ = ["KnowledgePlugin", "plugin"]
