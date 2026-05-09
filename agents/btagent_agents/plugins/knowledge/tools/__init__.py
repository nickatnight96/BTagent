"""Knowledge plugin tools."""

from btagent_agents.plugins.knowledge.tools.knowledge_search import (
    get_investigation_context,
    search_knowledge_base,
)

__all__ = ["search_knowledge_base", "get_investigation_context"]
