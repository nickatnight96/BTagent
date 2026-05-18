"""Hunter plugin — proactive threat-hunting agent (#99).

Entry point for the orchestrator. Exports :class:`HunterPlugin` which
the plugin registry discovers and wires into the agent surface.
"""

from btagent_agents.plugins.hunter.plugin import HunterPlugin

__all__ = ["HunterPlugin"]
