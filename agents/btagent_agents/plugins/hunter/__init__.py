"""Hunter plugin package.

Combines the proactive threat-hunting agent (#99, :class:`HunterPlugin`)
with the Hunt Pack Runner (Phase 6 #112): Sigma transpilation
(:class:`SigmaCompiler`) and scheduled multi-backend hunt-pack execution
(:class:`HuntPackRunner`), landing hits in the #119 HuntFinding triage queue.
"""

from btagent_agents.plugins.hunter.plugin import HunterPlugin
from btagent_agents.plugins.hunter.runner import (
    HuntPackRunner,
    RuleRunResult,
    make_mock_hunt_executor,
)
from btagent_agents.plugins.hunter.sigma_compiler import (
    SigmaCompileError,
    SigmaCompiler,
)

__all__ = [
    "HuntPackRunner",
    "HunterPlugin",
    "RuleRunResult",
    "SigmaCompileError",
    "SigmaCompiler",
    "make_mock_hunt_executor",
]
