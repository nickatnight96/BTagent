"""Hunt Pack Runner plugin (Phase 6 #112).

Transpiles Sigma rules to every connected SIEM/EDR backend
(:class:`SigmaCompiler`) and runs versioned hunt packs on a schedule
(:class:`HuntPackRunner`), landing hits in the #119 HuntFinding triage queue.
"""

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
    "SigmaCompiler",
    "SigmaCompileError",
    "HuntPackRunner",
    "RuleRunResult",
    "make_mock_hunt_executor",
]
