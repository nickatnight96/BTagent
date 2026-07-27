"""Detection-validation orchestration (#118).

The :class:`ValidationOrchestrator` drives the guardrailed adversary-emulation
loop: trigger -> observe -> score -> report. It is SANDBOX-ONLY (it re-asserts
the sandbox-enforcement guard at entry) and mock-first (the emulators it drives
honour ``BTAGENT_MOCK_CONNECTORS``).
"""

from btagent_agents.validation.orchestrator import (
    ObservedFiring,
    ValidationOrchestrator,
)

__all__ = ["ObservedFiring", "ValidationOrchestrator"]
