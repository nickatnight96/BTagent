"""Cross-cutting concerns wrapped around Node.run.

In Sprint 2 the existing hook implementations (HITL, EventEmitter,
Classification / TLP egress, EvidenceChain, ScopeEnforcement,
PromptBudget) move here as Middleware subclasses.
"""

from btagent_engine.middleware.base import Middleware, Runner

__all__ = ["Middleware", "Runner"]
