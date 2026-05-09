"""BTagent hook system — LangChain callback-based cross-cutting concerns."""

from btagent_agents.hooks.base import HookProvider, HookRegistry
from btagent_agents.hooks.classification_hook import ClassificationHook, TLPViolation
from btagent_agents.hooks.event_emitter_hook import EventEmitterHook
from btagent_agents.hooks.evidence_chain_hook import EvidenceChainHook
from btagent_agents.hooks.hitl_hook import HITLHook, HITLInterrupt
from btagent_agents.hooks.prompt_budget_hook import PromptBudgetExceeded, PromptBudgetHook
from btagent_agents.hooks.scope_enforcement_hook import (
    InvestigationScope,
    ScopeEnforcementHook,
    ScopeViolation,
)

__all__ = [
    "ClassificationHook",
    "EvidenceChainHook",
    "EventEmitterHook",
    "HITLHook",
    "HITLInterrupt",
    "HookProvider",
    "HookRegistry",
    "InvestigationScope",
    "PromptBudgetExceeded",
    "PromptBudgetHook",
    "ScopeEnforcementHook",
    "ScopeViolation",
    "TLPViolation",
]
