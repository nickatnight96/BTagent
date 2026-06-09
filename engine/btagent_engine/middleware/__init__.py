"""Cross-cutting concerns wrapped around Node.run.

Sprint 1 shipped the Middleware ABC + Runner. Sprint 2 ports the legacy
hooks (HITL, EventEmitter, Classification / TLP egress, EvidenceChain,
ScopeEnforcement, PromptBudget) as Middleware subclasses. The legacy
hooks remain in ``agents/btagent_agents/hooks/`` until Sprint 3's
cutover removes them; for now both implementations exist.

Six design adaptations vs the legacy contract -- see each module's
docstring for details:

* PromptBudget reads token usage from ``ctx.metadata[USAGE_METADATA_KEY]``
  rather than from a LangChain LLMResult. Reasoning Nodes will need to
  populate this in Sprint 3.
* EventEmitter emits ``node.start`` / ``node.end`` / ``node.error``
  rather than the legacy ``THINKING`` / ``OUTPUT`` / ``TOOL_*`` taxonomy.
  Sprint 3's orchestrator can adapter-translate for legacy WebSocket
  consumers.
* ClassificationMiddleware does TLP egress only. The TLP-vs-provider
  routing (legacy ``ClassificationHook``) belongs in an LLM-router
  middleware that lives outside the engine since the engine has no
  provider concept.
* EvidenceChain records every successful Node run (heuristic dropped).
* HITL maps node ids (substrings) to autonomy levels rather than
  LangChain tool names.
* ScopeEnforcement scans Node inputs for IPs/hosts/IOCs against an
  ``InvestigationScope``; raises ``ScopeViolation`` on out-of-scope
  references.
"""

from btagent_engine.middleware.base import Middleware, Runner, step_is_approved
from btagent_engine.middleware.classification import ClassificationMiddleware
from btagent_engine.middleware.connector_policy import (
    CAPABILITY_ID_KEY,
    COST_CLASS_KEY,
    MANIFEST_NAME_KEY,
    ConnectorPolicyMiddleware,
    ConnectorPolicyViolation,
    PendingHITLApproval,
)
from btagent_engine.middleware.event_emitter import (
    EmitCallable,
    EventEmitterMiddleware,
)
from btagent_engine.middleware.evidence_chain import (
    GENESIS_HASH,
    EvidenceChainMiddleware,
    EvidenceRecord,
)
from btagent_engine.middleware.hitl import (
    HITLMiddleware,
    HITLPause,
    requires_approval,
)
from btagent_engine.middleware.ocsf_normalize import (
    OCSF_SUMMARY_KEY,
    OCSFContractViolation,
    OCSFEmitSummary,
    OCSFNormalizerMiddleware,
)
from btagent_engine.middleware.prompt_budget import (
    USAGE_METADATA_KEY,
    BudgetUsage,
    PromptBudgetExceeded,
    PromptBudgetMiddleware,
)
from btagent_engine.middleware.scope import (
    InvestigationScope,
    ScopeEnforcementMiddleware,
    ScopeViolation,
)

__all__ = [
    "CAPABILITY_ID_KEY",
    "COST_CLASS_KEY",
    "GENESIS_HASH",
    "MANIFEST_NAME_KEY",
    "OCSF_SUMMARY_KEY",
    "USAGE_METADATA_KEY",
    "BudgetUsage",
    "ClassificationMiddleware",
    "ConnectorPolicyMiddleware",
    "ConnectorPolicyViolation",
    "EmitCallable",
    "EventEmitterMiddleware",
    "EvidenceChainMiddleware",
    "EvidenceRecord",
    "HITLMiddleware",
    "HITLPause",
    "InvestigationScope",
    "Middleware",
    "OCSFContractViolation",
    "OCSFEmitSummary",
    "OCSFNormalizerMiddleware",
    "PendingHITLApproval",
    "PromptBudgetExceeded",
    "PromptBudgetMiddleware",
    "Runner",
    "ScopeEnforcementMiddleware",
    "ScopeViolation",
    "requires_approval",
    "step_is_approved",
]
