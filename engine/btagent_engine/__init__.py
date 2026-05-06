"""BTagent workflow engine.

The engine is the runtime layer underneath BTagent's agent /
orchestrator / API / canvas surfaces. Every workflow node -- triggers,
integrations, reasoning, decisions, outputs -- is a ``Node`` subclass
executed by ``Runner`` with a ``Middleware`` chain wrapped around it.

Engine has zero runtime dependency on ``btagent_agents`` or
``btagent_backend`` -- only ``btagent-shared`` is imported. Standalone-
shippable / embeddable in other security tools per the redesign plan.

## Public API

Foundation (Sprint 1):

* ``Node`` -- ABC every workflow node subclasses.
* ``NodeContext`` -- per-run state passed to ``Node.run``.
* ``NodeMeta`` / ``NodeCategory`` -- design-time metadata.
* ``NodeRegistry`` -- discovery surface for the canvas / compiler.
* ``Middleware`` / ``Runner`` -- composition wrapper around node
  execution. ``Middleware`` is intentionally not an ABC -- subclasses
  opt into whichever of before_run / after_run / on_error they need.

Compiler (Sprint 2C) -- ``btagent_engine.compiler``:

* ``compile_playbook`` -- YAML -> ``Workflow``.
* ``Workflow`` / ``WorkflowNode`` / ``WorkflowEdge`` -- runtime graph.
* ``DecisionNode`` / ``ParallelNode`` / ``HITLGateNode`` -- step-type
  Nodes used by the compiler.
* ``PlaybookCompileError`` + ``MAX_*`` size caps inherited from the
  prior playbook hardening commit.

Context cascade (Sprint 2C) -- ``btagent_engine.context``:

* ``apply_cascade`` -- reduce a too-big conversation through 4 layers
  (externalise / compress / prune / summarize) until it fits a budget.

Integrations (Sprint 2A1 + 2A2 + 2.5B) -- ``btagent_engine.integrations``:

* 9 vendor connector Nodes (GreyNoise, Splunk, CrowdStrike, Sentinel,
  Elastic, VirusTotal, Shodan, AbuseIPDB, MISP) all honouring
  ``BTAGENT_MOCK_CONNECTORS``.
* ``LLMCallNode`` (reasoning category) honouring ``BTAGENT_MOCK_LLM``;
  writes ``BudgetUsage`` to ``ctx.metadata`` so PromptBudgetMiddleware
  can enforce the cap.

Middleware (Sprint 2B) -- ``btagent_engine.middleware``:

* 6 cross-cutting middlewares (ClassificationMiddleware,
  EventEmitterMiddleware, EvidenceChainMiddleware, HITLMiddleware,
  PromptBudgetMiddleware, ScopeEnforcementMiddleware).

Triggers (Sprint 2.5B) -- ``btagent_engine.triggers``:

* ``ManualTriggerNode`` -- the simplest workflow entry point;
  webhook / schedule / alert variants ship in Phase 3.

Runtime (Sprint 2.5A) -- ``btagent_engine.runtime``:

* ``WorkflowExecutor`` walks a compiled :class:`Workflow` end-to-end,
  routing every step through ``Runner.execute`` so the middleware
  chain applies uniformly. Surfaces ``WorkflowPaused`` for HITL
  checkpoints and ``WorkflowExecutionError`` for structural / step
  failures.
"""

from btagent_engine.middleware import Middleware, Runner
from btagent_engine.node import (
    Node,
    NodeAlreadyRegisteredError,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.runtime import (
    WorkflowExecutionError,
    WorkflowExecutor,
    WorkflowPaused,
    WorkflowRunResult,
    WorkflowState,
)

__all__ = [
    "Middleware",
    "Node",
    "NodeAlreadyRegisteredError",
    "NodeCategory",
    "NodeContext",
    "NodeMeta",
    "NodeRegistry",
    "Runner",
    "WorkflowExecutionError",
    "WorkflowExecutor",
    "WorkflowPaused",
    "WorkflowRunResult",
    "WorkflowState",
]
