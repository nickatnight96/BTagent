"""Workflow runtime -- walks a compiled :class:`Workflow` graph end-to-end.

Sprint 2.5A. The compiler (Sprint 2C) emits an immutable :class:`Workflow`
graph of step ids; this sub-package is what actually executes one. Per-node
execution still routes through ``Runner.execute`` so the full middleware
chain (HITL, EventEmitter, EvidenceChain, Classification, Scope, PromptBudget)
applies uniformly across every step.

Public API:

* :class:`WorkflowExecutor` -- the executor itself.
* :class:`WorkflowRunResult` -- terminal result of a successful run.
* :class:`WorkflowPaused` -- raised when the HITL middleware pauses a node;
  carries the partial :class:`WorkflowState` so the caller can checkpoint.
* :class:`WorkflowExecutionError` -- raised on any structural / execution
  failure, with ``node_id`` + ``cause`` populated for diagnostics.
* :class:`WorkflowState` -- per-node-output map, available to downstream
  nodes for input building (and to checkpoint persistence on pause).
"""

from btagent_engine.runtime.executor import (
    WorkflowExecutionError,
    WorkflowExecutor,
    WorkflowPaused,
    WorkflowRunResult,
)
from btagent_engine.runtime.state import WorkflowState

__all__ = [
    "WorkflowExecutionError",
    "WorkflowExecutor",
    "WorkflowPaused",
    "WorkflowRunResult",
    "WorkflowState",
]
