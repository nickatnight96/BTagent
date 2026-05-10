"""Workflow execution state -- per-node outputs keyed by workflow step id.

Held by :class:`WorkflowExecutor` while it walks the graph and exposed to
the caller on completion (via :class:`WorkflowRunResult`) or on pause (via
:class:`WorkflowPaused`). Downstream nodes use the upstream entries to
build their input payloads; checkpoint persistence (Sprint 3) snapshots it.

Mutable on purpose: the executor appends to it as each step finishes. The
type itself is a thin Pydantic-friendly wrapper around a dict so it can
round-trip through ``model_dump`` for storage if needed -- the executor
exposes the underlying dict via ``outputs`` for convenience.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkflowState(BaseModel):
    """Per-node output map produced as the executor walks the graph.

    ``outputs`` keys are workflow step ids (``WorkflowNode.step_id``);
    values are the typed BaseModel a node returned. Order of insertion
    matches execution order, which matters for the parallel-merge
    case where branch outputs are gathered in declaration order.

    ``nodes_executed`` is the same step-id sequence as a plain list so
    callers don't have to call ``list(outputs)`` to get it (and so it
    survives a round-trip without depending on dict insertion order
    semantics that pre-3.7 Pythons didn't guarantee).
    """

    # Pydantic 2 needs ``arbitrary_types_allowed`` so we can stash typed
    # node outputs (BaseModel subclasses) as values without forcing every
    # downstream node's output_schema to be importable here.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    outputs: dict[str, BaseModel] = Field(default_factory=dict)
    nodes_executed: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def record(self, step_id: str, output: BaseModel) -> None:
        """Record *output* under *step_id* and append to the order list.

        Idempotent on re-record (the order list is not duplicated) so
        the executor can defensively call this in branches that re-enter
        the same join point without bloating ``nodes_executed``.
        """
        self.outputs[step_id] = output
        if step_id not in self.nodes_executed:
            self.nodes_executed.append(step_id)

    def get(self, step_id: str) -> BaseModel | None:
        """Look up a recorded output by step id."""
        return self.outputs.get(step_id)
