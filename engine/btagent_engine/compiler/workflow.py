"""Compiled workflow representation.

A :class:`Workflow` is the immutable post-compile artefact: a directed
graph of step ids, each pinned to a registered Node id with a static
config payload, plus labelled edges for ordering / branching.

The runtime representation is intentionally dumb: no Node *instances*
are stored on the graph, only their ids. The Runner instantiates a Node
when it needs to execute a step. This keeps :class:`Workflow` cheaply
serialisable (workflow runs are persisted for replay / audit) and lets
the registry change between compile and execute without invalidating
saved compiled workflows.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkflowEdge(BaseModel):
    """A directed edge between two steps in the compiled workflow.

    ``label`` is the routing key the source step's Node returns to pick
    this edge -- ``"next"`` for the linear next-step case, ``"true"`` /
    ``"false"`` for decision branches, ``"branch.<i>"`` for parallel
    fork branches, ``"join"`` for the join node a parallel fork merges
    back to.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(..., description="Step id this edge leaves from.")
    target: str = Field(..., description="Step id this edge enters.")
    label: str = Field(default="next", description="Routing label; see class docstring.")


class WorkflowNode(BaseModel):
    """A single node in the compiled workflow graph.

    ``step_id`` is the unique id within the workflow (matches the YAML
    step id). ``node_id`` is the registry id of the Node *class* that
    will execute this step -- e.g. ``"integration.greynoise.lookup_ip"``
    for an action step, or ``"decision.branch"`` for a compiled
    DecisionStep. The two are decoupled so the same Node class can power
    multiple steps in a single workflow.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(..., description="Unique within the parent Workflow.")
    node_id: str = Field(..., description="NodeRegistry id of the Node class to run.")
    name: str = Field(default="", description="Human-readable label, mirrors YAML name.")
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Static per-step config the Node receives via input. Values "
        "are surfaced to the Node's input_schema by the runner; the compiler "
        "doesn't validate them since input_schema can vary by Node.",
    )


class Workflow(BaseModel):
    """The compiled, validated playbook -- a graph the Runner can walk.

    Round-trips through Pydantic so a compiled workflow can be persisted
    in the playbook execution store without a custom serialiser.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str = "1.0"
    description: str = ""
    trigger: dict[str, Any] = Field(default_factory=dict)
    nodes: tuple[WorkflowNode, ...] = Field(default_factory=tuple)
    edges: tuple[WorkflowEdge, ...] = Field(default_factory=tuple)

    def step(self, step_id: str) -> WorkflowNode | None:
        """Look up a node by step id."""
        for n in self.nodes:
            if n.step_id == step_id:
                return n
        return None

    def out_edges(self, step_id: str) -> tuple[WorkflowEdge, ...]:
        """Edges leaving *step_id*, in declaration order."""
        return tuple(e for e in self.edges if e.source == step_id)

    def in_edges(self, step_id: str) -> tuple[WorkflowEdge, ...]:
        """Edges entering *step_id*, in declaration order."""
        return tuple(e for e in self.edges if e.target == step_id)

    def step_ids(self) -> set[str]:
        return {n.step_id for n in self.nodes}
