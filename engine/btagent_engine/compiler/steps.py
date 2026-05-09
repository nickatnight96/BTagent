"""Built-in Node classes the compiler emits for non-action step types.

Three Nodes live here:

* :class:`DecisionNode` (id ``decision.branch``) -- given a value, picks
  a branch label. The compiler turns an ``if cond then A else B`` step
  into a DecisionNode with ``"true"`` / ``"false"`` out-edges; the
  evaluated value (typically a bool) is passed in via the input.

* :class:`ParallelNode` (id ``decision.parallel``) -- pure fan-out /
  fan-in glue. Receives a list of pre-run branch results and merges
  them into a single output. The actual parallel execution is the
  Runner's job; this Node is the join point. Keeping the node merge-
  only matches how the compiler emits it: a ParallelNode with one
  out-edge per branch and the runner collects results and re-feeds them
  in for the merge.

* :class:`HITLGateNode` (id ``decision.hitl_gate``) -- a *pass-through*
  with category ``DECISION``. The HITL middleware (Sprint 2B) inspects
  the node's category and gates execution; the Node itself does
  nothing functional. This keeps the gating policy in middleware and
  out of the Node, so the same gate can be opted-out of in unit tests
  by simply running without the middleware.

The ``action`` step type is *not* a class here: an action step is just
the wrapping of an already-registered Node by id. The compiler emits a
:class:`btagent_engine.compiler.workflow.WorkflowNode` whose ``node_id``
is the action step's ``tool_name``. No subclass needed.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import Node, NodeCategory, NodeContext, NodeMeta

# --------------------------------------------------------------------------- #
# DecisionNode
# --------------------------------------------------------------------------- #


class DecisionNodeInput(BaseModel):
    """Input to a decision node.

    ``value`` is the already-evaluated condition outcome (typically a
    bool, but can be any hashable used as a branch key by the runner).
    Decision evaluation lives in the playbook runtime, not the Node;
    the Node is just the join point so the graph has somewhere to
    branch.
    """

    model_config = ConfigDict(extra="forbid")

    value: Any = Field(..., description="Routing key the runner uses to pick an out-edge.")


class DecisionNodeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    branch: str = Field(..., description="Label of the chosen out-edge.")
    value: Any = Field(..., description="Echoed input value, for audit.")


class DecisionNode(Node[DecisionNodeInput, DecisionNodeOutput]):
    """Branch-picking Node. The runner uses ``branch`` to choose the next edge."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="decision.branch",
        name="Decision",
        version="0.1.0",
        category=NodeCategory.DECISION,
        description="Pick an out-edge by label based on an evaluated value.",
    )
    input_schema = DecisionNodeInput
    output_schema = DecisionNodeOutput

    async def run(self, input: DecisionNodeInput, ctx: NodeContext) -> DecisionNodeOutput:
        # Bool values map to the standard "true" / "false" branch labels the
        # compiler emits for `if cond then A else B`. Anything else is passed
        # through verbatim so a decision can also pick from a string-labelled
        # set of branches.
        if isinstance(input.value, bool):
            branch = "true" if input.value else "false"
        else:
            branch = str(input.value)
        return DecisionNodeOutput(branch=branch, value=input.value)


# --------------------------------------------------------------------------- #
# ParallelNode
# --------------------------------------------------------------------------- #


class ParallelNodeInput(BaseModel):
    """Input to a parallel-fork merge.

    ``branch_results`` is the per-branch result list, in branch order.
    Each entry is whatever shape the branch's terminal Node returned;
    the merge node treats them as opaque values.
    """

    model_config = ConfigDict(extra="forbid")

    branch_results: list[Any] = Field(default_factory=list)


class ParallelNodeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    merged: list[Any] = Field(default_factory=list)
    branch_count: int = 0


class ParallelNode(Node[ParallelNodeInput, ParallelNodeOutput]):
    """Fan-in for a parallel fork.

    The parallel *fork* is implemented in the runner -- it sees N
    out-edges from this node, runs each subgraph, and feeds the
    collected results back through ``run`` as the merge step. The Node
    deliberately doesn't spawn the branches itself; that would couple
    it to the runner's concurrency model.
    """

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="decision.parallel",
        name="Parallel Fork / Join",
        version="0.1.0",
        category=NodeCategory.DECISION,
        description="Fan-out / fan-in barrier for parallel branches.",
    )
    input_schema = ParallelNodeInput
    output_schema = ParallelNodeOutput

    async def run(self, input: ParallelNodeInput, ctx: NodeContext) -> ParallelNodeOutput:
        return ParallelNodeOutput(
            merged=list(input.branch_results),
            branch_count=len(input.branch_results),
        )


# --------------------------------------------------------------------------- #
# HITLGateNode
# --------------------------------------------------------------------------- #


class HITLGateNodeInput(BaseModel):
    """Input to a HITL gate.

    The Node itself is a pass-through; the HITL middleware (which
    inspects ``node.meta.category`` + ``node.meta.id``) is what blocks
    execution. ``payload`` is whatever upstream produced and will be
    forwarded unchanged on approval.
    """

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(default_factory=dict)
    prompt: str = ""
    required_role: str = "senior_analyst"


class HITLGateNodeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)


class HITLGateNode(Node[HITLGateNodeInput, HITLGateNodeOutput]):
    """Pass-through Node whose category triggers the HITL middleware.

    ``approved`` is True at the Node level by default; the gating
    middleware overlays the actual approval state via context metadata
    (the contract's exact shape is owned by the HITL middleware in
    Sprint 2B). Without that middleware the Node is a no-op, which is
    exactly what we want for unit tests.
    """

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="decision.hitl_gate",
        name="HITL Gate",
        version="0.1.0",
        category=NodeCategory.DECISION,
        description="Block execution until a human approves.",
    )
    input_schema = HITLGateNodeInput
    output_schema = HITLGateNodeOutput

    async def run(self, input: HITLGateNodeInput, ctx: NodeContext) -> HITLGateNodeOutput:
        return HITLGateNodeOutput(approved=True, payload=dict(input.payload))
