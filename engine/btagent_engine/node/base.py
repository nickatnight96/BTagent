"""Node ABC + supporting types.

A *Node* is the unit of work in a BTagent workflow. Triggers, integration
calls (Splunk / VirusTotal / etc.), reasoning steps (LLM call), data
transforms, decisions, and outputs (ticket, notify) all subclass it.

Design choices, recorded for the avoidance of drift:

1. **Async-first**. Most node operations are I/O-bound (HTTP, DB,
   queue, LLM). Sync code can wrap blocking calls in
   ``asyncio.to_thread``; we don't carry a sync ``run`` overload.

2. **Pydantic input/output schemas, declared as class attributes**.
   The schema is the contract. The canvas UI generates the property
   panel from it, the trigger ingress validates webhook bodies against
   it, and serialised workflow runs round-trip through it cleanly.

3. **Static metadata via ``meta: NodeMeta`` class attribute**, not
   instance state. Two instances of the same Node class are
   interchangeable; metadata belongs to the class.

4. **No middleware on the ABC itself**. Middleware composition is
   done by the Runner (see ``btagent_engine.middleware``). Keeping
   ``Node.run`` middleware-free means a node can be unit-tested by
   calling it directly with no wrapper plumbing.

5. **No global registry coupling**. ``Node`` does not register itself
   with the registry on definition; opting in is explicit via
   ``NodeRegistry.register`` so test-only nodes don't pollute the
   discovery surface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node.context import NodeContext


class NodeCategory(str, Enum):  # noqa: UP042 -- StrEnum is 3.11+; classical form works for any 3.10+ test env
    """Top-level node grouping used for canvas palette organisation.

    Stable; new categories must be added here, not invented per-node.
    """

    TRIGGER = "trigger"
    INTEGRATION = "integration"
    REASONING = "reasoning"
    KNOWLEDGE = "knowledge"
    DECISION = "decision"
    DATA = "data"
    OUTPUT = "output"


class NodeMeta(BaseModel):
    """Static, design-time metadata about a Node class."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        ...,
        description="Stable identifier (e.g. 'integration.greynoise.lookup_ip'). "
        "Workflow files reference nodes by this id; it must not change once "
        "shipped or existing workflows break.",
    )
    name: str = Field(..., description="Human-readable canvas label.")
    version: str = Field(
        ...,
        description="Semver-ish version; bump on input/output schema changes so "
        "the workflow store can warn when a saved workflow targets an older one.",
    )
    category: NodeCategory
    description: str = ""


# Type variables bound to the input/output schemas. Bound to BaseModel so the
# Runner can rely on .model_dump() / .model_validate() for serialisation.
NodeInputT = TypeVar("NodeInputT", bound=BaseModel)
NodeOutputT = TypeVar("NodeOutputT", bound=BaseModel)


class Node(ABC, Generic[NodeInputT, NodeOutputT]):  # noqa: UP046 -- PEP 695 is 3.12-only; classical Generic works on any 3.10+ test env
    """Base class for all workflow nodes.

    Subclasses declare three class attributes:

    * ``meta`` -- a ``NodeMeta`` describing the node.
    * ``input_schema`` -- the Pydantic model for ``run``'s input.
    * ``output_schema`` -- the Pydantic model for ``run``'s output.

    And implement ``run(input, ctx) -> output``.

    The Runner calls ``input_schema.model_validate(payload)`` before
    dispatching to ``run``; subclasses can assume ``input`` is well-formed.
    """

    meta: ClassVar[NodeMeta]
    input_schema: ClassVar[type[BaseModel]]
    output_schema: ClassVar[type[BaseModel]]

    @abstractmethod
    async def run(self, input: NodeInputT, ctx: NodeContext) -> NodeOutputT:
        """Execute the node's work.

        Implementations should:

        * Be idempotent where possible -- the runner may retry a transient
          failure depending on middleware policy.
        * Raise on unrecoverable errors instead of returning sentinel
          outputs; the runner / middleware will translate the exception
          into a workflow-level failure.
        * Not catch ``asyncio.CancelledError`` -- the workflow run may be
          cancelled upstream; honour the cooperative-cancel contract.
        * Not log secrets, including data echoed back from an upstream
          API. The egress middleware redacts and TLP-gates emitted
          events; ``run`` itself shouldn't log payloads.
        """

    async def teardown(self) -> None:  # noqa: B027 -- default no-op is intentional
        """Optional cleanup hook. Default is a no-op.

        Called by the Runner once per node lifetime when the workflow
        run is finalising (success or failure). Use for closing pooled
        connections that are exclusive to this node.
        """
