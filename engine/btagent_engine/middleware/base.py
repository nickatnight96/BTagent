"""Middleware ABC + Runner that composes middlewares around Node.run.

Middleware is BTagent's port of the existing hooks (HITL, EventEmitter,
Classification / TLP, EvidenceChain, ScopeEnforcement, PromptBudget) to
the engine model. Each existing hook becomes a Middleware subclass and
plugs into any Node, not just LLM-issuing ones.

Composition contract:

* ``before_run`` is invoked in registration order *before* dispatching
  to ``node.run``. A middleware that wants to short-circuit (e.g. HITL
  awaiting approval) raises a typed exception; the Runner translates
  that into a ``NodePaused`` outcome rather than a hard failure.

* ``after_run`` is invoked in *reverse* registration order after
  ``node.run`` returns successfully. This mirrors the ASGI / express
  request-response flow: the outermost middleware sees the world both
  before validation and after the final result.

* ``on_error`` is invoked in *reverse* registration order on any
  exception from ``node.run`` or any earlier middleware's ``after_run``.
  Middleware may inspect / log the error but cannot swallow it -- the
  Runner re-raises after the chain completes.

* Middleware is *not* responsible for input validation. The Runner does
  ``input_schema.model_validate`` once before the chain starts; by the
  time middleware sees the input it is already typed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from btagent_engine.node import Node, NodeContext


def step_is_approved(ctx: NodeContext) -> bool:
    """True if the step about to run was explicitly approved for this run.

    Gate middlewares (HITL, ConnectorPolicy) call this to honour a resume:
    the :class:`~btagent_engine.runtime.executor.WorkflowExecutor` stamps
    ``ctx.metadata['current_step_id']`` before each node and seeds
    ``ctx.metadata['approved_steps']`` from the resume request, so a step a
    human just approved skips its pause exactly once (this execution).
    """
    current = ctx.metadata.get("current_step_id")
    approved = ctx.metadata.get("approved_steps") or set()
    return current is not None and current in approved


class Middleware:
    """Base class for cross-cutting concerns wrapped around node execution.

    Not an ABC -- subclasses opt into whichever hooks they care about and
    leave the rest as the inherited no-op. An abstract base would force
    every middleware to implement all three hooks, which makes the
    ergonomics worse and gains nothing.
    """

    name: str = ""

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        """Called before ``node.run``. Default is a no-op."""

    async def after_run(
        self,
        node: Node,
        input: BaseModel,
        output: BaseModel,
        ctx: NodeContext,
    ) -> None:
        """Called after ``node.run`` returns successfully. Default is no-op."""

    async def on_error(
        self,
        node: Node,
        input: BaseModel,
        error: BaseException,
        ctx: NodeContext,
    ) -> None:
        """Called when ``node.run`` (or a later middleware) raises.

        Implementations must not catch the error; the Runner re-raises
        after the chain finishes. Use this for logging, metrics, audit
        trail, NOT for recovery.
        """


class Runner:
    """Executes a Node with a middleware chain wrapped around its ``run``."""

    def __init__(self, middlewares: list[Middleware] | None = None) -> None:
        self._middlewares: list[Middleware] = list(middlewares or [])

    @property
    def middlewares(self) -> list[Middleware]:
        return list(self._middlewares)

    async def execute(
        self,
        node: Node,
        payload: BaseModel | dict,
        ctx: NodeContext,
    ) -> BaseModel:
        """Run a Node end-to-end.

        Validates *payload* against the node's ``input_schema`` (a dict
        is coerced via ``model_validate``), then walks the middleware
        chain around ``node.run``.

        Returns the validated output. The output is also passed through
        ``output_schema.model_validate`` defensively in case ``node.run``
        returned a dict-shaped result -- this lets node implementations
        be slightly loose and the type contract still hold.
        """
        validated_input = (
            payload
            if isinstance(payload, node.input_schema)
            else node.input_schema.model_validate(payload)
        )

        # before_run in registration order
        for mw in self._middlewares:
            await mw.before_run(node, validated_input, ctx)

        try:
            raw_output = await node.run(validated_input, ctx)
        except BaseException as exc:
            # reverse order so the outermost middleware sees the error last,
            # mirroring how it saw the input first.
            for mw in reversed(self._middlewares):
                await mw.on_error(node, validated_input, exc, ctx)
            raise

        validated_output = (
            raw_output
            if isinstance(raw_output, node.output_schema)
            else node.output_schema.model_validate(raw_output)
        )

        for mw in reversed(self._middlewares):
            await mw.after_run(node, validated_input, validated_output, ctx)

        return validated_output
