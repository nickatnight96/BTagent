"""LLM-router middleware -- the TLP-vs-provider gate for reasoning nodes.

Sprint 2B's :class:`btagent_engine.middleware.classification.ClassificationMiddleware`
deliberately stopped at TLP egress: it scans node inputs/outputs for
``tlp_level == 'red'`` and blocks them, but it does *not* know which LLM
provider a reasoning step is about to dispatch to because the engine has
no provider concept.

The TLP -> allowed-provider matrix lives in
:mod:`btagent_agents.hooks.classification_hook` (the legacy LangChain
callback consumes the same table). This module wires that policy into the
engine's middleware chain so that when an :class:`LLMCallNode` is about to
run, the resolver-supplied provider is checked against
``ctx.tlp_level`` *before* any prompt or credential leaves the process.

Design choices, recorded so Sprint 3 doesn't drift:

1. **Resolver injection**. The middleware does not import the LiteLLM-
   backed router directly. Instead it takes a ``model_to_provider``
   callable that maps an abstract model handle (``"claude-haiku"``,
   ``"gpt-4o"``, ...) to a concrete :class:`ModelProvider`. The
   orchestrator wires a thin closure around
   :meth:`btagent_agents.llm.router.TLPAwareLLMRouter.resolve` -- this
   keeps the middleware free of LiteLLM imports and makes it trivially
   testable with a stub callable.

2. **Reasoning category only**. ``before_run`` is a no-op for any node
   whose ``meta.category != NodeCategory.REASONING``. Integration nodes
   (GreyNoise, Splunk, ...) carry no LLM-bound provider and must not
   trigger resolver lookups -- they would either be unresolvable or
   resolve to nonsense.

3. **No policy duplication**. The TLP matrix is imported from
   ``btagent_agents.hooks.classification_hook`` -- never copied or
   re-declared here. If TLP policy changes, it changes in one place.

4. **Single exception type**. Disallowed combinations raise
   :class:`btagent_shared.security.TLPViolation`, the same exception the
   four engine-level egress gates use, so consumers can ``except
   TLPViolation:`` once and cover every TLP enforcement point.

5. **Provider stashed on context metadata**. After a successful gate
   pass, the resolved provider is written to
   ``ctx.metadata[LLM_PROVIDER_METADATA_KEY]``. The Node itself can read
   this if it needs the resolution downstream (e.g. when Sprint 3 wires
   the LiteLLM dispatch path), and audit middleware can pick it up to
   record which provider answered each call.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from btagent_engine.middleware import Middleware
from btagent_engine.node import NodeCategory
from btagent_shared.security import TLPViolation
from btagent_shared.types.config import TLP, ModelProvider

from btagent_agents.hooks.classification_hook import is_provider_allowed

if TYPE_CHECKING:
    from btagent_engine.node import Node, NodeContext
    from pydantic import BaseModel


# Public metadata key the LLMCallNode (or any downstream wrapper) can read
# to recover the router's decision without re-invoking the resolver.
LLM_PROVIDER_METADATA_KEY = "btagent.llm.provider"


def _coerce_tlp(value: TLP | str) -> TLP:
    """Normalise the context's ``tlp_level`` to a :class:`TLP` enum.

    ``NodeContext.tlp_level`` is typed as ``str`` (so the model stays JSON
    round-trippable). The classification helper expects the enum, so we
    coerce here. Unknown strings fall through to the strictest level
    (RED) -- failing closed is the right call when the classification is
    ambiguous.
    """
    if isinstance(value, TLP):
        return value
    try:
        return TLP(value.lower())
    except (ValueError, AttributeError):
        return TLP.RED


class LLMRouterMiddleware(Middleware):
    """Resolve a reasoning node's model handle to a provider and TLP-gate it.

    Activates only on nodes whose ``meta.category`` is
    :attr:`NodeCategory.REASONING`. For every other category the
    ``before_run`` hook is an inexpensive no-op -- the resolver is not
    invoked, no metadata is written, no exceptions are raised.

    On a reasoning node the middleware:

    1. Reads the abstract model handle from the node's input
       (``input.model``) -- :class:`LLMCallInput` declares this field;
       any other reasoning-category Node that wants to participate in
       the router must follow the same convention.
    2. Calls the injected ``model_to_provider`` callable to map the
       handle to a :class:`ModelProvider`.
    3. Checks the provider against ``ctx.tlp_level`` via
       :func:`is_provider_allowed`. Disallowed combinations raise
       :class:`TLPViolation`, halting the run before ``Node.run``
       executes.
    4. On success, stashes the resolved provider on
       ``ctx.metadata[LLM_PROVIDER_METADATA_KEY]`` so the node (or a
       later middleware) can use it without re-resolving.
    """

    name = "llm_router"

    def __init__(
        self,
        model_to_provider: Callable[[str], ModelProvider],
    ) -> None:
        self._resolve = model_to_provider

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        # Cheap fast-path: skip non-reasoning nodes entirely. Integration
        # nodes (GreyNoise, Splunk, ...) and triggers do not have a
        # model-handle field; invoking the resolver would either error
        # or produce a meaningless decision, and the TLP-vs-provider
        # check has no semantic meaning for them.
        if node.meta.category is not NodeCategory.REASONING:
            return

        # Pull the abstract model handle off the validated input. The
        # ``model`` field is part of the LLMCallNode contract; any other
        # reasoning-category node that wants router protection must
        # expose the same attribute.
        model_handle = getattr(input, "model", None)
        if not isinstance(model_handle, str) or not model_handle:
            # A reasoning node without a string model handle is malformed;
            # surface that loudly rather than silently bypass the gate.
            raise TLPViolation(
                _coerce_tlp(ctx.tlp_level),
                "<unresolved-model>",
            )

        provider = self._resolve(model_handle)
        tlp = _coerce_tlp(ctx.tlp_level)

        if not is_provider_allowed(tlp, provider):
            # Same exception type the engine egress gates raise, so
            # ``except TLPViolation:`` covers both.
            raise TLPViolation(tlp, provider)

        # NodeContext is frozen at the field level, but ``metadata`` is a
        # dict and mutable in place -- this is the documented hand-off
        # path for cross-middleware/node state in the engine model.
        ctx.metadata[LLM_PROVIDER_METADATA_KEY] = provider


__all__ = [
    "LLM_PROVIDER_METADATA_KEY",
    "LLMRouterMiddleware",
]
