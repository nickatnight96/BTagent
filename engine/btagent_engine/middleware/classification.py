"""Classification / TLP egress middleware.

Runs the shared TLP-egress gate over a node's input on ``before_run`` and
its output on ``after_run``. The gate is the same one used by STIX export,
knowledge ingest, and the MCP return path -- consistency is the whole
point of putting it in ``btagent_shared.security``.

Sized down from the legacy ``classification_hook.py``: the legacy version
also enforced provider routing (TLP -> allowed model providers), but that
is a property of the LLM client / router, not of the workflow node
runtime. Sprint 3's LLM router middleware will own provider gating; this
middleware focuses on the data-flow side.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from btagent_shared.security import assert_tlp_allows_egress
from btagent_shared.types.config import TLP

from btagent_engine.middleware.base import Middleware

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


class ClassificationMiddleware(Middleware):
    """TLP-gate node inputs and outputs against the configured channel kind.

    Constructor takes the channel kind to pass through to the shared gate
    (one of the four ``EgressKind`` literals). Defaults to
    ``"event_emit"`` because that is the channel a Node's data is most
    likely to be observed on, but the orchestrator may install a separate
    instance per channel where it matters.
    """

    name = "classification"

    def __init__(
        self,
        tlp_level: TLP | str | None = None,
        egress_kind: str = "event_emit",
    ) -> None:
        self._tlp_level = tlp_level
        self._egress_kind = egress_kind

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        # Use the context's tlp_level if no explicit override was given --
        # this lets per-investigation classification flow through without
        # the orchestrator constructing a fresh middleware per run.
        ctx_tlp = self._tlp_level or ctx.tlp_level
        assert_tlp_allows_egress(
            input.model_dump(mode="json"),
            self._egress_kind,
            classification_ctx=ctx_tlp,
        )

    async def after_run(
        self,
        node: Node,
        input: BaseModel,
        output: BaseModel,
        ctx: NodeContext,
    ) -> None:
        ctx_tlp = self._tlp_level or ctx.tlp_level
        assert_tlp_allows_egress(
            output.model_dump(mode="json"),
            self._egress_kind,
            classification_ctx=ctx_tlp,
        )


__all__ = ["ClassificationMiddleware"]
