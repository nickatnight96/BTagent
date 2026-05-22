"""Connector-policy middleware — enforces the runtime contract declared
in a node's :class:`ConnectorManifest`.

Where ClassificationMiddleware enforces TLP egress on inputs / outputs
generically, this middleware reads the specific capability the node is
executing and applies its declared policy:

* ``hitl_required=True`` -> raise :class:`PendingHITLApproval` so the
  Runner can pause the workflow until an analyst approves. Mutate-class
  actions default to this; queries opt in via the manifest.
* ``tlp_egress=<level>`` -> assert the active TLP context allows the
  capability to run at all. A capability declared as ``tlp_egress=GREEN``
  must not run when the workflow context is classified RED.
* ``cost_class`` -> recorded into ``ctx.metadata`` so downstream cost
  middleware / dashboards can aggregate per-run spend.

The policy is read **per capability**, not per node, because a single
node may expose multiple capabilities (e.g. Okta has ``list_users``
(query, no HITL) and ``deactivate_user`` (action, HITL required)). The
node tells this middleware which capability is active via the input
field ``_capability_id``; if the field is absent, the middleware
falls back to the manifest's first declared capability or skips
enforcement (and logs a warning at the Runner level).

Design notes:

1. **Pause vs deny.** HITL approvals pause; TLP / cost-budget denials
   raise hard errors. Pauses can be resumed by an analyst; TLP denials
   are policy violations that must be investigated.
2. **Manifest absence is benign.** Nodes without a manifest get the
   default policy (no HITL, no TLP check). The middleware logs but does
   not refuse — gradual adoption is the point.
3. **No side effects on success.** When everything is fine the
   middleware writes one cost-class entry to ``ctx.metadata`` and
   returns. Keep it cheap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from btagent_shared.types.config import TLP
from btagent_shared.types.connector import (
    ActionCapability,
    ConnectorManifest,
    QueryCapability,
    StreamCapability,
)

from btagent_engine.middleware.base import Middleware

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


# Metadata keys the middleware writes to ctx.metadata. Public so tests +
# downstream consumers can read them without string-typos.
CAPABILITY_ID_KEY = "connector.capability_id"
COST_CLASS_KEY = "connector.cost_class"
MANIFEST_NAME_KEY = "connector.name"


class ConnectorPolicyViolation(Exception):
    """The capability's declared policy refuses the current execution.

    Raised for TLP downgrades (capability allows lower than the active
    context demands) or other hard violations the runner cannot resume
    from without an explicit policy change.
    """


class PendingHITLApproval(Exception):
    """The capability requires human approval before execution.

    The Runner translates this into a paused-workflow state; the
    workflow resumes once an analyst approves via the HITL surface.
    Distinct from :class:`ConnectorPolicyViolation` because the
    execution isn't refused, just deferred.
    """

    def __init__(self, capability_id: str, connector_name: str) -> None:
        super().__init__(
            f"Capability {connector_name!r}.{capability_id!r} requires "
            "explicit analyst approval before execution."
        )
        self.capability_id = capability_id
        self.connector_name = connector_name


# Ordering of TLP for the egress comparison. Higher index == more restricted.
# A capability declaring ``tlp_egress=GREEN`` (index 1) can only run when
# the active context is GREEN-or-lower (index <= 1).
_TLP_ORDER: dict[TLP, int] = {
    TLP.WHITE: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}


def _tlp_allows(capability_max: TLP, active: TLP) -> bool:
    """True iff the capability's declared egress max permits the active TLP."""
    return _TLP_ORDER[active] <= _TLP_ORDER[capability_max]


def _resolve_capability(
    manifest: ConnectorManifest,
    node: Node,
    input: BaseModel,
) -> QueryCapability | ActionCapability | StreamCapability | None:
    """Pick the capability this node represents.

    Resolution order:
      1. ``input._capability_id`` (per-invocation override, rarely used)
      2. ``node.__class__.capability_id`` (the canonical place — every
         integration node declares which manifest capability it implements)
      3. fall-through: if the manifest exposes exactly one capability,
         use it (single-capability connectors don't need to declare)
      4. otherwise None — the middleware will refuse execution
    """
    requested: str | None = getattr(input, "_capability_id", None)
    if requested is not None:
        return manifest.capability(requested)

    declared: str | None = getattr(node.__class__, "capability_id", None)
    if isinstance(declared, str):
        return manifest.capability(declared)

    total = len(manifest.queries) + len(manifest.actions) + len(manifest.streams)
    if total == 1:
        if manifest.queries:
            return manifest.queries[0]
        if manifest.actions:
            return manifest.actions[0]
        if manifest.streams:
            return manifest.streams[0]
    return None


class ConnectorPolicyMiddleware(Middleware):
    """Enforce per-capability HITL + TLP + cost policy from the manifest.

    Constructor takes the active TLP for the run (the classification
    layer typically sets this once at workflow start). If omitted the
    TLP check is skipped — this is the right default for unit tests
    and for workflows that haven't classified themselves yet, but
    production runs should always pass a level.
    """

    name = "connector_policy"

    def __init__(self, active_tlp: TLP | None = None) -> None:
        self._active_tlp = active_tlp

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        manifest = getattr(node.__class__, "manifest", None)
        if not isinstance(manifest, ConnectorManifest):
            # No manifest -> no policy. Gradual-adoption stance.
            return

        capability = _resolve_capability(manifest, node, input)
        if capability is None:
            # Manifest exists but exposes no capabilities, no node-level
            # capability_id is declared, or an unknown id was requested.
            # Fail loud — almost always a bug.
            raise ConnectorPolicyViolation(
                f"No capability resolved for connector {manifest.name!r}; "
                "the node class must declare `capability_id` (matching a "
                "manifest entry) or the input must set _capability_id."
            )

        # 1. TLP egress check
        if self._active_tlp is not None and not _tlp_allows(
            capability.tlp_egress, self._active_tlp
        ):
            raise ConnectorPolicyViolation(
                f"Capability {manifest.name!r}.{capability.id!r} declares "
                f"tlp_egress={capability.tlp_egress.value} but the active "
                f"context is {self._active_tlp.value} — refusing execution."
            )

        # 2. HITL gate
        if capability.hitl_required:
            raise PendingHITLApproval(
                capability_id=capability.id, connector_name=manifest.name
            )

        # 3. Record cost class + capability metadata for downstream
        # observability. No side effects on policy decisions.
        ctx.metadata[MANIFEST_NAME_KEY] = manifest.name
        ctx.metadata[CAPABILITY_ID_KEY] = capability.id
        ctx.metadata[COST_CLASS_KEY] = capability.cost_class.value


__all__ = [
    "CAPABILITY_ID_KEY",
    "COST_CLASS_KEY",
    "ConnectorPolicyMiddleware",
    "ConnectorPolicyViolation",
    "MANIFEST_NAME_KEY",
    "PendingHITLApproval",
]
