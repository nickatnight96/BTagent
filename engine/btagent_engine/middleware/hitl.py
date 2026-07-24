"""Human-in-the-loop middleware -- pauses integration nodes pending approval.

Ports the autonomy-policy logic from
``agents/btagent_agents/hooks/hitl_hook.py`` into the engine middleware
model. The original was a LangChain ``on_tool_start`` callback; here it's a
``before_run`` middleware that triggers on nodes whose
``meta.category == NodeCategory.INTEGRATION``.

Contract:

* On ``before_run``, if the node is an integration node *and* the autonomy
  policy says approval is required for its id, raise :class:`HITLPause`.
* The Runner re-raises after walking ``on_error`` on the chain. The
  orchestrator (Sprint 3) catches :class:`HITLPause` and translates it to a
  ``NodePaused`` workflow outcome with a checkpoint persisted for analyst
  approval. The middleware itself is *not* responsible for emitting the
  HITL_CHECKPOINT event -- that's the EventEmitter middleware's job once the
  pause is observed.

The mapping from node id -> integration category mirrors the original
``_TOOL_AUTONOMY_MAP`` keyword scan; it lives here as a reusable function so
plugin authors can sanity-check their node ids against it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy

from btagent_engine.compiler.steps import HITLGateNode
from btagent_engine.middleware.base import Middleware, step_is_approved
from btagent_engine.node import NodeCategory

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


# The stable node id the ``hitl_gate`` playbook step compiles to. The
# explicit-gate middleware keys off this exact id rather than the node's
# DECISION category (DecisionNode / ParallelNode share that category).
_HITL_GATE_NODE_ID = HITLGateNode.meta.id


# Maps substring tokens found in a node id to a field on
# ``IntegrationAutonomy``. Order matters where overlap is possible (e.g.
# ``elastic`` before ``last``-anything would conflict): keep specific
# tokens before generic ones. Source of truth for ports of the legacy
# ``_TOOL_AUTONOMY_MAP``.
_NODE_AUTONOMY_MAP: dict[str, str] = {
    "splunk": "siem_query",
    "elastic": "siem_query",
    "sentinel": "siem_query",
    "siem": "siem_query",
    "crowdstrike": "edr_query",
    "defender": "edr_query",
    "carbon_black": "edr_query",
    "edr": "edr_query",
    "virustotal": "cti_lookup",
    "misp": "cti_lookup",
    "otx": "cti_lookup",
    "abuse": "cti_lookup",
    "greynoise": "cti_lookup",
    "shodan": "cti_lookup",
    "cti": "cti_lookup",
    "isolate": "host_isolation",
    "quarantine": "host_isolation",
    "contain": "host_isolation",
    "firewall": "firewall_rule",
    "block_ip": "firewall_rule",
    "block_domain": "firewall_rule",
    "disable_account": "account_disable",
    "disable_user": "account_disable",
    "lock_account": "account_disable",
    "playbook": "playbook_execution",
    "soar": "playbook_execution",
}

# IntegrationAutonomy fields for destructive containment. Every connector
# manifest marks the matching actions ``hitl_required=True``, so the autonomy
# layer treats that intent as the source of truth and NEVER auto-approves them
# -- regardless of the agent's autonomy level or a per-integration override
# (#377). The engine has zero deps on ``btagent_agents``, so this list is kept
# in lockstep with the agents-side hook by hand + the manifest coverage tests.
_ALWAYS_GATE_CATEGORIES: frozenset[str] = frozenset(
    {"host_isolation", "firewall_rule", "account_disable"}
)

# Substring tokens that mark a node as destructive containment, derived from
# ``_NODE_AUTONOMY_MAP`` so the two never drift. Checked independently of that
# map's iteration order: a node id like ``integration.crowdstrike.isolate_host``
# matches ``crowdstrike``->edr_query *first* in the map, which would
# misclassify containment as a benign EDR query -- the token scan below is
# immune to that ordering.
_CONTAINMENT_TOKENS: tuple[str, ...] = tuple(
    token
    for token, field_name in _NODE_AUTONOMY_MAP.items()
    if field_name in _ALWAYS_GATE_CATEGORIES
)


def _is_containment_node(node_id: str) -> bool:
    """True when *node_id* is a destructive containment action.

    Containment is HITL-gated in every connector manifest, so it is always
    gated by the autonomy layer too -- independent of the configured level.
    """
    lower = node_id.lower()
    return any(token in lower for token in _CONTAINMENT_TOKENS)


class HITLPause(Exception):
    """Raised when a node requires human approval before execution.

    Carries the node id, the resolved required autonomy level, and the
    agent's current autonomy level so the orchestrator can build a
    checkpoint record for the analyst UI without re-deriving any of it.
    """

    def __init__(
        self,
        node_id: str,
        required_level: AutonomyLevel,
        agent_level: AutonomyLevel,
    ) -> None:
        self.node_id = node_id
        self.required_level = required_level
        self.agent_level = agent_level
        super().__init__(
            f"Node {node_id!r} requires approval "
            f"(agent={agent_level.value}, required={required_level.value})"
        )


class HITLGatePause(HITLPause):
    """Raised when an explicit ``hitl_gate`` playbook step must pause.

    Distinct from the autonomy-policy :class:`HITLPause`: a ``hitl_gate``
    is a human-approval checkpoint authored directly in the playbook, so
    it carries the step's ``required_role`` and analyst ``prompt`` for the
    approval card rather than autonomy levels.

    It subclasses :class:`HITLPause` on purpose -- the
    :class:`~btagent_engine.runtime.executor.WorkflowExecutor` already
    catches ``HITLPause`` and translates it into a
    :class:`~btagent_engine.runtime.executor.WorkflowPaused`, so an
    explicit gate reuses that exact suspend/checkpoint/resume path with no
    executor change. ``required_level`` / ``agent_level`` are intentionally
    left unset (autonomy doesn't apply); ``WorkflowPaused`` reads them via
    ``getattr(..., None)`` and falls back to this exception's message.
    """

    def __init__(self, node_id: str, required_role: str, prompt: str = "") -> None:
        self.node_id = node_id
        self.required_role = required_role
        self.prompt = prompt
        # Bypass HITLPause.__init__ (it demands autonomy levels that don't
        # apply to an explicit gate) and build the message directly.
        detail = f" -- {prompt}" if prompt else ""
        Exception.__init__(
            self,
            f"HITL gate {node_id!r} requires approval by role {required_role!r}{detail}",
        )


def _resolve_node_autonomy(
    node_id: str,
    integration_autonomy: IntegrationAutonomy,
) -> AutonomyLevel:
    """Determine the autonomy level required to run *node_id* unattended.

    Falls back to ``L2_SUPERVISED`` for unknown integration nodes -- the
    safe default mirrors the legacy hook so behaviour is identical.
    """
    lower = node_id.lower()
    for token, field_name in _NODE_AUTONOMY_MAP.items():
        if token in lower:
            return getattr(integration_autonomy, field_name)
    return AutonomyLevel.L2_SUPERVISED


def requires_approval(
    node_id: str,
    agent_autonomy: AutonomyLevel,
    integration_autonomy: IntegrationAutonomy,
) -> bool:
    """Pure-function policy -- mirrors the legacy ``requires_approval`` exactly.

    L0 -> always pause. L1 -> pause unless the integration is L3+. L2 ->
    pause when the integration is L1 or L0. L3/L4 -> pause only on L0.

    Destructive containment is the exception to the table above: it is
    ``hitl_required=True`` in every connector manifest, so it always pauses --
    even at L3/L4 and even if a config sets a higher per-integration level
    (#377).
    """
    # Containment is never auto-approved -- the manifest intent overrides the
    # autonomy table (#377).
    if _is_containment_node(node_id):
        return True

    node_level = _resolve_node_autonomy(node_id, integration_autonomy)

    if agent_autonomy == AutonomyLevel.L0_MANUAL:
        return True

    if agent_autonomy == AutonomyLevel.L1_ASSISTED:
        return _level_index(node_level) < _level_index(AutonomyLevel.L3_AUTONOMOUS)

    if agent_autonomy == AutonomyLevel.L2_SUPERVISED:
        return _level_index(node_level) <= _level_index(AutonomyLevel.L1_ASSISTED)

    # L3 / L4
    return node_level == AutonomyLevel.L0_MANUAL


# AutonomyLevel is a StrEnum (values "L0".."L4"), so ``.value`` is a string;
# ordinal comparisons need explicit indexing rather than ``int(level.value)``.
_LEVEL_ORDER: tuple[AutonomyLevel, ...] = (
    AutonomyLevel.L0_MANUAL,
    AutonomyLevel.L1_ASSISTED,
    AutonomyLevel.L2_SUPERVISED,
    AutonomyLevel.L3_AUTONOMOUS,
    AutonomyLevel.L4_FULL_AUTO,
)


def _level_index(level: AutonomyLevel) -> int:
    return _LEVEL_ORDER.index(level)


class HITLMiddleware(Middleware):
    """Pauses integration-category nodes that require human approval."""

    name = "hitl"

    def __init__(
        self,
        agent_autonomy: AutonomyLevel = AutonomyLevel.L2_SUPERVISED,
        integration_autonomy: IntegrationAutonomy | None = None,
    ) -> None:
        self._agent_autonomy = agent_autonomy
        self._integration_autonomy = integration_autonomy or IntegrationAutonomy()

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        if node.meta.category != NodeCategory.INTEGRATION:
            return
        # Resume bypass: a step a human just approved skips its gate for this
        # execution. The executor stamps ``current_step_id`` before each node
        # and seeds ``approved_steps`` from the resume request.
        if step_is_approved(ctx):
            return
        if not requires_approval(
            node.meta.id,
            self._agent_autonomy,
            self._integration_autonomy,
        ):
            return
        raise HITLPause(
            node_id=node.meta.id,
            required_level=_resolve_node_autonomy(node.meta.id, self._integration_autonomy),
            agent_level=self._agent_autonomy,
        )


class HITLGateMiddleware(Middleware):
    """Pauses an explicit ``hitl_gate`` playbook step pending human approval.

    The ``hitl_gate`` step compiles to :class:`HITLGateNode` (id
    ``decision.hitl_gate``, category ``DECISION``) whose ``run`` is a
    pass-through that unconditionally returns ``approved=True``. The
    autonomy-policy :class:`HITLMiddleware` only gates ``INTEGRATION``
    nodes and ``ConnectorPolicyMiddleware`` only gates nodes carrying a
    :class:`ConnectorManifest`, so *neither* touches the gate. Without
    this middleware an explicit human-approval gate -- often the only
    intended control point in a SOAR playbook, and the last line of
    defence at autonomy L3/L4 -- is silently auto-approved (GH #389).

    Contract mirrors the integration HITL path exactly:

    * ``before_run`` raises :class:`HITLGatePause` (a :class:`HITLPause`
      subclass, so the executor's existing catch suspends the run) the
      first time the gate node is reached.
    * A resume that approved this step bypasses the pause via the shared
      ``step_is_approved(ctx)`` check -- the executor stamps
      ``current_step_id`` before each node and seeds ``approved_steps``
      from the resume request, so an approved gate runs its pass-through
      ``run`` (``approved=True``) exactly once and routing continues.
    * ``required_role`` / ``prompt`` are read from the validated gate
      input and propagated onto the pause so the approval card can render
      who must approve and why. The gate therefore stops being a no-op
      without changing ``HITLGateNode``'s category (which would break
      DecisionNode-shared routing).
    """

    name = "hitl_gate"

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        if node.meta.id != _HITL_GATE_NODE_ID:
            return
        # Resume bypass: a gate a human just approved skips its pause for
        # this execution so its pass-through ``run`` proceeds.
        if step_is_approved(ctx):
            return
        # Pull the approval-card fields off the validated gate input; fall
        # back to the node default so the pause always names a role.
        required_role = getattr(input, "required_role", "") or "senior_analyst"
        prompt = getattr(input, "prompt", "") or ""
        raise HITLGatePause(
            node_id=node.meta.id,
            required_role=required_role,
            prompt=prompt,
        )


__all__ = [
    "HITLGateMiddleware",
    "HITLGatePause",
    "HITLMiddleware",
    "HITLPause",
    "requires_approval",
]
