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

from btagent_engine.middleware.base import Middleware
from btagent_engine.node import NodeCategory

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


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
    """
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


__all__ = [
    "HITLMiddleware",
    "HITLPause",
    "requires_approval",
]
