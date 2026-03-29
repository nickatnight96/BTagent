"""Human-in-the-loop hook — checks tool calls against autonomy levels.

Works with LangGraph's ``interrupt_before`` mechanism. When a tool call requires
human approval (based on the investigation's autonomy level and per-integration
overrides), this hook emits an HITL_CHECKPOINT event and signals the interrupt.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from btagent_shared.types.events import EventType
from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks.base import HookProvider

logger = logging.getLogger("btagent.hooks.hitl")

# Maps tool name patterns to IntegrationAutonomy fields
_TOOL_AUTONOMY_MAP: dict[str, str] = {
    "siem": "siem_query",
    "splunk": "siem_query",
    "elastic": "siem_query",
    "sentinel": "siem_query",
    "edr": "edr_query",
    "crowdstrike": "edr_query",
    "defender": "edr_query",
    "carbon_black": "edr_query",
    "cti": "cti_lookup",
    "virustotal": "cti_lookup",
    "misp": "cti_lookup",
    "otx": "cti_lookup",
    "abuse": "cti_lookup",
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


class HITLInterrupt(Exception):
    """Raised to signal that a tool call requires human approval.

    LangGraph nodes should catch this and enter an interrupt state, persisting
    the checkpoint so the graph can resume after approval.
    """

    def __init__(
        self,
        tool_name: str,
        tool_input: str,
        required_level: AutonomyLevel,
        checkpoint_id: str,
    ) -> None:
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.required_level = required_level
        self.checkpoint_id = checkpoint_id
        super().__init__(f"Tool {tool_name!r} requires approval (autonomy level: {required_level})")


def _resolve_tool_autonomy(
    tool_name: str,
    integration_autonomy: IntegrationAutonomy,
) -> AutonomyLevel:
    """Determine the autonomy level required for a specific tool.

    Matches the tool name against known patterns and returns the configured
    autonomy level for that integration category.
    """
    lower = tool_name.lower()
    for pattern, field_name in _TOOL_AUTONOMY_MAP.items():
        if pattern in lower:
            return getattr(integration_autonomy, field_name)
    # Default: use the general supervised level for unknown tools
    return AutonomyLevel.L2_SUPERVISED


def requires_approval(
    tool_name: str,
    agent_autonomy: AutonomyLevel,
    integration_autonomy: IntegrationAutonomy,
) -> bool:
    """Check if a tool call requires human approval.

    A tool requires approval when its integration-specific autonomy level is
    stricter (lower number) than the agent's overall autonomy level, or when
    the agent's autonomy level is L0 (manual) or L1 (assisted).

    Returns:
        True if the tool call should be paused for human review.
    """
    tool_level = _resolve_tool_autonomy(tool_name, integration_autonomy)

    # L0: everything requires approval
    if agent_autonomy == AutonomyLevel.L0_MANUAL:
        return True

    # L1: agent can execute only if the integration is L3+ autonomous
    if agent_autonomy == AutonomyLevel.L1_ASSISTED:
        return tool_level.value < AutonomyLevel.L3_AUTONOMOUS.value

    # L2: only approve high-risk actions (L0 or L1 integration level)
    if agent_autonomy == AutonomyLevel.L2_SUPERVISED:
        return tool_level.value <= AutonomyLevel.L1_ASSISTED.value

    # L3/L4: only approve L0 manual actions
    return tool_level == AutonomyLevel.L0_MANUAL


class HITLCallback(AsyncCallbackHandler):
    """LangChain callback that checks tool calls against autonomy policy."""

    def __init__(
        self,
        emitter: RedisEmitter,
        agent_autonomy: AutonomyLevel,
        integration_autonomy: IntegrationAutonomy,
        investigation_id: str,
    ) -> None:
        super().__init__()
        self._emitter = emitter
        self._agent_autonomy = agent_autonomy
        self._integration_autonomy = integration_autonomy
        self._investigation_id = investigation_id

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown_tool")

        if not requires_approval(tool_name, self._agent_autonomy, self._integration_autonomy):
            return

        # Emit HITL_CHECKPOINT event for the frontend
        from btagent_shared.utils.ids import generate_id

        checkpoint_id = generate_id("cp")

        await self._emitter.emit(
            EventType.HITL_CHECKPOINT,
            checkpoint_id=checkpoint_id,
            tool_name=tool_name,
            tool_input=input_str[:5000],  # Truncate large inputs
            required_autonomy=_resolve_tool_autonomy(tool_name, self._integration_autonomy).value,
            agent_autonomy=self._agent_autonomy.value,
            message=f"Tool '{tool_name}' requires human approval before execution.",
        )

        logger.info(
            "HITL checkpoint %s: tool=%s requires approval (agent=%s, tool_level=%s)",
            checkpoint_id,
            tool_name,
            self._agent_autonomy.value,
            _resolve_tool_autonomy(tool_name, self._integration_autonomy).value,
        )

        # Raise interrupt for LangGraph to catch
        raise HITLInterrupt(
            tool_name=tool_name,
            tool_input=input_str,
            required_level=_resolve_tool_autonomy(tool_name, self._integration_autonomy),
            checkpoint_id=checkpoint_id,
        )


class HITLHook(HookProvider):
    """Hook that enforces human-in-the-loop approval for sensitive tool calls.

    Usage::

        hook = HITLHook(
            emitter=emitter,
            investigation_id="inv_01HX...",
            agent_autonomy=AutonomyLevel.L2_SUPERVISED,
            integration_autonomy=IntegrationAutonomy(),
        )
        registry.register(hook)
    """

    def __init__(
        self,
        emitter: RedisEmitter,
        investigation_id: str,
        agent_autonomy: AutonomyLevel = AutonomyLevel.L2_SUPERVISED,
        integration_autonomy: IntegrationAutonomy | None = None,
    ) -> None:
        self._emitter = emitter
        self._investigation_id = investigation_id
        self._agent_autonomy = agent_autonomy
        self._integration_autonomy = integration_autonomy or IntegrationAutonomy()

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [
            HITLCallback(
                emitter=self._emitter,
                agent_autonomy=self._agent_autonomy,
                integration_autonomy=self._integration_autonomy,
                investigation_id=self._investigation_id,
            )
        ]
