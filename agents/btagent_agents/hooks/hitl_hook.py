"""Human-in-the-loop hook — checks tool calls against autonomy levels.

Works with LangGraph's ``interrupt_before`` mechanism. When a tool call requires
human approval (based on the investigation's autonomy level and per-integration
overrides), this hook emits an HITL_CHECKPOINT event and signals the interrupt.
"""

from __future__ import annotations

import ast
import json
import logging
from collections.abc import Mapping
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

# The single LangChain tool every MCP dispatch flows through. Its own name says
# nothing about the destructiveness of the call — the real target
# (``cs_isolate_host`` etc.) rides inside the router's ``tool_name`` argument
# (#377), so autonomy must be resolved from that, not the wrapper name.
_MCP_ROUTER_TOOL_NAME = "mcp_router_tool"

# IntegrationAutonomy fields for destructive containment. Every connector
# manifest marks the matching actions ``hitl_required=True`` (see
# ``btagent_agents.mcp.manifests``), so the autonomy layer treats that intent
# as the source of truth and NEVER auto-approves them — regardless of the
# agent's autonomy level or a per-integration override (#377).
_ALWAYS_GATE_CATEGORIES: frozenset[str] = frozenset(
    {"host_isolation", "firewall_rule", "account_disable"}
)

# Substring tokens that mark a call as destructive containment, derived from
# the autonomy map so the two never drift. Membership is checked independently
# of ``_TOOL_AUTONOMY_MAP`` iteration order: a name like
# ``cs_isolate_host`` matches ``crowdstrike``->edr_query *first* in that map,
# which would misclassify containment as a benign EDR query — the token scan
# below is immune to that ordering.
_CONTAINMENT_TOKENS: tuple[str, ...] = tuple(
    token
    for token, field_name in _TOOL_AUTONOMY_MAP.items()
    if field_name in _ALWAYS_GATE_CATEGORIES
)


def _coerce_mapping(raw: Any) -> dict[str, Any] | None:
    """Best-effort decode of a tool input into a mapping.

    LangChain may hand us the router input as an already-structured dict
    (``inputs`` kwarg) or as a string — JSON for a real dispatch, or a Python
    ``repr`` in some runtimes. Handle all three; return ``None`` when the input
    is not a mapping (e.g. a plain ``"host=host-42"`` string).
    """
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(raw)
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed, Mapping):
            return dict(parsed)
    return None


def _resolve_effective_tool_name(tool_name: str, tool_input: Any = None) -> str:
    """Resolve the tool whose autonomy actually governs this call.

    For an MCP router dispatch the LangChain-visible tool is the wrapper
    ``mcp_router_tool``; the destructive target (``cs_isolate_host`` …) is
    named by the router's ``tool_name`` argument. Reach through the wrapper so
    containment is classified by its real target, not the benign wrapper name
    (#377). Non-router tools are returned unchanged.
    """
    if tool_name != _MCP_ROUTER_TOOL_NAME:
        return tool_name
    args = _coerce_mapping(tool_input)
    if args:
        target = args.get("tool_name")
        if isinstance(target, str) and target:
            return target
    return tool_name


def _is_containment_tool(tool_name: str) -> bool:
    """True when *tool_name* is a destructive containment action.

    Containment is HITL-gated in every connector manifest, so it is always
    gated by the autonomy layer too — independent of the configured level.
    """
    lower = tool_name.lower()
    return any(token in lower for token in _CONTAINMENT_TOKENS)


class HITLInterrupt(Exception):
    """Callback-level signal that a tool call requires human approval.

    Note on production wiring: the BTagent orchestrator pauses for HITL via
    LangGraph's declarative ``interrupt_before=["hitl_checkpoint"]`` config
    (see ``orchestrator/graph.py``). It does **not** catch this exception.

    This class is preserved as an extension point for non-LangGraph consumers
    that wire ``HITLCallback`` directly into a tool runtime and want to
    surface "approval required" as a typed exception. The contract is
    enforced by ``tests/test_hitl_integration.py``.
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
    tool_input: Any = None,
) -> bool:
    """Check if a tool call requires human approval.

    A tool requires approval when its integration-specific autonomy level is
    stricter (lower number) than the agent's overall autonomy level, or when
    the agent's autonomy level is L0 (manual) or L1 (assisted).

    ``tool_input`` (the tool call's arguments) is used to reach through the
    ``mcp_router_tool`` wrapper to its real target so router-dispatched
    containment is classified correctly (#377); pass it for router calls.

    Returns:
        True if the tool call should be paused for human review.
    """
    # Reach through the MCP router wrapper to the real target so a
    # router-dispatched containment tool is classified as containment (#377).
    effective_name = _resolve_effective_tool_name(tool_name, tool_input)

    # Destructive containment is HITL-gated in every connector manifest
    # (hitl_required=True). Treat that intent as the source of truth: never
    # auto-approve it — not at L3/L4, and not even if a config sets a higher
    # per-integration level (#377).
    if _is_containment_tool(effective_name):
        return True

    tool_level = _resolve_tool_autonomy(effective_name, integration_autonomy)

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

        # LangChain hands structured tool inputs via the ``inputs`` kwarg; fall
        # back to ``input_str`` for runtimes that only pass the string form.
        raw_input = kwargs.get("inputs")
        if raw_input is None:
            raw_input = input_str

        # Resolve the real target so a router-dispatched containment action
        # (mcp_router_tool -> cs_isolate_host) is gated and reported as
        # containment, not as the benign wrapper (#377).
        effective_name = _resolve_effective_tool_name(tool_name, raw_input)

        if not requires_approval(
            tool_name,
            self._agent_autonomy,
            self._integration_autonomy,
            raw_input,
        ):
            return

        # Emit HITL_CHECKPOINT event for the frontend
        from btagent_shared.utils.ids import generate_id

        checkpoint_id = generate_id("cp")
        required_level = _resolve_tool_autonomy(effective_name, self._integration_autonomy)

        await self._emitter.emit(
            EventType.HITL_CHECKPOINT,
            checkpoint_id=checkpoint_id,
            tool_name=effective_name,
            tool_input=input_str[:5000],  # Truncate large inputs
            required_autonomy=required_level.value,
            agent_autonomy=self._agent_autonomy.value,
            message=f"Tool '{effective_name}' requires human approval before execution.",
        )

        logger.info(
            "HITL checkpoint %s: tool=%s requires approval (agent=%s, tool_level=%s)",
            checkpoint_id,
            effective_name,
            self._agent_autonomy.value,
            required_level.value,
        )

        # Raise interrupt for LangGraph to catch
        raise HITLInterrupt(
            tool_name=effective_name,
            tool_input=input_str,
            required_level=required_level,
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
