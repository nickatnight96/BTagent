"""Playbook YAML -> Workflow compiler.

Ported from ``btagent_agents.playbook.compiler`` (the original spec) and
restructured so the output is a Node-graph (:class:`Workflow`) rather
than the typed ``PlaybookDefinition`` of the legacy Phase 1 SOAR.

What the compiler does, in order:

1. ``yaml.safe_load`` the input string with a 1 MiB byte cap.
2. Reject unknown top-level / trigger / per-step keys against an
   allowlist (catches typos that would otherwise silently no-op).
3. Walk the steps once to build :class:`WorkflowNode` + :class:`WorkflowEdge`
   entries, applying step-count and parallel-fork caps.
4. Topologically sort to detect cycles.
5. Return an immutable :class:`Workflow`.

Imports allowed: stdlib, ``yaml``, Pydantic, and the engine's own Node /
compiler modules. *Not* allowed: any ``btagent_agents`` or
``btagent_backend`` import -- the engine ships standalone.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.compiler.steps import (
    DecisionNode,
    HITLGateNode,
    ParallelNode,
)
from btagent_engine.compiler.workflow import Workflow, WorkflowEdge, WorkflowNode

logger = logging.getLogger("btagent_engine.compiler")

# --------------------------------------------------------------------------- #
# Resource caps -- defence against malformed / hostile YAML.
# --------------------------------------------------------------------------- #

MAX_PLAYBOOK_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_STEPS = 500
MAX_PARALLEL_BRANCHES = 32
MAX_BRANCH_DEPTH = 100

# --------------------------------------------------------------------------- #
# Key allowlists
# --------------------------------------------------------------------------- #

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"name", "version", "description", "trigger", "steps", "metadata"}
)
ALLOWED_TRIGGER_KEYS = frozenset({"type", "parameters"})

_BASE_STEP_KEYS = frozenset(
    {"id", "type", "name", "description", "config", "next_step", "on_failure"}
)
_ALLOWED_STEP_KEYS_BY_TYPE: dict[str, frozenset[str]] = {
    "action": _BASE_STEP_KEYS | frozenset({"tool_name", "arguments", "timeout_seconds"}),
    "decision": _BASE_STEP_KEYS | frozenset({"condition", "true_branch", "false_branch"}),
    "hitl_gate": _BASE_STEP_KEYS | frozenset({"prompt", "timeout_seconds", "required_role"}),
    "parallel_fork": _BASE_STEP_KEYS | frozenset({"branches"}),
    "join": _BASE_STEP_KEYS,
    "end": _BASE_STEP_KEYS,
}
_KNOWN_STEP_TYPES = frozenset(_ALLOWED_STEP_KEYS_BY_TYPE)

# Step types that compile to one of our shipped Nodes (vs. wrapping a
# user-registered Node by id).
_BUILTIN_NODE_IDS: dict[str, str] = {
    "decision": DecisionNode.meta.id,
    "parallel_fork": ParallelNode.meta.id,
    "hitl_gate": HITLGateNode.meta.id,
}


class PlaybookCompileError(ValueError):
    """Raised on any compile-time validation failure."""


class CompiledStep(BaseModel):
    """Light parsed-step record used during compilation.

    Distinct from :class:`WorkflowNode` because compilation needs to
    track edge-routing data (true/false branches, parallel branches)
    that doesn't live on the final WorkflowNode.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    name: str = ""
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    next_step: str | None = None
    on_failure: str = "abort"

    # action
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int | None = None

    # decision
    condition: str = ""
    true_branch: str = ""
    false_branch: str = ""

    # hitl_gate
    prompt: str = ""
    required_role: str = "senior_analyst"

    # parallel_fork
    branches: list[list[str]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #


def _parse_yaml(yaml_str: str) -> dict[str, Any]:
    if len(yaml_str.encode("utf-8")) > MAX_PLAYBOOK_BYTES:
        raise PlaybookCompileError(f"Playbook YAML exceeds {MAX_PLAYBOOK_BYTES} bytes")
    raw = yaml.safe_load(yaml_str)
    if not isinstance(raw, dict):
        raise PlaybookCompileError("Playbook YAML must be a mapping at top level")
    return raw


def _validate_branches(step_id: str, branches: Any) -> list[list[str]]:
    if not isinstance(branches, list):
        raise PlaybookCompileError(f"Step '{step_id}' branches must be a list")
    if len(branches) > MAX_PARALLEL_BRANCHES:
        raise PlaybookCompileError(
            f"Step '{step_id}' has {len(branches)} branches (max {MAX_PARALLEL_BRANCHES})"
        )
    cleaned: list[list[str]] = []
    for i, branch in enumerate(branches):
        if not isinstance(branch, list):
            raise PlaybookCompileError(f"Step '{step_id}' branch[{i}] must be a list of step ids")
        if len(branch) > MAX_BRANCH_DEPTH:
            raise PlaybookCompileError(
                f"Step '{step_id}' branch[{i}] has {len(branch)} steps (max {MAX_BRANCH_DEPTH})"
            )
        for j, ref in enumerate(branch):
            if not isinstance(ref, str) or not ref:
                raise PlaybookCompileError(
                    f"Step '{step_id}' branch[{i}][{j}] must be a non-empty string"
                )
        cleaned.append(list(branch))
    return cleaned


def _parse_step(raw: Any) -> CompiledStep:
    if not isinstance(raw, dict):
        raise PlaybookCompileError(f"Step entry must be a mapping, got {type(raw).__name__}")

    step_id = raw.get("id")
    if not isinstance(step_id, str) or not step_id:
        raise PlaybookCompileError("Step missing required string field: id")

    step_type = raw.get("type", "action")
    if step_type not in _KNOWN_STEP_TYPES:
        raise PlaybookCompileError(
            f"Step '{step_id}' has unknown type '{step_type}'. Allowed: {sorted(_KNOWN_STEP_TYPES)}"
        )

    unknown = set(raw.keys()) - _ALLOWED_STEP_KEYS_BY_TYPE[step_type]
    if unknown:
        raise PlaybookCompileError(
            f"Step '{step_id}' has unknown keys for type '{step_type}': {sorted(unknown)}"
        )

    on_failure = raw.get("on_failure", "abort")
    if on_failure not in {"skip", "abort", "retry"}:
        raise PlaybookCompileError(f"Step '{step_id}' invalid on_failure: {on_failure!r}")

    branches_raw = raw.get("branches", [])
    branches = _validate_branches(step_id, branches_raw) if step_type == "parallel_fork" else []

    return CompiledStep(
        id=step_id,
        type=step_type,
        name=raw.get("name", ""),
        description=raw.get("description", ""),
        config=dict(raw.get("config", {})),
        next_step=raw.get("next_step"),
        on_failure=on_failure,
        tool_name=raw.get("tool_name", ""),
        arguments=dict(raw.get("arguments", {})),
        timeout_seconds=raw.get("timeout_seconds"),
        condition=raw.get("condition", ""),
        true_branch=raw.get("true_branch", ""),
        false_branch=raw.get("false_branch", ""),
        prompt=raw.get("prompt", ""),
        required_role=raw.get("required_role", "senior_analyst"),
        branches=branches,
    )


# --------------------------------------------------------------------------- #
# Graph construction
# --------------------------------------------------------------------------- #


def _resolve_node_id(step: CompiledStep) -> str:
    """Map a parsed step to the NodeRegistry id its WorkflowNode should run.

    Action steps without a ``tool_name`` are tolerated at compile time --
    the legacy templates have a few "log and close" stub steps that omit
    it. The Runner will fail loudly when it tries to resolve the empty
    id against the registry; the compiler's job is structural validation,
    not registry resolution.
    """
    if step.type == "action":
        return step.tool_name or "action.unresolved"
    if step.type in _BUILTIN_NODE_IDS:
        return _BUILTIN_NODE_IDS[step.type]
    # join / end: synthetic pass-through nodes; we use the type as the
    # node id so the runner can short-circuit them. The compiler itself
    # doesn't need a Node class for these -- the runner treats them
    # structurally.
    return f"compiler.{step.type}"


def _build_node(step: CompiledStep) -> WorkflowNode:
    config: dict[str, Any] = dict(step.config)
    if step.type == "action":
        if step.arguments:
            config.setdefault("arguments", step.arguments)
        if step.timeout_seconds is not None:
            config.setdefault("timeout_seconds", step.timeout_seconds)
    elif step.type == "decision":
        config.setdefault("condition", step.condition)
    elif step.type == "hitl_gate":
        config.setdefault("prompt", step.prompt)
        config.setdefault("required_role", step.required_role)
        if step.timeout_seconds is not None:
            config.setdefault("timeout_seconds", step.timeout_seconds)
    elif step.type == "parallel_fork":
        config.setdefault("branches", step.branches)

    return WorkflowNode(
        step_id=step.id,
        node_id=_resolve_node_id(step),
        name=step.name,
        config=config,
    )


def _build_edges(step: CompiledStep, step_ids: set[str]) -> list[WorkflowEdge]:
    edges: list[WorkflowEdge] = []
    if step.type == "decision":
        if step.true_branch and step.true_branch in step_ids:
            edges.append(WorkflowEdge(source=step.id, target=step.true_branch, label="true"))
        if step.false_branch and step.false_branch in step_ids:
            edges.append(WorkflowEdge(source=step.id, target=step.false_branch, label="false"))
        # decision steps may also have a downstream `next_step` that
        # both branches reconverge on.
        if step.next_step and step.next_step in step_ids:
            edges.append(WorkflowEdge(source=step.id, target=step.next_step, label="next"))
        return edges

    if step.type == "parallel_fork":
        for i, branch in enumerate(step.branches):
            if branch and branch[0] in step_ids:
                edges.append(
                    WorkflowEdge(
                        source=step.id,
                        target=branch[0],
                        label=f"branch.{i}",
                    )
                )
            # Internal sequencing within a branch: each step links to the
            # next step in the branch list (if both ids exist).
            for j in range(len(branch) - 1):
                a, b = branch[j], branch[j + 1]
                if a in step_ids and b in step_ids:
                    edges.append(WorkflowEdge(source=a, target=b, label="next"))
        if step.next_step and step.next_step in step_ids:
            edges.append(WorkflowEdge(source=step.id, target=step.next_step, label="join"))
        return edges

    if step.next_step and step.next_step in step_ids:
        edges.append(WorkflowEdge(source=step.id, target=step.next_step, label="next"))
    return edges


def _detect_cycles(nodes: list[WorkflowNode], edges: list[WorkflowEdge]) -> list[str]:
    """Kahn's topological sort. Returns the ids of any nodes left in a cycle."""
    step_ids = {n.step_id for n in nodes}
    adj: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = {sid: 0 for sid in step_ids}

    for edge in edges:
        if edge.source in step_ids and edge.target in step_ids:
            adj[edge.source].append(edge.target)
            in_degree[edge.target] = in_degree.get(edge.target, 0) + 1

    queue: deque[str] = deque(sid for sid, deg in in_degree.items() if deg == 0)
    visited = 0
    while queue:
        cur = queue.popleft()
        visited += 1
        for nxt in adj[cur]:
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                queue.append(nxt)

    if visited < len(step_ids):
        return sorted(sid for sid, deg in in_degree.items() if deg > 0)
    return []


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def compile_playbook(yaml_str: str) -> Workflow:
    """Compile a playbook YAML string into an immutable :class:`Workflow`.

    Raises :class:`PlaybookCompileError` on any structural failure
    (oversize input, unknown keys, duplicate step ids, cycles, branch
    cap exceeded, ...). The error message includes the step id where
    possible so playbook authors can locate the problem.
    """
    raw = _parse_yaml(yaml_str)

    unknown_top = set(raw.keys()) - ALLOWED_TOP_LEVEL_KEYS
    if unknown_top:
        raise PlaybookCompileError(
            f"Unknown top-level playbook keys: {sorted(unknown_top)}. "
            f"Allowed: {sorted(ALLOWED_TOP_LEVEL_KEYS)}"
        )

    if "name" not in raw:
        raise PlaybookCompileError("Missing required field: name")
    if "trigger" not in raw:
        raise PlaybookCompileError("Missing required field: trigger")

    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list):
        raise PlaybookCompileError("Missing or invalid field: steps (must be a list)")
    if len(steps_raw) > MAX_STEPS:
        raise PlaybookCompileError(f"Playbook has {len(steps_raw)} steps (max {MAX_STEPS})")

    trigger_raw = raw["trigger"]
    if not isinstance(trigger_raw, dict):
        raise PlaybookCompileError("trigger must be a mapping")
    unknown_trigger = set(trigger_raw.keys()) - ALLOWED_TRIGGER_KEYS
    if unknown_trigger:
        raise PlaybookCompileError(
            f"Unknown trigger keys: {sorted(unknown_trigger)}. "
            f"Allowed: {sorted(ALLOWED_TRIGGER_KEYS)}"
        )
    if "type" not in trigger_raw:
        raise PlaybookCompileError("trigger missing required field: type")

    parsed_steps: list[CompiledStep] = []
    seen: set[str] = set()
    for raw_step in steps_raw:
        step = _parse_step(raw_step)
        if step.id in seen:
            raise PlaybookCompileError(f"Duplicate step id: {step.id}")
        seen.add(step.id)
        parsed_steps.append(step)

    nodes = [_build_node(s) for s in parsed_steps]
    step_ids = {n.step_id for n in nodes}

    edges: list[WorkflowEdge] = []
    for s in parsed_steps:
        edges.extend(_build_edges(s, step_ids))

    cycle_nodes = _detect_cycles(nodes, edges)
    if cycle_nodes:
        raise PlaybookCompileError(f"Cycle detected among steps: {cycle_nodes}")

    return Workflow(
        name=raw["name"],
        version=str(raw.get("version", "1.0")),
        description=str(raw.get("description", "")),
        trigger={
            "type": trigger_raw["type"],
            "parameters": dict(trigger_raw.get("parameters", {})),
        },
        nodes=tuple(nodes),
        edges=tuple(edges),
    )
