"""Playbook YAML parser and DAG validator.

Responsible for parsing raw YAML into a typed PlaybookDefinition and
validating the step graph is a valid DAG (no cycles).
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any

import yaml
from btagent_shared.types.playbook import (
    ActionStep,
    DecisionStep,
    HITLGateStep,
    OnFailure,
    ParallelForkStep,
    PlaybookDefinition,
    PlaybookStep,
    StepType,
    TriggerCondition,
)

logger = logging.getLogger("btagent.playbook.compiler")

# Resource caps — defense against malformed/oversized YAML reaching the engine.
MAX_PLAYBOOK_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_STEPS = 500
MAX_PARALLEL_BRANCHES = 32
MAX_BRANCH_DEPTH = 100

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"name", "version", "description", "trigger", "steps", "metadata"}
)
ALLOWED_TRIGGER_KEYS = frozenset({"type", "parameters"})

_BASE_STEP_KEYS = frozenset(
    {"id", "type", "name", "description", "config", "next_step", "on_failure"}
)
ALLOWED_STEP_KEYS_BY_TYPE: dict[StepType, frozenset[str]] = {
    StepType.ACTION: _BASE_STEP_KEYS | frozenset({"tool_name", "arguments", "timeout_seconds"}),
    StepType.DECISION: _BASE_STEP_KEYS | frozenset({"condition", "true_branch", "false_branch"}),
    StepType.HITL_GATE: _BASE_STEP_KEYS | frozenset({"prompt", "timeout_seconds", "required_role"}),
    StepType.PARALLEL_FORK: _BASE_STEP_KEYS | frozenset({"branches"}),
    StepType.JOIN: _BASE_STEP_KEYS,
    StepType.END: _BASE_STEP_KEYS,
}


class PlaybookCompiler:
    """Parse playbook YAML into typed models and validate the step DAG."""

    def parse_yaml(self, yaml_str: str) -> dict[str, Any]:
        """Parse raw YAML string into a Python dict.

        Raises ValueError on oversize input or non-mapping top-level.
        Raises yaml.YAMLError on parse failure.
        """
        if len(yaml_str.encode("utf-8")) > MAX_PLAYBOOK_BYTES:
            raise ValueError(f"Playbook YAML exceeds {MAX_PLAYBOOK_BYTES} bytes")
        raw = yaml.safe_load(yaml_str)
        if not isinstance(raw, dict):
            raise ValueError("Playbook YAML must be a mapping at top level")
        return raw

    def parse_step(self, raw: dict[str, Any]) -> PlaybookStep:
        """Convert a raw step dict into the appropriate PlaybookStep subclass."""
        if not isinstance(raw, dict):
            raise ValueError(f"Step entry must be a mapping, got {type(raw).__name__}")

        step_id = raw.get("id")
        if not isinstance(step_id, str) or not step_id:
            raise ValueError("Step missing required string field: id")

        raw_type = raw.get("type", "action")
        if raw_type not in {e.value for e in StepType}:
            raise ValueError(
                f"Step '{step_id}' has unknown type '{raw_type}'. "
                f"Allowed: {sorted(e.value for e in StepType)}"
            )
        step_type = StepType(raw_type)

        # Reject unknown keys per step type — catches typos like `tool` vs `tool_name`
        # which would otherwise silently create a no-op step.
        unknown = set(raw.keys()) - ALLOWED_STEP_KEYS_BY_TYPE[step_type]
        if unknown:
            raise ValueError(
                f"Step '{step_id}' has unknown keys for type '{step_type.value}': {sorted(unknown)}"
            )

        try:
            on_failure = OnFailure(raw.get("on_failure", "abort"))
        except ValueError as exc:
            raise ValueError(f"Step '{step_id}' invalid on_failure: {exc}") from exc

        if step_type == StepType.ACTION:
            return ActionStep(
                id=step_id,
                type=StepType.ACTION,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=on_failure,
                tool_name=raw.get("tool_name", ""),
                arguments=raw.get("arguments", {}),
                timeout_seconds=raw.get("timeout_seconds", 300),
            )
        if step_type == StepType.DECISION:
            return DecisionStep(
                id=step_id,
                type=StepType.DECISION,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=on_failure,
                condition=raw.get("condition", ""),
                true_branch=raw.get("true_branch", ""),
                false_branch=raw.get("false_branch", ""),
            )
        if step_type == StepType.HITL_GATE:
            return HITLGateStep(
                id=step_id,
                type=StepType.HITL_GATE,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=on_failure,
                prompt=raw.get("prompt", ""),
                timeout_seconds=raw.get("timeout_seconds", 3600),
                required_role=raw.get("required_role", "senior_analyst"),
            )
        if step_type == StepType.PARALLEL_FORK:
            branches = raw.get("branches", [])
            self._validate_branches(step_id, branches)
            return ParallelForkStep(
                id=step_id,
                type=StepType.PARALLEL_FORK,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=on_failure,
                branches=branches,
            )
        # JOIN, END
        return PlaybookStep(
            id=step_id,
            type=step_type,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=on_failure,
        )

    @staticmethod
    def _validate_branches(step_id: str, branches: Any) -> None:
        if not isinstance(branches, list):
            raise ValueError(f"Step '{step_id}' branches must be a list")
        if len(branches) > MAX_PARALLEL_BRANCHES:
            raise ValueError(
                f"Step '{step_id}' has {len(branches)} branches (max {MAX_PARALLEL_BRANCHES})"
            )
        for i, branch in enumerate(branches):
            if not isinstance(branch, list):
                raise ValueError(f"Step '{step_id}' branch[{i}] must be a list of step ids")
            if len(branch) > MAX_BRANCH_DEPTH:
                raise ValueError(
                    f"Step '{step_id}' branch[{i}] has {len(branch)} steps (max {MAX_BRANCH_DEPTH})"
                )
            for j, step_ref in enumerate(branch):
                if not isinstance(step_ref, str) or not step_ref:
                    raise ValueError(
                        f"Step '{step_id}' branch[{i}][{j}] must be a non-empty string"
                    )

    def validate_dag(self, steps: list[PlaybookStep]) -> list[str]:
        """Detect cycles in the step graph using Kahn's topological sort.

        Returns a list of error strings (empty if DAG is valid).
        """
        step_ids = {s.id for s in steps}
        adj: dict[str, list[str]] = defaultdict(list)
        in_degree: dict[str, int] = {sid: 0 for sid in step_ids}

        for step in steps:
            successors: list[str] = []

            if step.next_step and step.next_step in step_ids:
                successors.append(step.next_step)

            if isinstance(step, DecisionStep):
                if step.true_branch and step.true_branch in step_ids:
                    successors.append(step.true_branch)
                if step.false_branch and step.false_branch in step_ids:
                    successors.append(step.false_branch)

            if isinstance(step, ParallelForkStep):
                for branch in step.branches:
                    for branch_step_id in branch:
                        if branch_step_id in step_ids:
                            successors.append(branch_step_id)

            for succ in successors:
                adj[step.id].append(succ)
                in_degree[succ] = in_degree.get(succ, 0) + 1

        queue: deque[str] = deque(sid for sid, deg in in_degree.items() if deg == 0)
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for neighbor in adj[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        errors: list[str] = []
        if visited < len(step_ids):
            cycle_nodes = sorted(sid for sid, deg in in_degree.items() if deg > 0)
            errors.append(f"Cycle detected among steps: {cycle_nodes}")

        return errors

    def compile(self, yaml_str: str) -> PlaybookDefinition:
        """Full pipeline: parse YAML, build typed steps, validate DAG.

        Raises ValueError on any validation failure.
        """
        raw = self.parse_yaml(yaml_str)

        unknown_top = set(raw.keys()) - ALLOWED_TOP_LEVEL_KEYS
        if unknown_top:
            raise ValueError(
                f"Unknown top-level playbook keys: {sorted(unknown_top)}. "
                f"Allowed: {sorted(ALLOWED_TOP_LEVEL_KEYS)}"
            )

        if "name" not in raw:
            raise ValueError("Missing required field: name")
        if "trigger" not in raw:
            raise ValueError("Missing required field: trigger")
        steps_raw = raw.get("steps")
        if not isinstance(steps_raw, list):
            raise ValueError("Missing or invalid field: steps (must be a list)")
        if len(steps_raw) > MAX_STEPS:
            raise ValueError(f"Playbook has {len(steps_raw)} steps (max {MAX_STEPS})")

        trigger_raw = raw["trigger"]
        if not isinstance(trigger_raw, dict):
            raise ValueError("trigger must be a mapping")
        unknown_trigger = set(trigger_raw.keys()) - ALLOWED_TRIGGER_KEYS
        if unknown_trigger:
            raise ValueError(
                f"Unknown trigger keys: {sorted(unknown_trigger)}. "
                f"Allowed: {sorted(ALLOWED_TRIGGER_KEYS)}"
            )
        if "type" not in trigger_raw:
            raise ValueError("trigger missing required field: type")
        trigger = TriggerCondition(
            type=trigger_raw["type"],
            parameters=trigger_raw.get("parameters", {}),
        )

        steps: list[PlaybookStep] = []
        seen_ids: set[str] = set()
        for step_raw in steps_raw:
            step = self.parse_step(step_raw)
            if step.id in seen_ids:
                raise ValueError(f"Duplicate step id: {step.id}")
            seen_ids.add(step.id)
            steps.append(step)

        cycle_errors = self.validate_dag(steps)
        if cycle_errors:
            raise ValueError("; ".join(cycle_errors))

        return PlaybookDefinition(
            name=raw["name"],
            version=raw.get("version", "1.0"),
            description=raw.get("description", ""),
            trigger=trigger,
            steps=steps,
        )
