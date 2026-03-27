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
    ValidationResult,
)

logger = logging.getLogger("btagent.playbook.compiler")


class PlaybookCompiler:
    """Parse playbook YAML into typed models and validate the step DAG."""

    def parse_yaml(self, yaml_str: str) -> dict[str, Any]:
        """Parse raw YAML string into a Python dict.

        Raises yaml.YAMLError on parse failure.
        """
        raw = yaml.safe_load(yaml_str)
        if not isinstance(raw, dict):
            raise ValueError("Playbook YAML must be a mapping at top level")
        return raw

    def parse_step(self, raw: dict[str, Any]) -> PlaybookStep:
        """Convert a raw step dict into the appropriate PlaybookStep subclass."""
        step_type = raw.get("type", "action")

        if step_type == StepType.ACTION:
            return ActionStep(
                id=raw["id"],
                type=StepType.ACTION,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=OnFailure(raw.get("on_failure", "abort")),
                tool_name=raw.get("tool_name", ""),
                arguments=raw.get("arguments", {}),
                timeout_seconds=raw.get("timeout_seconds", 300),
            )
        elif step_type == StepType.DECISION:
            return DecisionStep(
                id=raw["id"],
                type=StepType.DECISION,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=OnFailure(raw.get("on_failure", "abort")),
                condition=raw.get("condition", ""),
                true_branch=raw.get("true_branch", ""),
                false_branch=raw.get("false_branch", ""),
            )
        elif step_type == StepType.HITL_GATE:
            return HITLGateStep(
                id=raw["id"],
                type=StepType.HITL_GATE,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=OnFailure(raw.get("on_failure", "abort")),
                prompt=raw.get("prompt", ""),
                timeout_seconds=raw.get("timeout_seconds", 3600),
                required_role=raw.get("required_role", "senior_analyst"),
            )
        elif step_type == StepType.PARALLEL_FORK:
            return ParallelForkStep(
                id=raw["id"],
                type=StepType.PARALLEL_FORK,
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=OnFailure(raw.get("on_failure", "abort")),
                branches=raw.get("branches", []),
            )
        else:
            return PlaybookStep(
                id=raw["id"],
                type=(
                    StepType(step_type)
                    if step_type in {e.value for e in StepType}
                    else StepType.END
                ),
                name=raw.get("name", ""),
                description=raw.get("description", ""),
                config=raw.get("config", {}),
                next_step=raw.get("next_step"),
                on_failure=OnFailure(raw.get("on_failure", "abort")),
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

        queue: deque[str] = deque(
            sid for sid, deg in in_degree.items() if deg == 0
        )
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
            cycle_nodes = sorted(
                sid for sid, deg in in_degree.items() if deg > 0
            )
            errors.append(f"Cycle detected among steps: {cycle_nodes}")

        return errors

    def compile(self, yaml_str: str) -> PlaybookDefinition:
        """Full pipeline: parse YAML, build typed steps, validate DAG.

        Raises ValueError on any validation failure.
        """
        raw = self.parse_yaml(yaml_str)

        if "name" not in raw:
            raise ValueError("Missing required field: name")
        if "steps" not in raw or not isinstance(raw.get("steps"), list):
            raise ValueError("Missing or invalid field: steps")
        if "trigger" not in raw:
            raise ValueError("Missing required field: trigger")

        trigger = TriggerCondition(
            type=raw["trigger"]["type"],
            parameters=raw["trigger"].get("parameters", {}),
        )

        steps: list[PlaybookStep] = []
        seen_ids: set[str] = set()
        for step_raw in raw["steps"]:
            if step_raw["id"] in seen_ids:
                raise ValueError(f"Duplicate step id: {step_raw['id']}")
            seen_ids.add(step_raw["id"])
            steps.append(self.parse_step(step_raw))

        # Validate DAG
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
