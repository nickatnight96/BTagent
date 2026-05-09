"""Pydantic models for playbook YAML schema and execution state."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StepType(StrEnum):
    """Playbook step types."""

    ACTION = "action"
    DECISION = "decision"
    HITL_GATE = "hitl_gate"
    PARALLEL_FORK = "parallel_fork"
    JOIN = "join"
    END = "end"


class TriggerType(StrEnum):
    """Playbook trigger types."""

    ALERT_SEVERITY = "alert_severity"
    IOC_TYPE = "ioc_type"
    MANUAL = "manual"
    WEBHOOK = "webhook"
    SCHEDULE = "schedule"


class OnFailure(StrEnum):
    """Behaviour on step failure."""

    SKIP = "skip"
    ABORT = "abort"
    RETRY = "retry"


class PlaybookStatus(StrEnum):
    """Execution status of a playbook run."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED_HITL = "paused_hitl"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Trigger
# ---------------------------------------------------------------------------


class TriggerCondition(BaseModel):
    """When / why a playbook should fire."""

    type: TriggerType
    parameters: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Step hierarchy
# ---------------------------------------------------------------------------


class PlaybookStep(BaseModel):
    """Base class for all playbook step types."""

    id: str
    type: StepType
    name: str
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    next_step: str | None = None
    on_failure: OnFailure = OnFailure.ABORT


class ActionStep(PlaybookStep):
    """Invoke a tool / MCP action."""

    type: StepType = StepType.ACTION
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300


class DecisionStep(PlaybookStep):
    """Branch on a condition (no eval — key-path comparison only)."""

    type: StepType = StepType.DECISION
    condition: str = ""
    true_branch: str = ""
    false_branch: str = ""


class HITLGateStep(PlaybookStep):
    """Block until a human approves or rejects."""

    type: StepType = StepType.HITL_GATE
    prompt: str = ""
    timeout_seconds: int = 3600
    required_role: str = "senior_analyst"


class ParallelForkStep(PlaybookStep):
    """Fan-out to multiple parallel branches."""

    type: StepType = StepType.PARALLEL_FORK
    branches: list[list[str]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Playbook definition (top-level YAML object)
# ---------------------------------------------------------------------------


class PlaybookDefinition(BaseModel):
    """Complete playbook parsed from YAML."""

    name: str
    version: str = "1.0"
    description: str = ""
    trigger: TriggerCondition
    steps: list[PlaybookStep] = Field(default_factory=list)

    def get_step(self, step_id: str) -> PlaybookStep | None:
        """Look up a step by ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def step_ids(self) -> set[str]:
        """Return the set of all step IDs."""
        return {s.id for s in self.steps}


# ---------------------------------------------------------------------------
# Execution tracking
# ---------------------------------------------------------------------------


class StepResult(BaseModel):
    """Result of executing a single playbook step."""

    step_id: str
    status: str = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class PlaybookExecution(BaseModel):
    """Runtime state for a single playbook execution."""

    id: str
    playbook_id: str
    investigation_id: str | None = None
    status: PlaybookStatus = PlaybookStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    step_results: list[StepResult] = Field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Validation result (returned by validate_playbook)
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    """Result of validating a playbook YAML string."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    step_count: int = 0
