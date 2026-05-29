"""Response-plan schemas (EPIC-3 UC-3.2 — Containment & Response Playbook).

For a confirmed true positive, the agent proposes a **dual-path** plan:

* a **strategic** goal in plain English ("Contain ransomware on WS-12 and
  preserve evidence within 5 minutes"), and
* a **tactical** list of concrete :class:`ResponseAction` steps, each mapped
  to a connector-catalog tool, tagged destructive/reversible, and gated by
  per-action approval (adaptive consent).

The plan is a *proposal only* — nothing executes here. Each action carries
``requires_approval`` (always true for destructive steps) and, where the
action is reversible, a ``rollback`` plan. Execution + approver capture is
the run-layer's job.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ResponseCategory(StrEnum):
    """What phase of the response a step belongs to."""

    CONTAIN = "contain"  # stop the bleeding (often destructive)
    INVESTIGATE = "investigate"  # gather forensic depth (read-only)
    DOCUMENT = "document"  # ticketing / notification


class ResponseActionType(StrEnum):
    """Concrete action a connector can execute."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    FORENSIC_SNAPSHOT = "forensic_snapshot"
    PULL_LOGS = "pull_logs"
    OPEN_TICKET = "open_ticket"
    NOTIFY = "notify"


class ResponseAction(BaseModel):
    """One tactical step in a response plan (a connector-catalog action)."""

    model_config = ConfigDict(frozen=True)

    id: str
    category: ResponseCategory
    action_type: ResponseActionType
    target: str = Field(default="", description="Entity acted on (host/ip/account/domain).")
    connector: str = Field(..., description="Tool that would execute it, e.g. 'crowdstrike'.")
    description: str
    destructive: bool = Field(
        default=False, description="High-impact / hard to reverse — needs adaptive consent."
    )
    requires_approval: bool = Field(
        default=True, description="HITL gate; always true for destructive steps."
    )
    rollback: str | None = Field(
        default=None, description="Rollback plan when the action is reversible."
    )


class ResponsePlan(BaseModel):
    """A dual-path (strategic + tactical) response proposal for a confirmed TP."""

    model_config = ConfigDict(extra="forbid")

    strategic_goal: str = Field(..., description="Plain-English containment objective.")
    rationale: str = Field(default="", description="Why this plan fits the incident.")
    tactical_steps: list[ResponseAction] = Field(default_factory=list)
    estimated_containment_minutes: int | None = Field(
        default=None, description="Target time-to-contain for typical incidents of this severity."
    )


__all__ = [
    "ResponseAction",
    "ResponseActionType",
    "ResponseCategory",
    "ResponsePlan",
]
