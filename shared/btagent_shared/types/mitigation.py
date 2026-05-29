"""Bulk-mitigation schemas (EPIC-3 UC-3.3 — Bulk IOC Block & Mitigation).

Given a batch of IOCs an analyst wants to block, the agent proposes a
**per-tool mitigation plan**: for each IOC it decides whether to block,
routes it to the connector + policy object that would enforce the block,
and renders a human-readable *policy-change preview* plus a rollback.

Safety-by-design (enforced in the engine node, mirrored here):

* **Allowlist first.** IOCs matching the allowlist — RFC1918 / loopback /
  reserved IPs, well-known public resolvers, critical-infrastructure
  domains, plus any caller-supplied exact values — are **never** blocked
  (a self-inflicted-outage guard). They surface as ``skip_allowlisted``.
* **Validation.** Malformed IOCs (bad IP, wrong hash length, junk domain)
  are ``skip_invalid``; IOC kinds with no automated block path are
  ``skip_unsupported``. Only well-formed, non-allowlisted IOCs become
  ``block`` actions.
* **Nothing executes.** Every ``block`` action is ``destructive=True`` +
  ``requires_approval=True`` with a ``rollback``. This is a *proposal
  only*; approval + execution are the run-layer's job.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.enums import IOCType


class MitigationDecision(StrEnum):
    """What the planner decided to do with one IOC."""

    BLOCK = "block"  # well-formed + not allowlisted -> propose a block
    SKIP_ALLOWLISTED = "skip_allowlisted"  # matches the never-block allowlist
    SKIP_INVALID = "skip_invalid"  # malformed for its declared type
    SKIP_UNSUPPORTED = "skip_unsupported"  # no automated block path for this kind
    SKIP_DUPLICATE = "skip_duplicate"  # same (type, value) already planned


class MitigationAction(BaseModel):
    """One per-IOC entry in a bulk-mitigation plan."""

    model_config = ConfigDict(frozen=True)

    id: str
    ioc_type: IOCType
    ioc_value: str
    decision: MitigationDecision
    tool: str = Field(default="", description="Connector that would enforce the block.")
    policy_object: str = Field(default="", description="Blocklist / policy name on that tool.")
    policy_preview: str = Field(
        default="", description="Human-readable policy-change line (the proposed diff)."
    )
    description: str = Field(default="", description="Plain-English action summary.")
    destructive: bool = Field(default=False, description="True for block actions.")
    requires_approval: bool = Field(
        default=False, description="HITL gate; always true for block actions."
    )
    rollback: str | None = Field(default=None, description="How to undo the block.")
    reason: str = Field(default="", description="Why the IOC was skipped (non-block decisions).")


class MitigationPlan(BaseModel):
    """A per-tool bulk-block proposal (proposal only — nothing executes)."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., description="Plain-English overview of the plan.")
    actions: list[MitigationAction] = Field(default_factory=list)
    block_count: int = Field(default=0, description="Number of proposed block actions.")
    skip_count: int = Field(default=0, description="Number of skipped IOCs (all skip reasons).")
    tools: list[str] = Field(
        default_factory=list, description="Distinct connectors a block would touch."
    )


__all__ = [
    "MitigationAction",
    "MitigationDecision",
    "MitigationPlan",
]
