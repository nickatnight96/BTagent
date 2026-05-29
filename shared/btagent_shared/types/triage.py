"""Alert-triage schemas (EPIC-3 UC-3.1 — Autonomous Alert Triage Agent).

The triage agent takes a raw SIEM/EDR alert and produces a *reviewed case*:
a classified "Typed Intent", a proposed severity + disposition with a
confidence score and plain-English explanation, an evidence trail, and
2–3 recommended next steps. It is **read-only / advisory** — it never
executes an action; the analyst approves every disposition and next step
(HITL is enforced at the run layer).

These types live in ``btagent_shared`` so the engine node, the backend
API, and the React review surface all share one contract.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.enums import Severity


class TypedIntent(StrEnum):
    """What the alert most likely *is* — the triage classification.

    A flat enum (not a discriminated union) for v1: it's the discriminator
    the UI groups by and the API filters on. Per-intent payload models can
    layer on later without changing this contract.
    """

    SUSPICIOUS_LOGIN = "suspicious_login"
    MALWARE_DETECTED = "malware_detected"
    DATA_EXFIL_SUSPECTED = "data_exfil_suspected"
    C2_BEACONING = "c2_beaconing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    PHISHING = "phishing"
    POLICY_VIOLATION = "policy_violation"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class TriageDisposition(StrEnum):
    """The proposed verdict the analyst reviews."""

    ESCALATE = "escalate"  # likely true positive — hand to IR
    INVESTIGATE = "investigate"  # needs more analyst depth
    MONITOR = "monitor"  # low-confidence; keep an eye on it
    CLOSE_BENIGN = "close_benign"  # expected/benign activity
    CLOSE_FALSE_POSITIVE = "close_false_positive"  # detector misfired


class NextStep(BaseModel):
    """One recommended next action (read-only — the analyst executes it)."""

    model_config = ConfigDict(frozen=True)

    action: str = Field(
        ..., description="Short imperative, e.g. 'Pull 24h auth history for the user'."
    )
    rationale: str = Field(default="", description="Why this step is worth taking.")


class Alert(BaseModel):
    """A raw alert handed to the triage agent."""

    model_config = ConfigDict(extra="forbid")

    id: str
    source: str = Field(default="", description="Originating tool, e.g. 'splunk' / 'sentinel'.")
    title: str
    description: str = Field(default="")
    severity: Severity = Field(
        default=Severity.MEDIUM, description="Severity as reported by the source detector."
    )
    entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted entities keyed by kind: 'ip', 'user', 'host', 'process', 'hash'.",
    )
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original alert fields, passed through for the evidence trail.",
    )
    observed_at: datetime | None = None


class TriageResult(BaseModel):
    """The reviewed case the analyst sees instead of a raw alert."""

    model_config = ConfigDict(extra="forbid")

    typed_intent: TypedIntent
    proposed_severity: Severity
    disposition: TriageDisposition
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str = Field(..., description="Plain-English justification for the verdict.")
    next_steps: list[NextStep] = Field(
        default_factory=list, description="2–3 recommended next steps."
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Signals that drove the classification (matched keywords / present entities).",
    )
    severity_escalated: bool = Field(
        default=False,
        description="True when triage raised severity above the source-reported level "
        "(suspicious-pattern redetermination, UC-3.1 acceptance criterion).",
    )


__all__ = [
    "Alert",
    "NextStep",
    "TriageDisposition",
    "TriageResult",
    "TypedIntent",
]
