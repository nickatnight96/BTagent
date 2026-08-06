"""Role-tuned PunchList layout preference (EPIC-5, #108).

The PunchList is every analyst's landing surface, but different roles walk in
with different first questions: an incident commander wants the HITL-blocked
queue, a senior analyst wants what's actively running, a line analyst wants
the whole board. This module owns the layout schema and the per-role default
sets; the config API resolves a user's saved preference (``dashboard_prefs``
row) or falls back to their role's default.

``default_status_filter`` holds the status pill preselected on load, or ``""``
for "All". It stays a bounded free string on the wire so ``""`` round-trips and
a saved preference from an older client cannot 422 a whole layout GET — but the
value it carries is a real :class:`InvestigationStatus`, and
``test_dashboard_layout_api`` enforces that for every default below.

This module used to claim the opposite: that the pill vocabulary was "owned by
the SPA and intentionally diverges from the backend enum". No translation layer
ever existed to make that true. The frontend sends the pill straight to
``GET /investigations?status=``, which does an exact string compare against
``investigations.status`` — so "running", "awaiting_hitl" and "completed", none
of which the backend ever writes, matched nothing. Six of the ten personas here
preselected one of those and landed on a permanently empty punch list.
"""

from __future__ import annotations

from typing import Literal

from btagent_shared.types.enums import InvestigationStatus
from pydantic import BaseModel, Field, field_validator

# PunchList section keys the frontend knows how to render, in canonical order.
SectionKey = Literal["handover", "investigations"]

_ALL_SECTIONS: tuple[str, ...] = ("handover", "investigations")


class DashboardLayout(BaseModel):
    """A user's PunchList arrangement.

    ``sections`` is the ordered list of visible sections; omitting
    ``"handover"`` hides the shift-handover card. ``"investigations"`` is
    always retained — a punch list without the punch list is a blank page,
    so the validator re-appends it rather than 422-ing a well-meaning PUT.
    """

    sections: list[SectionKey] = Field(
        default_factory=lambda: list(_ALL_SECTIONS),
        max_length=len(_ALL_SECTIONS),
    )
    default_status_filter: str = Field(
        default="",
        max_length=32,
        pattern=r"^[a-z_]*$",
        description="InvestigationStatus preselected on load; '' = All.",
    )

    @field_validator("sections")
    @classmethod
    def _dedupe_and_keep_investigations(cls, v: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(v))
        if "investigations" not in cleaned:
            cleaned.append("investigations")
        return cleaned


# Role → default layout. Unknown/future roles fall back to the analyst view.
#
# The keys cover both the coarse ``UserRole`` enum (analyst / senior_analyst /
# incident_commander / admin) and the finer UC-5.1 SOC personas (Tier1-3, IR,
# detection engineer, CTI analyst) that a customer's SSO ``role_map`` can hand
# us verbatim. Each persona lands on a board tuned to its first question. The
# two levers are which cards show (``sections`` — dropping "handover" hides the
# shift card) and which status pill is preselected.
#
# Personas that share a first question deliberately share a board:
# senior_analyst and tier2 both want the actively-worked queue, and
# incident_commander / admin / ir_analyst all want the HITL-blocked queue.
# (An earlier comment here claimed no two personas resolved to the same board;
# those pairs were already identical when it was written.)
#
# Every value below must be a real ``InvestigationStatus`` — see the module
# docstring for what happened when they weren't.
_ROLE_DEFAULTS: dict[str, DashboardLayout] = {
    # Line analysts triage the whole board.
    "analyst": DashboardLayout(),
    # Seniors pick up from the handover and watch active work.
    "senior_analyst": DashboardLayout(
        default_status_filter=InvestigationStatus.INVESTIGATING.value
    ),
    # ICs (and admins acting as ICs) unblock the HITL queue first.
    "incident_commander": DashboardLayout(
        default_status_filter=InvestigationStatus.PAUSED_HITL.value
    ),
    "admin": DashboardLayout(default_status_filter=InvestigationStatus.PAUSED_HITL.value),
    # --- UC-5.1 SOC personas --------------------------------------------
    # Tier1 front-line triage: starts the shift from the handover, then works
    # the untriaged/new queue.
    "tier1": DashboardLayout(default_status_filter=InvestigationStatus.PENDING.value),
    # Tier2 owns the escalations that are actively being worked.
    "tier2": DashboardLayout(default_status_filter=InvestigationStatus.INVESTIGATING.value),
    # Tier3 subject-matter escalation: digs into the runs that stalled or
    # failed and the lower tiers couldn't close.
    "tier3": DashboardLayout(default_status_filter=InvestigationStatus.FAILED.value),
    # IR analyst drives containment; the HITL-gated queue is the first stop.
    "ir_analyst": DashboardLayout(default_status_filter=InvestigationStatus.PAUSED_HITL.value),
    # Detection engineer backfills coverage off resolved cases — not a
    # shift-driven role, so the handover card is dropped.
    "detection_engineer": DashboardLayout(
        sections=["investigations"], default_status_filter=InvestigationStatus.CLOSED.value
    ),
    # CTI analyst scans the whole board for cross-case patterns with no
    # status focus; also not shift-driven, so the handover card is dropped.
    "cti_analyst": DashboardLayout(sections=["investigations"]),
}


def role_default_layout(role: str) -> DashboardLayout:
    """The default PunchList layout for ``role`` (analyst view if unknown)."""
    layout = _ROLE_DEFAULTS.get(role, _ROLE_DEFAULTS["analyst"])
    # Copy so callers can't mutate the shared default.
    return layout.model_copy(deep=True)
