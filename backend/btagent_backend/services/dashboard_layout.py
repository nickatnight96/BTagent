"""Role-tuned PunchList layout preference (EPIC-5, #108).

The PunchList is every analyst's landing surface, but different roles walk in
with different first questions: an incident commander wants the HITL-blocked
queue, a senior analyst wants what's actively running, a line analyst wants
the whole board. This module owns the layout schema and the per-role default
sets; the config API resolves a user's saved preference (``dashboard_prefs``
row) or falls back to their role's default.

``default_status_filter`` is deliberately a bounded free string, not an enum:
it holds the *frontend* status-pill value ("running", "awaiting_hitl", …),
whose vocabulary is owned by the SPA and intentionally diverges from the
backend ``InvestigationStatus`` enum. The backend treats it as an opaque UI
preference.
"""

from __future__ import annotations

from typing import Literal

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
        description="Frontend status-pill value preselected on load; '' = All.",
    )

    @field_validator("sections")
    @classmethod
    def _dedupe_and_keep_investigations(cls, v: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(v))
        if "investigations" not in cleaned:
            cleaned.append("investigations")
        return cleaned


# Role → default layout. Unknown/future roles fall back to the analyst view.
_ROLE_DEFAULTS: dict[str, DashboardLayout] = {
    # Line analysts triage the whole board.
    "analyst": DashboardLayout(),
    # Seniors pick up from the handover and watch active work.
    "senior_analyst": DashboardLayout(default_status_filter="running"),
    # ICs (and admins acting as ICs) unblock the HITL queue first.
    "incident_commander": DashboardLayout(default_status_filter="awaiting_hitl"),
    "admin": DashboardLayout(default_status_filter="awaiting_hitl"),
}


def role_default_layout(role: str) -> DashboardLayout:
    """The default PunchList layout for ``role`` (analyst view if unknown)."""
    layout = _ROLE_DEFAULTS.get(role, _ROLE_DEFAULTS["analyst"])
    # Copy so callers can't mutate the shared default.
    return layout.model_copy(deep=True)
