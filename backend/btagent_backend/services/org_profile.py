"""Admin-configurable organisation profile — stored in DB as JSON.

The org profile is injected into agent system prompts via the ``{org_profile}``
placeholder so that investigations are contextualised to the organisation's
industry, compliance requirements, tech stack, and IR team structure.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import OrgConfigRow

logger = logging.getLogger("btagent.services.org_profile")

_ORG_PROFILE_KEY = "org_profile"


# ---------------------------------------------------------------------------
# Pydantic schema
# ---------------------------------------------------------------------------


class IRTeam(BaseModel):
    """Incident-response team configuration."""

    shifts: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Shift definitions (e.g. name, timezone, hours)",
    )
    escalation_paths: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Escalation chain definitions",
    )
    on_call: dict[str, Any] = Field(
        default_factory=dict,
        description="Current on-call rotation info",
    )


class OrgProfile(BaseModel):
    """Organisation profile injected into agent prompts."""

    industry: str = Field(
        default="",
        description="Industry vertical (e.g. financial_services, healthcare)",
    )
    compliance: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks (e.g. HIPAA, PCI-DSS, SOX)",
    )
    tech_stack: dict[str, Any] = Field(
        default_factory=dict,
        description="SIEMs, EDRs, OS types, cloud providers",
    )
    critical_assets: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Crown jewels: key servers, databases, applications",
    )
    ir_team: IRTeam = Field(
        default_factory=IRTeam,
        description="IR team shifts, escalation paths, on-call",
    )


# ---------------------------------------------------------------------------
# Default profile (used when nothing has been saved yet)
# ---------------------------------------------------------------------------

_DEFAULT_PROFILE = OrgProfile(
    industry="",
    compliance=[],
    tech_stack={},
    critical_assets=[],
    ir_team=IRTeam(),
)


# ---------------------------------------------------------------------------
# DB operations
# ---------------------------------------------------------------------------


async def get_org_profile(db: AsyncSession) -> OrgProfile:
    """Load the org profile from the ``org_config`` table.

    Returns the default (empty) profile if nothing has been saved yet.
    """
    result = await db.execute(
        select(OrgConfigRow).where(OrgConfigRow.key == _ORG_PROFILE_KEY)
    )
    row = result.scalar_one_or_none()

    if row is None or row.value is None:
        return _DEFAULT_PROFILE.model_copy()

    try:
        return OrgProfile.model_validate(row.value)
    except Exception:
        logger.warning("Failed to parse stored org profile; returning default")
        return _DEFAULT_PROFILE.model_copy()


async def save_org_profile(
    db: AsyncSession,
    profile: OrgProfile,
    *,
    updated_by: str,
) -> OrgProfile:
    """Upsert the org profile into the ``org_config`` table.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    profile : OrgProfile
        The validated profile to persist.
    updated_by : str
        User ID of the admin performing the update.

    Returns
    -------
    OrgProfile
        The saved profile (round-tripped through serialisation).
    """
    value = profile.model_dump(mode="json")
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(OrgConfigRow).where(OrgConfigRow.key == _ORG_PROFILE_KEY)
    )
    existing = result.scalar_one_or_none()

    if existing:
        await db.execute(
            update(OrgConfigRow)
            .where(OrgConfigRow.key == _ORG_PROFILE_KEY)
            .values(value=value, updated_at=now, updated_by=updated_by)
        )
    else:
        from btagent_shared.utils.ids import generate_id

        row = OrgConfigRow(
            id=generate_id("cfg"),
            key=_ORG_PROFILE_KEY,
            value=value,
            updated_at=now,
            updated_by=updated_by,
        )
        db.add(row)

    await db.flush()
    logger.info("Org profile saved by user %s", updated_by)
    return profile


def render_for_prompt(profile: OrgProfile) -> str:
    """Render the org profile as a text block for injection into agent prompts.

    The output is wrapped in ``<org-profile>`` XML tags as per project convention
    for external data in prompts.
    """
    sections: list[str] = []

    if profile.industry:
        sections.append(f"Industry: {profile.industry}")

    if profile.compliance:
        sections.append(f"Compliance: {', '.join(profile.compliance)}")

    if profile.tech_stack:
        tech_parts: list[str] = []
        for category, items in profile.tech_stack.items():
            if isinstance(items, list):
                tech_parts.append(f"  {category}: {', '.join(str(i) for i in items)}")
            else:
                tech_parts.append(f"  {category}: {items}")
        sections.append("Tech Stack:\n" + "\n".join(tech_parts))

    if profile.critical_assets:
        asset_lines = []
        for asset in profile.critical_assets:
            name = asset.get("name", "unnamed")
            asset_type = asset.get("type", "unknown")
            asset_lines.append(f"  - {name} ({asset_type})")
        sections.append("Critical Assets:\n" + "\n".join(asset_lines))

    if profile.ir_team.on_call:
        on_call = profile.ir_team.on_call
        name = on_call.get("name", "unset")
        contact = on_call.get("contact", "")
        sections.append(f"On-Call: {name}" + (f" ({contact})" if contact else ""))

    body = "\n".join(sections) if sections else "No organisation profile configured."

    return f"<org-profile>\n{body}\n</org-profile>"
