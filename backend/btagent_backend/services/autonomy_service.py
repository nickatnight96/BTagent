"""Per-org autonomy overrides (#418 — Autonomy & HITL gates editing).

The shared :class:`~btagent_shared.types.config.IntegrationAutonomy` defaults
are the platform baseline; this service stores an org's deviations and merges
them into the effective per-category levels.

Two hard rules keep the surface honest:

* **Containment is not configurable.** ``host_isolation`` / ``firewall_rule``
  / ``account_disable`` are HITL-gated in code (engine middleware + connector
  manifests), so writes for those categories are rejected outright — the
  config store never even *claims* to loosen them.
* **Invalid stored data degrades to defaults.** An unknown category or level
  in a stored override (schema drift, manual edit) is ignored at merge time
  rather than crashing every consumer.

Engine/agents call sites still construct ``IntegrationAutonomy()`` defaults
today; wiring them through :func:`get_effective_autonomy` is the documented
next slice on #418.
"""

from __future__ import annotations

import logging

from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import OrgAutonomyRow

logger = logging.getLogger("btagent.services.autonomy")

# Containment categories: always HITL-gated in code, never configurable.
HITL_FORCED_CATEGORIES = frozenset({"host_isolation", "firewall_rule", "account_disable"})

# Categories an org may override: everything else on the shared model.
EDITABLE_CATEGORIES = frozenset(IntegrationAutonomy.model_fields) - HITL_FORCED_CATEGORIES

_VALID_LEVELS = frozenset(level.value for level in AutonomyLevel)


def validate_overrides(overrides: dict[str, str]) -> str | None:
    """Return a human-readable rejection reason, or None when valid."""
    for category, level in overrides.items():
        if category in HITL_FORCED_CATEGORIES:
            return (
                f"Category {category!r} is containment and always HITL-gated in code; "
                "its level cannot be configured."
            )
        if category not in EDITABLE_CATEGORIES:
            return f"Unknown autonomy category {category!r}."
        if level not in _VALID_LEVELS:
            return f"Invalid autonomy level {level!r} for {category!r} (expected L0–L4)."
    return None


async def get_overrides(db: AsyncSession, org_id: str) -> dict[str, str]:
    """The org's stored overrides (empty when never configured)."""
    row = await db.get(OrgAutonomyRow, org_id)
    return dict(row.overrides or {}) if row else {}


async def set_overrides(
    db: AsyncSession, *, org_id: str, overrides: dict[str, str], updated_by: str
) -> dict[str, str]:
    """Replace the org's override set wholesale (caller validates first).

    Flushes but never commits. An empty dict clears back to pure defaults.
    """
    row = await db.get(OrgAutonomyRow, org_id)
    if row is None:
        row = OrgAutonomyRow(org_id=org_id, overrides=dict(overrides), updated_by=updated_by)
        db.add(row)
    else:
        row.overrides = dict(overrides)
        row.updated_by = updated_by
    await db.flush()
    return dict(overrides)


async def get_effective_autonomy(db: AsyncSession, org_id: str) -> IntegrationAutonomy:
    """Shared defaults overlaid with the org's valid overrides."""
    overrides = await get_overrides(db, org_id)
    valid = {
        category: level
        for category, level in overrides.items()
        if category in EDITABLE_CATEGORIES and level in _VALID_LEVELS
    }
    dropped = set(overrides) - set(valid)
    if dropped:
        logger.warning(
            "Ignoring invalid stored autonomy overrides for org %s: %s", org_id, sorted(dropped)
        )
    return IntegrationAutonomy(**valid)
