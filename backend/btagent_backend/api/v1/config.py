"""Config API endpoints — org profile and data retention."""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.config import IntegrationAutonomy
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.db.models import DashboardPrefRow
from btagent_backend.db.models_behavioral import OrgProfileRow
from btagent_backend.services.config_catalog import build_config_catalog
from btagent_backend.services.dashboard_layout import DashboardLayout, role_default_layout
from btagent_backend.services.data_retention import DataRetentionService
from btagent_backend.services.org_profile import OrgProfile

logger = logging.getLogger("btagent.api.config")

router = APIRouter(prefix="/config", tags=["config"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class OrgProfileResponse(BaseModel):
    profile: dict[str, Any]


class ConfigSchemaResponse(BaseModel):
    """The #418 configuration inventory — safe metadata only, never secrets."""

    runtime: list[dict[str, Any]]
    deploy_time: list[dict[str, Any]]


class RetentionStatsResponse(BaseModel):
    events: dict[str, Any]
    audit_logs: dict[str, Any]
    investigations: dict[str, Any]


class RetentionRunResponse(BaseModel):
    events: dict[str, Any]
    investigations: dict[str, Any]
    audit_verification: dict[str, Any]


# ---------------------------------------------------------------------------
# Configuration inventory (#418 — Settings / Configuration Center)
# ---------------------------------------------------------------------------


# Human-readable meaning of each autonomy level (mirrors the AutonomyLevel
# enum comments in shared/btagent_shared/types/config.py).
_AUTONOMY_LEVEL_LEGEND: dict[str, str] = {
    "L0": "Every action requires approval",
    "L1": "Human approves plans, agent executes",
    "L2": "Agent executes, human reviews critical decisions",
    "L3": "Agent runs independently, escalates on issues",
    "L4": "Fully autonomous (scheduled tasks)",
}

# Containment categories are ALWAYS HITL-gated in code (engine middleware +
# connector manifests mark them hitl_required), regardless of the configured
# level — surfacing that here keeps the read view honest.
_HITL_FORCED_CATEGORIES = frozenset({"host_isolation", "firewall_rule", "account_disable"})


class AutonomyCategory(BaseModel):
    key: str
    level: str
    hitl_forced: bool


class AutonomyConfigResponse(BaseModel):
    categories: list[AutonomyCategory]
    levels: dict[str, str]
    # False until the #418 autonomy-editing slice lands — the UI renders
    # read-only when this is false.
    editable: bool


@router.get("/autonomy", response_model=AutonomyConfigResponse)
async def get_autonomy_config(
    user: CurrentUser = Depends(get_current_user),
) -> AutonomyConfigResponse:
    """The effective per-category autonomy levels (#418 slice 3, read-only).

    There is no per-org autonomy store yet — every engine/agents call site
    constructs ``IntegrationAutonomy()`` defaults — so this reports exactly
    what deployments run today. Containment categories additionally carry
    ``hitl_forced``: they are gated in code no matter the configured level.
    """
    user.require_permission("config:view")
    autonomy = IntegrationAutonomy()
    return AutonomyConfigResponse(
        categories=[
            AutonomyCategory(
                key=key,
                level=getattr(autonomy, key).value,
                hitl_forced=key in _HITL_FORCED_CATEGORIES,
            )
            for key in IntegrationAutonomy.model_fields
        ],
        levels=_AUTONOMY_LEVEL_LEGEND,
        editable=False,
    )


@router.get("/schema", response_model=ConfigSchemaResponse)
async def get_config_schema(
    user: CurrentUser = Depends(get_current_user),
) -> ConfigSchemaResponse:
    """The consolidated configuration inventory (#418 slice 1).

    Read-only: runtime-changeable surfaces (with their scope, write
    permission, and API/UI location) plus every deploy-time ``BTAGENT_*``
    knob with secret-bearing values redacted. Answers "what can I change,
    and where?" without exposing credential material.
    """
    user.require_permission("config:view")
    return ConfigSchemaResponse(**build_config_catalog(get_settings()))


# ---------------------------------------------------------------------------
# Org profile
# ---------------------------------------------------------------------------


@router.get("/org-profile", response_model=OrgProfileResponse)
async def get_org_profile_endpoint(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get the organisation profile for the caller's org (GH #393).

    Scoped to ``user.org_id`` — an analyst can only ever read their OWN org's
    profile. Returns a default (empty) profile when the org has none saved yet.
    """
    user.require_permission("config:view")
    result = await db.execute(select(OrgProfileRow).where(OrgProfileRow.org_id == user.org_id))
    row = result.scalar_one_or_none()

    if row is None or not row.profile:
        profile = OrgProfile()
    else:
        try:
            profile = OrgProfile.model_validate(row.profile)
        except Exception:
            logger.warning(
                "Failed to parse stored org profile for org %s; returning default",
                user.org_id,
            )
            profile = OrgProfile()

    return OrgProfileResponse(profile=profile.model_dump(mode="json"))


@router.put("/org-profile", response_model=OrgProfileResponse)
async def update_org_profile_endpoint(
    body: OrgProfile,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update the organisation profile for the caller's org (admin only, GH #393).

    Upserts ONLY the row for ``user.org_id`` — never a global row — so an
    admin's update can never overwrite another org's profile.
    """
    user.require_permission("config:org_profile")

    value = body.model_dump(mode="json")
    result = await db.execute(select(OrgProfileRow).where(OrgProfileRow.org_id == user.org_id))
    row = result.scalar_one_or_none()

    if row is None:
        db.add(
            OrgProfileRow(
                id=generate_id("orgprof"),
                org_id=user.org_id,
                profile=value,
                updated_by=user.id,
            )
        )
    else:
        row.profile = value
        row.updated_by = user.id

    await db.flush()
    logger.info("Org profile updated for org %s by user %s", user.org_id, user.id)
    return OrgProfileResponse(profile=body.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Dashboard layout (EPIC-5 role-tuned PunchList views, #108)
# ---------------------------------------------------------------------------


class DashboardLayoutResponse(BaseModel):
    layout: DashboardLayout
    # "user" when the caller saved a customization; "role_default" otherwise.
    source: str
    role: str


@router.get("/dashboard-layout", response_model=DashboardLayoutResponse)
async def get_dashboard_layout(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DashboardLayoutResponse:
    """The caller's PunchList layout — their saved one, else their role default.

    Self-scoped (no extra permission): a user can only ever read their own
    preference. A stored payload that no longer validates (schema drift) falls
    back to the role default rather than 500-ing the landing page.
    """
    pref = await db.get(DashboardPrefRow, user.id)
    if pref is not None and pref.layout:
        try:
            layout = DashboardLayout.model_validate(pref.layout)
            return DashboardLayoutResponse(layout=layout, source="user", role=user.role)
        except Exception:
            logger.warning(
                "Stored dashboard layout for user %s failed validation; using role default",
                user.id,
            )
    return DashboardLayoutResponse(
        layout=role_default_layout(user.role), source="role_default", role=user.role
    )


@router.put("/dashboard-layout", response_model=DashboardLayoutResponse)
async def put_dashboard_layout(
    body: DashboardLayout,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DashboardLayoutResponse:
    """Save the caller's PunchList layout (self-scoped upsert)."""
    value = body.model_dump(mode="json")
    pref = await db.get(DashboardPrefRow, user.id)
    if pref is None:
        db.add(DashboardPrefRow(user_id=user.id, layout=value))
    else:
        pref.layout = value
    await db.flush()
    return DashboardLayoutResponse(layout=body, source="user", role=user.role)


@router.delete("/dashboard-layout", response_model=DashboardLayoutResponse)
async def reset_dashboard_layout(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DashboardLayoutResponse:
    """Drop the caller's saved layout, reverting to their role default."""
    pref = await db.get(DashboardPrefRow, user.id)
    if pref is not None:
        await db.delete(pref)
        await db.flush()
    return DashboardLayoutResponse(
        layout=role_default_layout(user.role), source="role_default", role=user.role
    )


# ---------------------------------------------------------------------------
# Data retention
# ---------------------------------------------------------------------------


def _get_retention_service() -> DataRetentionService:
    """Build a DataRetentionService from current settings."""
    return DataRetentionService(get_settings())


@router.get("/retention", response_model=RetentionStatsResponse)
async def get_retention_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get data retention statistics for the admin dashboard."""
    user.require_permission("config:view")
    svc = _get_retention_service()
    stats = await svc.get_retention_stats(db)
    return RetentionStatsResponse(**stats)


@router.post("/retention/run", response_model=RetentionRunResponse)
async def run_retention_cleanup(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger a data retention cleanup (admin only).

    Performs:
    - Delete events older than the configured retention period
    - Archive closed investigations older than the retention period
    - Verify audit log retention compliance
    """
    user.require_permission("config:edit")
    svc = _get_retention_service()

    events_result = await svc.archive_old_events(db)
    inv_result = await svc.cleanup_old_investigations(db)
    audit_result = await svc.verify_audit_retention(db)

    logger.info(
        "Retention cleanup triggered by user %s: %d events deleted, %d investigations archived",
        user.id,
        events_result["deleted_count"],
        inv_result["archived_count"],
    )

    return RetentionRunResponse(
        events=events_result,
        investigations=inv_result,
        audit_verification=audit_result,
    )
