"""Config API endpoints — org profile, config inventory, flags, retention."""

from __future__ import annotations

import logging
import re
from typing import Any

from btagent_shared.types.config import IntegrationAutonomy
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.db.models import DashboardPrefRow, FeatureFlagRow
from btagent_backend.db.models_behavioral import OrgProfileRow
from btagent_backend.services import autonomy_service
from btagent_backend.services.audit_trail import AuditTrail
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


class AutonomyCategory(BaseModel):
    key: str
    level: str
    hitl_forced: bool
    # True when the org has a stored override for this category.
    overridden: bool = False


class AutonomyConfigResponse(BaseModel):
    categories: list[AutonomyCategory]
    levels: dict[str, str]
    # PUT /config/autonomy exists (config:edit); containment stays locked.
    editable: bool


class AutonomyOverridesRequest(BaseModel):
    """Wholesale replacement of the org's override set; {} clears to defaults."""

    overrides: dict[str, str] = Field(default_factory=dict, max_length=32)


async def _autonomy_response(db: AsyncSession, org_id: str) -> AutonomyConfigResponse:
    autonomy = await autonomy_service.get_effective_autonomy(db, org_id)
    overrides = await autonomy_service.get_overrides(db, org_id)
    return AutonomyConfigResponse(
        categories=[
            AutonomyCategory(
                key=key,
                level=getattr(autonomy, key).value,
                hitl_forced=key in autonomy_service.HITL_FORCED_CATEGORIES,
                overridden=key in overrides,
            )
            for key in IntegrationAutonomy.model_fields
        ],
        levels=_AUTONOMY_LEVEL_LEGEND,
        editable=True,
    )


@router.get("/autonomy", response_model=AutonomyConfigResponse)
async def get_autonomy_config(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AutonomyConfigResponse:
    """Effective per-category autonomy levels (#418): shared defaults merged
    with the caller's org overrides. Containment categories carry
    ``hitl_forced`` — gated in code no matter the configured level."""
    user.require_permission("config:view")
    return await _autonomy_response(db, user.org_id)


@router.put("/autonomy", response_model=AutonomyConfigResponse)
async def put_autonomy_config(
    body: AutonomyOverridesRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AutonomyConfigResponse:
    """Replace the org's autonomy overrides (#418 slice 6, admin only).

    Containment categories are rejected with 422 — the store never even
    claims to loosen the code-enforced HITL gate. An empty override set
    reverts the org to pure shared defaults. Stored overrides now take
    execution effect (PR #430): investigation runs (``task_manager``) and
    workflow runs (``workflow_run_service``) resolve the org's effective
    per-category levels via ``get_effective_autonomy`` before dispatch.
    """
    user.require_permission("config:edit")

    reason = autonomy_service.validate_overrides(body.overrides)
    if reason is not None:
        raise HTTPException(status_code=422, detail=reason)

    await autonomy_service.set_overrides(
        db, org_id=user.org_id, overrides=body.overrides, updated_by=user.id
    )
    # Autonomy governs which agent actions pause for a human, so replacing the
    # org's posture is a security-relevant config change — record it on the
    # hash-chained ledger, not just the app log. ``resource`` keys the org's
    # autonomy config so an auditor can pull its whole change history.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="config_autonomy_overrides_replaced",
        resource=f"org_autonomy:{user.org_id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "override_count": len(body.overrides),
            "overrides": dict(body.overrides),
        },
        org_id=user.org_id,
    )
    logger.info(
        "Autonomy overrides replaced for org %s by user %s (%d override(s))",
        user.org_id,
        user.id,
        len(body.overrides),
    )
    return await _autonomy_response(db, user.org_id)


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
    # The org profile is injected into agent prompts, so a change steers every
    # subsequent investigation's context — audit it on the ledger.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="config_org_profile_updated",
        resource=f"org_profile:{user.org_id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "industry": body.industry,
            "compliance": list(body.compliance),
        },
        org_id=user.org_id,
    )
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
# Feature flags (#418 — per-org capability toggles)
# ---------------------------------------------------------------------------

# lowercase snake_case, 1-64 chars, must start with a letter.
_FLAG_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_FLAGS = 100


class FeatureFlags(BaseModel):
    """The org's complete flag set — PUT replaces it wholesale."""

    flags: dict[str, bool] = Field(default_factory=dict, max_length=_MAX_FLAGS)


@router.get("/feature-flags", response_model=FeatureFlags)
async def get_feature_flags(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> FeatureFlags:
    """The caller's org's feature flags (empty when never configured)."""
    user.require_permission("config:view")
    result = await db.execute(select(FeatureFlagRow).where(FeatureFlagRow.org_id == user.org_id))
    return FeatureFlags(flags={row.key: row.value for row in result.scalars()})


@router.put("/feature-flags", response_model=FeatureFlags)
async def put_feature_flags(
    body: FeatureFlags,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> FeatureFlags:
    """Replace the org's flag set (admin only; org-scoped; keys validated).

    Wholesale-replace semantics keep the API unambiguous: the stored set
    after the call is exactly the request body. Flags absent from the body
    are deleted, present ones upserted.
    """
    user.require_permission("config:edit")

    for key in body.flags:
        if not _FLAG_KEY_RE.match(key):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid flag key {key!r}: must match {_FLAG_KEY_RE.pattern}",
            )

    result = await db.execute(select(FeatureFlagRow).where(FeatureFlagRow.org_id == user.org_id))
    existing = {row.key: row for row in result.scalars()}

    for key, row in existing.items():
        if key not in body.flags:
            await db.delete(row)
    for key, value in body.flags.items():
        row = existing.get(key)
        if row is None:
            db.add(FeatureFlagRow(org_id=user.org_id, key=key, value=value, updated_by=user.id))
        elif row.value != value:
            row.value = value
            row.updated_by = user.id

    await db.flush()
    # Flags gate per-org capabilities, so a wholesale replacement is a config
    # change worth pinning on the ledger.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="config_feature_flags_replaced",
        resource=f"feature_flags:{user.org_id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "flag_count": len(body.flags),
            "flags": dict(body.flags),
        },
        org_id=user.org_id,
    )
    logger.info(
        "Feature flags replaced for org %s by user %s (%d flag(s))",
        user.org_id,
        user.id,
        len(body.flags),
    )
    return FeatureFlags(flags=dict(body.flags))


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
    stats = await svc.get_retention_stats(db, org_id=user.org_id)
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

    # B6: a retention run is destructive and admin-of-*any*-org triggerable,
    # so it must only touch the caller's own tenant.
    events_result = await svc.archive_old_events(db, org_id=user.org_id)
    inv_result = await svc.cleanup_old_investigations(db, org_id=user.org_id)
    audit_result = await svc.verify_audit_retention(db, org_id=user.org_id)

    # A manual retention run irreversibly deletes events and archives
    # investigations, so the destructive action itself must be defensible on
    # the ledger with the counts it affected.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="config_retention_cleanup_run",
        resource="data_retention",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "events_deleted": events_result["deleted_count"],
            "investigations_archived": inv_result["archived_count"],
            "audit_verification": audit_result,
        },
        org_id=user.org_id,
    )

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
