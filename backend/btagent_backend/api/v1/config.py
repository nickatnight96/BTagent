"""Config API endpoints — org profile and data retention."""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.db.models_behavioral import OrgProfileRow
from btagent_backend.services.data_retention import DataRetentionService
from btagent_backend.services.org_profile import OrgProfile

logger = logging.getLogger("btagent.api.config")

router = APIRouter(prefix="/config", tags=["config"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class OrgProfileResponse(BaseModel):
    profile: dict[str, Any]


class RetentionStatsResponse(BaseModel):
    events: dict[str, Any]
    audit_logs: dict[str, Any]
    investigations: dict[str, Any]


class RetentionRunResponse(BaseModel):
    events: dict[str, Any]
    investigations: dict[str, Any]
    audit_verification: dict[str, Any]


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
