"""Config API endpoints — org profile and data retention."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.services.data_retention import DataRetentionService
from btagent_backend.services.org_profile import (
    OrgProfile,
    get_org_profile,
    save_org_profile,
)

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
    """Get the organisation profile."""
    user.require_permission("config:view")
    profile = await get_org_profile(db)
    return OrgProfileResponse(profile=profile.model_dump(mode="json"))


@router.put("/org-profile", response_model=OrgProfileResponse)
async def update_org_profile_endpoint(
    body: OrgProfile,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update the organisation profile (admin only)."""
    user.require_permission("config:org_profile")

    saved = await save_org_profile(db, body, updated_by=user.id)
    logger.info("Org profile updated by user %s", user.id)
    return OrgProfileResponse(profile=saved.model_dump(mode="json"))


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
        "Retention cleanup triggered by user %s: %d events deleted, "
        "%d investigations archived",
        user.id,
        events_result["deleted_count"],
        inv_result["archived_count"],
    )

    return RetentionRunResponse(
        events=events_result,
        investigations=inv_result,
        audit_verification=audit_result,
    )
