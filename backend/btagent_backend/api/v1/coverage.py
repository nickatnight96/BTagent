"""Coverage Console API (#501).

``GET /api/v1/coverage/console``
    One composed, read-only, org-scoped view of the detection-engineering loop:
    per-technique coverage + validation freshness (#118), broken/noisy rules
    (#112), techniques whose detections are unproven against telemetry (#113),
    validation verdict counts, and a prioritised "next best actions" list that
    deep-links into the surfaces that act on each.

RBAC ``hunt:view`` — the same read scope the coverage map, the run history and
the noise baseline already use. Nothing here mutates, triggers, or recomputes:
the endpoint is a composition over existing services (see
:mod:`btagent_backend.services.coverage_console_service`).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.coverage_console_service import (
    DEFAULT_LOOKBACK_RUNS,
    CoverageConsole,
    build_coverage_console,
)

logger = logging.getLogger("btagent.api.coverage")

router = APIRouter(prefix="/coverage", tags=["coverage"])


@router.get("/console", response_model=CoverageConsole)
async def get_coverage_console(
    stale_days: int = Query(
        90,
        ge=1,
        le=3650,
        description="A technique validated longer ago than this (or never) is stale.",
    ),
    lookback_runs: int = Query(
        DEFAULT_LOOKBACK_RUNS,
        ge=1,
        le=500,
        description="How many recent hunt-pack runs the rule-health roll-up reads.",
    ),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CoverageConsole:
    """The Coverage Console payload for the caller's org.

    Answers, in one request: what do we detect, what is broken, what is
    unproven, and what should we do next. Strictly org-scoped — every
    underlying query filters on the caller's ``org_id``, so one tenant can
    never see another's coverage.
    """
    user.require_permission("hunt:view")

    return await build_coverage_console(
        db,
        org_id=user.org_id,
        stale_days=stale_days,
        lookback_runs=lookback_runs,
    )
