"""Test-only seed routes for stores with no public write API.

The behavioral and pattern-hunt stores are written exclusively by internal
pipelines (the behavioral scan sweep, the weekly pattern scan) — there is,
correctly, no product route that creates entities, outliers, or proposals.
That leaves browser tests with nothing to render against: the E2E specs for
/behavioral and /pattern-insights sat skipped from the day they merged
because the seed endpoints they call did not exist. (Hunt *findings* never
needed this module — ``POST /hunt/findings`` is a real product ingest route.)

These routes close that gap without opening a production write path:

* **Environment gate.** Outside ``BTAGENT_ENV=test`` every route here answers
  404 — indistinguishable from a route that was never registered, so nothing
  is discoverable in dev/staging/prod. The CI E2E stack (and only it) runs
  with ``BTAGENT_ENV=test``.
* **Same auth posture as real writes.** Even in test mode the caller must be
  authenticated and hold ``hunt:create`` (analyst+), and every row is stamped
  with the *caller's* org — a persona can't seed another tenant.
* **Store invariants respected.** Enum-valued columns are validated through
  the shared enums, ``hunt_input`` through the shared ``HuntInput`` model,
  and the unique-index keys (entity ``org/kind/canonical_id``, proposal
  ``org/cluster_id``) upsert instead of violating.

Every route lives in ``NOT_BROWSER_CALLED`` in the reachability ratchet:
Playwright calls them over HTTP, the SPA never does.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.behavioral import EntityKind, ProfileType
from btagent_shared.types.hunt import HuntInput
from btagent_shared.types.pattern_hunt import ProposalState
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.db.models_behavioral import BehavioralEntityRow, BehavioralOutlierRow
from btagent_backend.db.models_pattern import PatternHuntProposalRow

logger = logging.getLogger("btagent.api.test_seed")

router = APIRouter(tags=["test-seed"])


def _require_test_env() -> None:
    """404 (not 403) outside test mode: the routes must not even be probeable."""
    if get_settings().env != "test":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


class SeedIdResponse(BaseModel):
    id: str


# --------------------------------------------------------------------------- #
# Behavioral (#114 Phase B specs)
# --------------------------------------------------------------------------- #


class SeedEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_config = ConfigDict(extra="forbid")

    kind: EntityKind
    canonical_id: str = Field(..., min_length=1, max_length=512)
    enrichment: dict[str, Any] = Field(default_factory=dict)


@router.post(
    "/behavioral/test/entities",
    response_model=SeedIdResponse,
    status_code=201,
    dependencies=[Depends(_require_test_env)],
)
async def seed_behavioral_entity(
    body: SeedEntityRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SeedIdResponse:
    """Get-or-create a behavioral entity (upsert key: org/kind/canonical_id)."""
    user.require_permission("hunt:create")
    existing = (
        await db.execute(
            select(BehavioralEntityRow).where(
                BehavioralEntityRow.org_id == user.org_id,
                BehavioralEntityRow.kind == body.kind.value,
                BehavioralEntityRow.canonical_id == body.canonical_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return SeedIdResponse(id=existing.id)

    row = BehavioralEntityRow(
        id=generate_id("bent"),
        org_id=user.org_id,
        kind=body.kind.value,
        canonical_id=body.canonical_id,
        enrichment=body.enrichment,
    )
    db.add(row)
    await db.flush()
    return SeedIdResponse(id=row.id)


class SeedOutlierRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., min_length=1, max_length=64)
    profile_type: ProfileType
    event_id: str = Field(..., min_length=1, max_length=200)
    cosine_distance: float = Field(..., ge=0.0, le=2.0)
    frequency_rank: int = Field(default=0, ge=0)
    raw_event_excerpt: str = Field(default="", max_length=8192)


@router.post(
    "/behavioral/test/outliers",
    response_model=SeedIdResponse,
    status_code=201,
    dependencies=[Depends(_require_test_env)],
)
async def seed_behavioral_outlier(
    body: SeedOutlierRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SeedIdResponse:
    """Attach an untriaged outlier to one of the caller's org's entities."""
    user.require_permission("hunt:create")
    entity = (
        await db.execute(
            select(BehavioralEntityRow).where(BehavioralEntityRow.id == body.entity_id)
        )
    ).scalar_one_or_none()
    # 404 on miss OR cross-org — same no-leak posture as the product routes.
    if entity is None or entity.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Behavioral entity not found")

    row = BehavioralOutlierRow(
        id=generate_id("bout"),
        org_id=user.org_id,
        entity_id=entity.id,
        profile_type=body.profile_type.value,
        event_id=body.event_id,
        event_pattern_key=body.event_id,
        cosine_distance=body.cosine_distance,
        frequency_rank=body.frequency_rank,
        raw_event_excerpt=body.raw_event_excerpt,
    )
    db.add(row)
    await db.flush()
    return SeedIdResponse(id=row.id)


# --------------------------------------------------------------------------- #
# Pattern-hunt proposals (#120 Phase B specs)
# --------------------------------------------------------------------------- #


class SeedProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Field(..., min_length=1, max_length=128)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    hunt_input: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=8192)
    state: ProposalState = ProposalState.PROPOSED


@router.post(
    "/pattern/test/proposals",
    response_model=SeedIdResponse,
    status_code=201,
    dependencies=[Depends(_require_test_env)],
)
async def seed_pattern_proposal(
    body: SeedProposalRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SeedIdResponse:
    """Upsert a pattern-hunt proposal (unique key: org/cluster_id)."""
    user.require_permission("hunt:create")
    # Keep the store well-formed: the same shape the pattern scan persists.
    # ``initiated_by`` is required on HuntInput but is the caller's own id
    # for a seeded proposal, so default it rather than making specs carry it.
    try:
        hunt_input = HuntInput.model_validate({"initiated_by": user.id, **body.hunt_input})
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"hunt_input is not a HuntInput: {exc}")

    existing = (
        await db.execute(
            select(PatternHuntProposalRow).where(
                PatternHuntProposalRow.org_id == user.org_id,
                PatternHuntProposalRow.cluster_id == body.cluster_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.score = body.score
        existing.hunt_input = hunt_input.model_dump(mode="json")
        existing.rationale = body.rationale
        existing.state = body.state.value
        await db.flush()
        return SeedIdResponse(id=existing.id)

    row = PatternHuntProposalRow(
        id=generate_id("phpr"),
        org_id=user.org_id,
        cluster_id=body.cluster_id,
        score=body.score,
        hunt_input=hunt_input.model_dump(mode="json"),
        rationale=body.rationale,
        state=body.state.value,
    )
    db.add(row)
    await db.flush()
    return SeedIdResponse(id=row.id)


# --------------------------------------------------------------------------- #
# Investigations (#103 demo-scenario UAT)
# --------------------------------------------------------------------------- #


class SeedInvestigationRequest(BaseModel):
    """Create an investigation row with a caller-chosen id.

    The product create route mints its own ULID, but the report plugin's
    case-data source is still the fixed-id mock store (#109 gap), so an
    end-to-end reporting demo needs a DB row whose id matches a mock-store
    case (e.g. ``inv_mock_001``) to pass the route's org-scope check. Only
    this test-gated route may choose an id; it upserts on (org, id).
    """

    model_config = ConfigDict(extra="forbid")

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=4, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=20000)
    severity: str = Field(default="medium", max_length=20)
    status_value: str = Field(default="investigating", max_length=50, alias="status")


@router.post(
    "/investigations/test/seed",
    response_model=SeedIdResponse,
    status_code=201,
    dependencies=[Depends(_require_test_env)],
)
async def seed_investigation(
    body: SeedInvestigationRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SeedIdResponse:
    """Get-or-create an investigation with an explicit id (test env only)."""
    user.require_permission("investigation:create")

    from btagent_backend.db.models import InvestigationRow

    existing = (
        await db.execute(
            select(InvestigationRow).where(
                InvestigationRow.id == body.id,
                InvestigationRow.org_id == user.org_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return SeedIdResponse(id=existing.id)

    row = InvestigationRow(
        id=body.id,
        org_id=user.org_id,
        title=body.title,
        description=body.description,
        status=body.status_value,
        severity=body.severity,
        tlp_level="green",
        assigned_to=user.id,
    )
    db.add(row)
    await db.flush()
    return SeedIdResponse(id=row.id)
