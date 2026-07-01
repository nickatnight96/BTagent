"""Identity Hunts API — OAuth grant graph (#216 Phase C, slice 1).

Read-derive endpoint that exposes the principal × app × scope OAuth grant
graph the Phase B Identity Hunts UI uses (see PR #217 deferred-section).

Phase B's frontend currently builds the grant table client-side by extracting
``app_id`` / ``principal_id`` / ``scopes`` / ``consent_type`` / ``granted_at``
from each identity-domain ``HuntFinding.evidence`` dict (the shape the
``shared.hunt.identity`` detectors emit — see e.g. the dormant-app reactivation
detector). This endpoint moves that derivation server-side, dedupes by
``(org_id, principal_id, app_id, provider)``, and paginates.

By construction this is **read-only and reversible**:

* No new table.
* No migration.
* No write path; if the identity findings table is empty the response is
  empty too. The grants surface as soon as identity detectors emit findings.

A first-class ``oauth_grants`` table + ingest-side write path is a deliberate
follow-up. Keeping this slice read-derive lets the UI stop deriving the table
client-side immediately, while leaving every future choice open.

Reuses the Phase 6 hunt RBAC: ``hunt:view`` (analyst+) — same as
``list_findings`` it shadows.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import yaml
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.types.hunt import HuntDomain
from btagent_shared.types.identity_hunt import (
    IdentityProvider,
    OAuthConsentType,
    OAuthGrant,
    RevocationProposal,
    RevocationProposalStatus,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import InvestigationRow
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.playbook_service import PlaybookService

logger = logging.getLogger("btagent.api.identity")

router = APIRouter(prefix="/identity", tags=["identity"])


# --------------------------------------------------------------------------- #
# Response shape
# --------------------------------------------------------------------------- #


class OAuthGrantListResponse(BaseModel):
    items: list[OAuthGrant]
    total: int


# --------------------------------------------------------------------------- #
# Internal helpers — pure-logic so they're trivially unit-testable
# --------------------------------------------------------------------------- #


def _parse_dt(raw: object) -> datetime | None:
    """Accept ISO-8601 strings or datetimes from the evidence dict, ignore the rest.

    Detectors persist these as ``.isoformat()``; we only return a datetime when
    the value is non-empty and well-formed.
    """
    if isinstance(raw, datetime):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _coerce_consent(raw: object) -> OAuthConsentType:
    if isinstance(raw, OAuthConsentType):
        return raw
    if isinstance(raw, str):
        try:
            return OAuthConsentType(raw)
        except ValueError:
            return OAuthConsentType.UNKNOWN
    return OAuthConsentType.UNKNOWN


def _coerce_provider(raw: object) -> IdentityProvider | None:
    """Provider may be set explicitly in evidence; otherwise the caller falls back."""
    if isinstance(raw, IdentityProvider):
        return raw
    if isinstance(raw, str):
        try:
            return IdentityProvider(raw)
        except ValueError:
            return None
    return None


def _grant_from_evidence(
    row: HuntFindingRow,
    *,
    default_provider: IdentityProvider,
) -> OAuthGrant | None:
    """Extract an OAuthGrant from an identity finding's evidence dict.

    Returns ``None`` if the finding doesn't carry a complete grant tuple —
    not every identity-domain finding is grant-flavoured (token-replay,
    impossible-travel, etc.). Callers filter ``None`` out.
    """
    ev = row.evidence or {}
    principal_id = ev.get("principal_id")
    app_id = ev.get("app_id")
    if not isinstance(principal_id, str) or not isinstance(app_id, str):
        return None
    if not principal_id or not app_id:
        return None

    provider = _coerce_provider(ev.get("provider")) or default_provider
    granted_at = _parse_dt(ev.get("granted_at")) or row.created_at
    scopes_raw = ev.get("scopes")
    scopes = [s for s in scopes_raw if isinstance(s, str)] if isinstance(scopes_raw, list) else []

    return OAuthGrant(
        # Stable, dedup-friendly id derived from the unique grant tuple — same
        # key the dedupe step uses below, so two findings about the same grant
        # collapse to the same OAuthGrant.id.
        id=f"oag_{provider.value}_{principal_id}_{app_id}",
        org_id=row.org_id,
        app_id=app_id,
        app_display_name=ev.get("app_display_name") or "",
        principal_id=principal_id,
        provider=provider,
        scopes=scopes,
        consent_type=_coerce_consent(ev.get("consent_type")),
        granted_at=granted_at,
        last_used=_parse_dt(ev.get("last_used")),
        revoked_at=_parse_dt(ev.get("revoked_at")),
        raw={},
    )


def _naive(dt: datetime) -> datetime:
    """Strip tzinfo so naive (SQLite) and aware (Postgres / parsed ISO) datetimes
    can be compared without a TypeError. We only use this for *ordering*, never
    for storage, so dropping tz is safe."""
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


def _merge_into(latest: dict[str, OAuthGrant], grant: OAuthGrant, row_created_at: datetime) -> None:
    """Keep the freshest grant per dedup key.

    Picks the one whose source finding has the newer ``created_at`` so a
    later detector run that observes refreshed scopes / a revocation wins
    over an older snapshot.
    """
    existing = latest.get(grant.id)
    if existing is None:
        latest[grant.id] = grant
        return
    existing_anchor = _naive(existing.last_used or existing.granted_at)
    new_anchor = _naive(row_created_at)
    if new_anchor >= existing_anchor:
        latest[grant.id] = grant


# --------------------------------------------------------------------------- #
# GET /api/v1/identity/grants
# --------------------------------------------------------------------------- #


@router.get("/grants", response_model=OAuthGrantListResponse)
async def list_identity_grants(
    principal_id: str | None = Query(
        None,
        description="Filter to grants held by a single principal (user / service-account id).",
    ),
    active: bool | None = Query(
        None,
        description="True = only grants with no revoked_at; False = only revoked grants; omit for all.",
    ),
    provider: str | None = Query(
        None,
        description="Filter by identity provider (okta | entra | google_workspace | ...).",
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> OAuthGrantListResponse:
    """Org-scoped OAuth grant inventory, derived from identity hunt findings.

    Findings whose evidence dict doesn't carry a complete grant tuple
    (``principal_id`` + ``app_id``) are skipped — those are non-grant identity
    findings (token replay, impossible travel, etc.) and not part of the grant
    graph.

    Pagination is applied **after** dedup so a page is always ``page_size``
    distinct grants (not ``page_size`` raw rows where many collapse).
    """
    user.require_permission("hunt:view")

    coerced_provider = _coerce_provider(provider) if provider else None

    # Org + domain narrow at the SQL layer; principal/provider/active filter
    # in Python alongside the dedup loop so the implementation stays portable
    # across SQLite (tests) and Postgres (prod). Identity-domain finding
    # volumes are small enough — bounded by detector outputs — that this is
    # a non-issue at the expected order of magnitude.
    stmt = (
        select(HuntFindingRow)
        .where(HuntFindingRow.org_id == user.org_id)
        .where(HuntFindingRow.domain == HuntDomain.IDENTITY.value)
        .order_by(HuntFindingRow.created_at.desc())
    )

    rows_result = await db.execute(stmt)
    rows = list(rows_result.scalars().all())

    default_provider = coerced_provider or IdentityProvider.OKTA
    latest: dict[str, OAuthGrant] = {}
    for row in rows:
        grant = _grant_from_evidence(row, default_provider=default_provider)
        if grant is None:
            continue
        if principal_id and grant.principal_id != principal_id:
            continue
        if coerced_provider is not None and grant.provider is not coerced_provider:
            continue
        if active is True and grant.revoked_at is not None:
            continue
        if active is False and grant.revoked_at is None:
            continue
        _merge_into(latest, grant, row.created_at)

    # Stable sort: most-recently-granted first, then by id for tie-breaks.
    items = sorted(
        latest.values(),
        key=lambda g: (_naive(g.last_used or g.granted_at), g.id),
        reverse=True,
    )
    total = len(items)
    offset = (page - 1) * page_size
    return OAuthGrantListResponse(items=items[offset : offset + page_size], total=total)


# --------------------------------------------------------------------------- #
# Revocation proposal (#116 Phase C slice 2)
#
# Promotion of identity grant findings attaches an inert RevocationProposal
# to the investigation config (see hunt_triage_service.promote_to_investigation).
# These routes are the HITL gate: a senior analyst reviews the proposal and
# either accepts it — which materialises the proposal's playbook_spec as a
# real, runnable SOAR playbook (whose own first step is a second hitl_gate) —
# or rejects it with a rationale. Both decisions land on the audit chain.
# --------------------------------------------------------------------------- #

_PROPOSAL_KEY = "revocation_proposal"

_playbook_service = PlaybookService()


class RevocationDecisionRequest(BaseModel):
    rationale: str = Field(default="", max_length=8192)


async def _load_investigation_proposal(
    db: AsyncSession,
    *,
    investigation_id: str,
    user: CurrentUser,
) -> tuple[InvestigationRow, RevocationProposal]:
    """Fetch the org-scoped investigation and its revocation proposal (404 on either miss)."""
    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    # 404 on miss OR cross-org — same no-leak posture as the workflows route.
    if inv is None or inv.org_id != user.org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    assert_can_access_investigation(user, inv)

    raw = (inv.config or {}).get(_PROPOSAL_KEY)
    if not isinstance(raw, dict):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation has no revocation proposal",
        )
    try:
        proposal = RevocationProposal.model_validate(raw)
    except ValidationError:
        logger.exception("Malformed revocation proposal on investigation %s", investigation_id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Stored revocation proposal is malformed",
        ) from None
    return inv, proposal


def _store_proposal(inv: InvestigationRow, proposal: RevocationProposal) -> None:
    """Write the proposal back into the investigation config.

    Reassigns ``config`` wholesale so SQLAlchemy's JSON change detection
    (which doesn't track nested mutation) sees the update.
    """
    inv.config = {**(inv.config or {}), _PROPOSAL_KEY: proposal.model_dump(mode="json")}
    inv.updated_at = datetime.now(UTC)


@router.get(
    "/investigations/{investigation_id}/revocation-proposal",
    response_model=RevocationProposal,
)
async def get_revocation_proposal(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> RevocationProposal:
    """Read the revoke-playbook proposal attached to an investigation."""
    user.require_permission("hunt:view")
    _, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    return proposal


@router.post(
    "/investigations/{investigation_id}/revocation-proposal/accept",
    response_model=RevocationProposal,
)
async def accept_revocation_proposal(
    investigation_id: str,
    body: RevocationDecisionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> RevocationProposal:
    """Accept the proposal — the HITL decision that creates the real playbook.

    Gated on ``playbook:create`` (senior_analyst+): accepting *authors* a SOAR
    playbook, so the decision authority matches the playbook-authoring RBAC.
    Idempotency: a proposal that has already been decided returns 409 rather
    than silently re-creating playbooks.
    """
    user.require_permission("playbook:create")
    inv, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    if proposal.status is not RevocationProposalStatus.PROPOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Revocation proposal already {proposal.status.value}",
        )

    yaml_str = yaml.safe_dump(proposal.playbook_spec, sort_keys=False)
    try:
        playbook = await _playbook_service.create_playbook(
            db, name=proposal.playbook_name, yaml_str=yaml_str, user_id=user.id
        )
    except ValueError as exc:
        # The spec is generated by build_revocation_proposal, so this only
        # fires if the generator and the playbook schema drift apart.
        logger.exception("Generated revocation playbook failed validation")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Generated playbook failed validation: {exc}",
        ) from None

    proposal.status = RevocationProposalStatus.ACCEPTED
    proposal.playbook_id = playbook.id
    proposal.decided_by = user.id
    proposal.decided_at = datetime.now(UTC)
    proposal.decision_rationale = body.rationale
    _store_proposal(inv, proposal)

    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action="revocation_accept",
        resource=f"investigation:{inv.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "playbook_id": playbook.id,
            "target_count": len(proposal.targets),
            "rationale": body.rationale,
        },
    )
    return proposal


@router.post(
    "/investigations/{investigation_id}/revocation-proposal/reject",
    response_model=RevocationProposal,
)
async def reject_revocation_proposal(
    investigation_id: str,
    body: RevocationDecisionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> RevocationProposal:
    """Reject the proposal — same decision authority as accept."""
    user.require_permission("playbook:create")
    inv, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    if proposal.status is not RevocationProposalStatus.PROPOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Revocation proposal already {proposal.status.value}",
        )

    proposal.status = RevocationProposalStatus.REJECTED
    proposal.decided_by = user.id
    proposal.decided_at = datetime.now(UTC)
    proposal.decision_rationale = body.rationale
    _store_proposal(inv, proposal)

    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action="revocation_reject",
        resource=f"investigation:{inv.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "target_count": len(proposal.targets),
            "rationale": body.rationale,
        },
    )
    return proposal
