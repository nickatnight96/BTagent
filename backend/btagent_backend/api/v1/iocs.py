"""IOC CRUD, enrichment, and STIX import/export endpoints."""

from __future__ import annotations

import csv
import io
import logging
from typing import Any, Literal

from btagent_shared.security import EgressKind, TLPViolation, tlp_rank
from btagent_shared.types.config import TLP
from btagent_shared.types.enums import IOCType
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import (
    assert_can_access_investigation,
    assert_can_access_ioc,
)
from btagent_backend.db.models import InvestigationRow, IOCRow
from btagent_backend.services import ioc_service, stix_service
from btagent_backend.services.tlp_egress_guard import assert_org_policy_allows_egress

logger = logging.getLogger("btagent.api.iocs")

router = APIRouter(prefix="/iocs", tags=["iocs"])

# AUTH-B1: roles allowed to see every IOC in their org regardless of which
# investigation owns it. Plain analysts can only see IOCs whose parent
# investigation they own.
_ORG_WIDE_ROLES = frozenset({"admin", "incident_commander", "senior_analyst"})


async def _load_investigation_or_404(db: AsyncSession, investigation_id: str) -> InvestigationRow:
    """Fetch an investigation row or raise 404 (no scoping check)."""
    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Not found")
    return inv


# --------------------------------------------------------------------------- #
# Request / Response schemas
# --------------------------------------------------------------------------- #


# Hard caps on bulk endpoints. ``BulkCreateIOCRequest.iocs`` and
# ``BulkEnrichRequest.ioc_ids`` are unauthenticated-ish in the sense that a
# legitimate analyst can submit them, but without a list-size cap an
# off-by-one in the FE (or a malicious actor with valid creds) can DoS the
# enrichment scheduler with a single request. 500 is comfortably above any
# real analyst workflow and well below the heap-pressure threshold.
_MAX_BULK_IOCS = 500


class CreateIOCRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str
    type: IOCType
    value: str = Field(..., min_length=1, max_length=2048)
    tlp_level: str = "green"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = Field(default="", max_length=4096)
    source: str = Field(default="", max_length=256)


class BulkCreateIOCRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str
    iocs: list[CreateIOCRequest] = Field(..., min_length=1, max_length=_MAX_BULK_IOCS)


class UpdateIOCRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: IOCType | None = None
    value: str | None = Field(default=None, min_length=1, max_length=2048)
    tlp_level: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    context: str | None = Field(default=None, max_length=4096)
    source: str | None = Field(default=None, max_length=256)
    enrichment: dict[str, Any] | None = None


class MitreTagOut(BaseModel):
    """A MITRE technique tag on this IOC, with the technique named inline.

    The frontend's ``MitreTag`` type has carried exactly this shape since the
    IOC detail panel first rendered a "MITRE ATT&CK Techniques" section — but
    nothing on the backend ever populated it, so that section had never once
    rendered. Wiring the tag write path (``POST /mitre/tag``) exposed the
    fiction on the read side.
    """

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float


class IOCResponse(BaseModel):
    id: str
    investigation_id: str
    type: str
    value: str
    tlp_level: str
    confidence: float
    first_seen: str | None
    last_seen: str | None
    context: str
    source: str
    enrichment: dict[str, Any]
    # UC-5.2 notebook annotations (#108).
    pinned: bool
    tags: list[str]
    analyst_note: str
    disposition: str
    # Populated on the detail endpoint only — the list endpoint stays a
    # single query and the notebook table doesn't render tags anyway.
    mitre_tags: list[MitreTagOut] = []


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int


class AnnotateIOCRequest(BaseModel):
    """Partial update of the UC-5.2 notebook annotations.

    Only the supplied fields change (``exclude_unset`` semantics), so a pin
    toggle doesn't clobber tags or the note. Empty string / empty list are
    valid values — they clear the field.
    """

    model_config = ConfigDict(extra="forbid")

    pinned: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=20)
    analyst_note: str | None = Field(default=None, max_length=8192)
    disposition: (
        Literal["", "under_review", "confirmed_malicious", "benign", "false_positive"] | None
    ) = None


class EnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pass  # No body needed; IOC ID comes from URL path


class BulkEnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # See ``_MAX_BULK_IOCS`` above — same DoS-mitigation cap. Each id is
    # also length-bounded so a million-character "id" can't sneak past the
    # FastAPI request-body size limit.
    ioc_ids: list[str] = Field(..., min_length=1, max_length=_MAX_BULK_IOCS)


class STIXImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundle: dict[str, Any]
    investigation_id: str


class TextImportRequest(BaseModel):
    """Frontend-shaped import body (``IOCImportModal`` sends ``{data, investigation_id}``).

    Used by both ``/import/csv`` (raw CSV text) and ``/import/stix`` (STIX
    bundle as a JSON string — kept distinct from ``STIXImportRequest``
    which expects an already-parsed object).
    """

    model_config = ConfigDict(extra="forbid")

    data: str
    investigation_id: str


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _reject_if_over_bulk_cap(count: int) -> None:
    """Enforce the documented bulk-size cap on an import batch.

    The STIX / CSV import endpoints build their IOC list from a free-form
    payload (a STIX bundle or CSV blob) and then funnel it into
    ``create_iocs_bulk`` — the same insert path the ``POST /iocs`` bulk route
    uses. That route caps its list via ``BulkCreateIOCRequest``'s Pydantic
    ``max_length=_MAX_BULK_IOCS``; the import paths had no equivalent guard, so
    a single oversized bundle could bypass the cap and DoS the enrichment
    scheduler. Re-use the same ``_MAX_BULK_IOCS`` constant here and reject an
    oversized import with 413 (Request Entity Too Large).
    """
    if count > _MAX_BULK_IOCS:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Import exceeds the maximum bulk size of {_MAX_BULK_IOCS} IOCs "
                f"(got {count}). Split the import into smaller batches."
            ),
        )


def _to_response(row: IOCRow, mitre_tags: list[MitreTagOut] | None = None) -> IOCResponse:
    return IOCResponse(
        id=row.id,
        investigation_id=row.investigation_id,
        type=row.type,
        value=row.value,
        tlp_level=row.tlp_level,
        confidence=row.confidence,
        first_seen=row.first_seen.isoformat() if row.first_seen else None,
        last_seen=row.last_seen.isoformat() if row.last_seen else None,
        context=row.context,
        source=row.source,
        enrichment=row.enrichment or {},
        pinned=bool(row.pinned),
        tags=list(row.tags or []),
        analyst_note=row.analyst_note or "",
        disposition=row.disposition or "",
        mitre_tags=mitre_tags or [],
    )


async def _mitre_tags_for(db: AsyncSession, ioc_id: str) -> list[MitreTagOut]:
    """The IOC's technique tags with names resolved, newest first.

    Joined against ``mitre_techniques`` so the panel can show a name rather
    than a bare Txxxx id. A tag whose technique isn't in the loaded matrix
    (matrix not seeded, or a stale id) still returns — with the id standing
    in for the name — because hiding an existing tag is worse than showing
    it unnamed.
    """
    from btagent_backend.db.models_mitre import MitreTechniqueRow, MitreTechniqueTagRow

    rows = (
        await db.execute(
            select(MitreTechniqueTagRow, MitreTechniqueRow)
            .outerjoin(MitreTechniqueRow, MitreTechniqueTagRow.technique_id == MitreTechniqueRow.id)
            .where(
                MitreTechniqueTagRow.entity_type == "ioc",
                MitreTechniqueTagRow.entity_id == ioc_id,
            )
            .order_by(MitreTechniqueTagRow.created_at.desc())
        )
    ).all()
    return [
        MitreTagOut(
            technique_id=tag.technique_id,
            technique_name=tech.name if tech is not None else tag.technique_id,
            tactic=tech.tactic if tech is not None else "",
            confidence=tag.confidence,
        )
        for tag, tech in rows
    ]


# --------------------------------------------------------------------------- #
# CRUD Endpoints
# --------------------------------------------------------------------------- #


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    ioc_type: str | None = Query(None, alias="type"),
    investigation_id: str | None = Query(None),
    confidence_min: float | None = Query(None, ge=0.0, le=1.0),
    enriched: bool | None = Query(None),
    pinned: bool | None = Query(None, description="UC-5.2: true → pinned notebook set only"),
    search: str | None = Query(None, description="Substring filter on IOC value (ilike)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List IOCs with optional filters and pagination."""
    user.require_permission("ioc:view")

    # AUTH-B1: tenant scoping. If the caller filters by investigation_id we
    # validate access to that investigation up front; otherwise we narrow
    # the query to the caller's org (and, for plain analysts, to investigations
    # they own).
    accessible_investigation_ids: list[str] | None = None
    if investigation_id is not None:
        inv = await _load_investigation_or_404(db, investigation_id)
        assert_can_access_investigation(user, inv)
    else:
        # Build the set of investigation_ids the caller may see, then push
        # that into the IOC list query.
        inv_q = select(InvestigationRow.id).where(InvestigationRow.org_id == user.org_id)
        if user.role not in _ORG_WIDE_ROLES:
            inv_q = inv_q.where(InvestigationRow.assigned_to == user.id)
        inv_result = await db.execute(inv_q)
        accessible_investigation_ids = [row[0] for row in inv_result.all()]
        if not accessible_investigation_ids:
            return IOCListResponse(items=[], total=0, page=page, page_size=page_size)

    rows, total = await ioc_service.list_iocs(
        db,
        investigation_id=investigation_id,
        ioc_type=ioc_type,
        confidence_min=confidence_min,
        enriched=enriched,
        pinned=pinned,
        search=search,
        page=page,
        page_size=page_size,
        investigation_id_in=accessible_investigation_ids,
    )

    return IOCListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/search", response_model=IOCListResponse)
async def search_iocs(
    value: str | None = Query(None),
    ioc_type: str | None = Query(None, alias="type"),
    confidence_min: float | None = Query(None, ge=0.0, le=1.0),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Search IOCs across all investigations.

    Supports partial value matching and cross-investigation correlation.
    """
    user.require_permission("ioc:view")

    # AUTH-B1: cross-investigation search must still respect tenant + (for
    # plain analysts) ownership scoping. Compute the accessible parent set
    # and pass it down so the service-layer filter is applied at the SQL
    # level rather than after-the-fact.
    inv_q = select(InvestigationRow.id).where(InvestigationRow.org_id == user.org_id)
    if user.role not in _ORG_WIDE_ROLES:
        inv_q = inv_q.where(InvestigationRow.assigned_to == user.id)
    inv_result = await db.execute(inv_q)
    accessible_investigation_ids = [row[0] for row in inv_result.all()]
    if not accessible_investigation_ids:
        return IOCListResponse(items=[], total=0, page=page, page_size=page_size)

    rows, total = await ioc_service.search_cross_investigation(
        db,
        value=value,
        ioc_type=ioc_type,
        confidence_min=confidence_min,
        page=page,
        page_size=page_size,
        investigation_id_in=accessible_investigation_ids,
    )

    return IOCListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/notebook/search", response_model=IOCListResponse)
async def search_notebook(
    q: str | None = Query(None, max_length=200, description="Matches note, tags, and value"),
    disposition: Literal["under_review", "confirmed_malicious", "benign", "false_positive"]
    | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Search analyst-annotated IOCs across cases (#108 UC-5.2 notebook).

    Unlike ``/iocs/search`` (raw indicator values), this searches the
    notebook layer — only IOCs with at least one annotation, with ``q``
    matching the analyst note and tags too — so "have we seen this before,
    and what did we conclude?" is answerable across investigations.
    """
    user.require_permission("ioc:view")

    # AUTH-B1: same tenant + (for plain analysts) ownership scoping as the
    # sibling cross-investigation search above.
    inv_q = select(InvestigationRow.id).where(InvestigationRow.org_id == user.org_id)
    if user.role not in _ORG_WIDE_ROLES:
        inv_q = inv_q.where(InvestigationRow.assigned_to == user.id)
    inv_result = await db.execute(inv_q)
    accessible_investigation_ids = [row[0] for row in inv_result.all()]
    if not accessible_investigation_ids:
        return IOCListResponse(items=[], total=0, page=page, page_size=page_size)

    rows, total = await ioc_service.search_notebook(
        db,
        q=q,
        disposition=disposition,
        page=page,
        page_size=page_size,
        investigation_id_in=accessible_investigation_ids,
    )

    return IOCListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


#: Serialisations ``GET /iocs/export`` can produce. ``stix_2.1`` is the
#: default and the only one that carries TLP markings structurally; see
#: :func:`_render_export` for how the other two keep classification with the
#: data instead.
ExportFormat = Literal["stix_2.1", "csv", "json"]


def _render_export(ioc_dicts: list[dict[str, Any]], *, fmt: str, tlp: str) -> Response:
    """Serialise the (already TLP-filtered) IOCs in the requested format.

    Every format carries the classification with the data. STIX has
    ``object_marking_refs``; CSV and JSON have no such mechanism, so they
    carry an explicit ``tlp`` column/field. Without it, choosing CSV would
    turn the export into a classification-stripping channel — the indicators
    leave, the label does not.

    The CSV column order matches what :func:`_parse_csv_rows` reads
    (``type,value,source,confidence``), so an export re-imports cleanly; the
    parser ignores columns past the fourth, which is where ``tlp`` sits.
    """
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["type", "value", "source", "confidence", "tlp"])
        for ioc in ioc_dicts:
            writer.writerow(
                [
                    ioc["type"],
                    ioc["value"],
                    ioc.get("source") or "btagent_export",
                    ioc.get("confidence", 0.5),
                    ioc.get("tlp_level", tlp),
                ]
            )
        return Response(content=buf.getvalue(), media_type="text/csv")

    if fmt == "json":
        return JSONResponse(content={"tlp_level": tlp, "iocs": ioc_dicts})

    return JSONResponse(content=stix_service.stix_bundle_from_iocs(ioc_dicts, tlp_level=tlp))


@router.get("/export", response_model=None)
async def export_stix(
    investigation_id: str = Query(...),
    tlp_level: str = Query("green"),
    # Aliased: the wire names are ``format`` and ``type``, which shadow
    # builtins if used as Python parameter names.
    export_format: ExportFormat = Query("stix_2.1", alias="format"),
    ioc_type: IOCType | None = Query(None, alias="type"),
    confidence_min: float = Query(0.0, ge=0.0, le=1.0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Export an investigation's IOCs.

    ``tlp_level`` is the classification this export is being made at, and it
    acts as a ceiling: an indicator more restricted than it is excluded rather
    than shipped under a weaker marking. TLP:RED is never exportable, and the
    org egress policy is evaluated against the same value.

    Until #586 the export dialog sent this as ``tlp_max``. FastAPI drops an
    unknown query parameter silently, so ``tlp_level`` always fell back to its
    ``"green"`` default: the analyst's choice reached nothing, every bundle
    was marked TLP:GREEN, and the org policy was only ever evaluated at green.
    The frontend now sends ``tlp_level``; this name is canonical because the
    API tests, the security E2E spec and ``docs/deployment/air-gap.md`` all
    already speak it.

    ``format``, ``type`` and ``confidence_min`` are the export dialog's other
    three controls, which the route did not declare and therefore discarded in
    the same silent way. ``format`` was the worst of the three: the endpoint
    always returned a STIX bundle while ``iocStore`` picked the *download
    extension* from the analyst's choice, so selecting CSV saved STIX JSON
    into a ``.csv`` file.
    """
    user.require_permission("ioc:export")

    try:
        ceiling = TLP(tlp_level)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown TLP level {tlp_level!r}. Expected one of: "
            f"{', '.join(t.value for t in TLP)}.",
        ) from None

    if ceiling is TLP.RED:
        raise HTTPException(
            status_code=403,
            detail="Cannot export TLP:RED IOCs. Downgrade TLP level before export.",
        )

    # AUTH-B1: scope check on the parent investigation before exporting.
    inv = await _load_investigation_or_404(db, investigation_id)
    assert_can_access_investigation(user, inv)

    # UC-7.2: this org's TLP policies may forbid this channel carrying this
    # classification even though the universal gate above permits it. Org
    # policies can only ever *subtract* permission here — see
    # services/tlp_egress_guard.py.
    try:
        await assert_org_policy_allows_egress(
            db, org_id=user.org_id, tlp=ceiling.value, egress_kind=EgressKind.STIX_EXPORT.value
        )
    except TLPViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    rows, _ = await ioc_service.list_iocs(
        db,
        investigation_id=investigation_id,
        page=1,
        page_size=10000,  # Export all
    )

    # Apply the ceiling. This generalises the hardcoded ``!= "red"`` drop that
    # stood here: an IOC goes out only if its restriction rank is at or below
    # the ceiling's, so choosing TLP:GREEN no longer silently ships AMBER
    # indicators. An unrecognised stored ``tlp_level`` is not in the allowed
    # set, so it fails closed rather than being treated as unclassified.
    allowed = {t.value for t in TLP if tlp_rank(t) <= tlp_rank(ceiling)}
    ioc_dicts = [
        {
            "id": r.id,
            "type": r.type,
            "value": r.value,
            "confidence": r.confidence,
            "context": r.context,
            "source": r.source,
            "tlp_level": r.tlp_level,
            "enrichment": r.enrichment,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        }
        for r in rows
        # The TLP ceiling is applied first and unconditionally: the dialog's
        # other two filters narrow what the analyst asked for, but they must
        # never be able to widen what classification permits.
        if r.tlp_level in allowed
        and (ioc_type is None or r.type == ioc_type.value)
        and (r.confidence or 0.0) >= confidence_min
    ]

    return _render_export(ioc_dicts, fmt=export_format, tlp=ceiling.value)


# NOTE: ``/{ioc_id}`` MUST stay below the static-path GET routes
# (``/search``, ``/export``) — FastAPI matches in declaration order
# and a path-param route here would shadow them, so a request to
# ``GET /iocs/export`` would fall into ``get_ioc(ioc_id="export")``
# and 404 with "IOC not found".
@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get IOC detail with enrichment data."""
    user.require_permission("ioc:view")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    # AUTH-B1: scope via parent investigation. Out-of-scope -> 404 to avoid
    # leaking that the IOC ID exists.
    inv = await _load_investigation_or_404(db, row.investigation_id)
    assert_can_access_ioc(user, row, investigation=inv)

    return _to_response(row, mitre_tags=await _mitre_tags_for(db, ioc_id))


@router.post("", response_model=IOCResponse | list[IOCResponse], status_code=201)
async def create_ioc(
    body: CreateIOCRequest | BulkCreateIOCRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create one or more IOCs."""
    user.require_permission("ioc:create")

    # AUTH-B1: validate the caller can write to the parent investigation
    # before any rows are inserted. This closes the High-severity audit
    # finding where POST accepted any user-supplied investigation_id.
    inv = await _load_investigation_or_404(db, body.investigation_id)
    assert_can_access_investigation(user, inv, write=True)

    if isinstance(body, BulkCreateIOCRequest):
        rows = await ioc_service.create_iocs_bulk(
            db,
            investigation_id=body.investigation_id,
            iocs=[ioc.model_dump() for ioc in body.iocs],
            org_id=inv.org_id,
        )
        return [_to_response(r) for r in rows]

    row = await ioc_service.create_ioc(
        db,
        investigation_id=body.investigation_id,
        ioc_type=body.type,
        value=body.value,
        tlp_level=body.tlp_level,
        confidence=body.confidence,
        context=body.context,
        source=body.source,
        org_id=inv.org_id,
    )

    return _to_response(row)


@router.put("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: str,
    body: UpdateIOCRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update an existing IOC."""
    user.require_permission("ioc:edit")

    # AUTH-B1: scope check before mutation (closes the High-severity audit
    # finding where PUT updated any IOC). Load IOC + parent first, scope-check,
    # then apply the update.
    existing = await ioc_service.get_ioc(db, ioc_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IOC not found")
    inv = await _load_investigation_or_404(db, existing.investigation_id)
    assert_can_access_ioc(user, existing, investigation=inv, write=True)

    # Build update dict from non-None fields
    update_fields = {k: v for k, v in body.model_dump().items() if v is not None}

    if not update_fields:
        raise HTTPException(
            status_code=400,
            detail="No fields to update",
        )

    row = await ioc_service.update_ioc(db, ioc_id, **update_fields)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    return _to_response(row)


@router.patch("/{ioc_id}/annotate", response_model=IOCResponse)
async def annotate_ioc(
    ioc_id: str,
    body: AnnotateIOCRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update the IOC's notebook annotations (pin / tags / note / disposition).

    UC-5.2 (#108): analyst-owned metadata layered on the evidence record.
    Partial semantics — only fields present in the body change, and empty
    values clear a field. Requires ``ioc:edit``.
    """
    user.require_permission("ioc:edit")

    existing = await ioc_service.get_ioc(db, ioc_id)
    if not existing:
        raise HTTPException(status_code=404, detail="IOC not found")
    inv = await _load_investigation_or_404(db, existing.investigation_id)
    assert_can_access_ioc(user, existing, investigation=inv, write=True)

    # None means "not provided" (all fields default to None); explicit empty
    # values ("", []) are the way to clear a field.
    update_fields = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not update_fields:
        raise HTTPException(status_code=400, detail="No annotation fields supplied")

    row = await ioc_service.update_ioc(db, ioc_id, **update_fields)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    return _to_response(row)


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Soft-delete an IOC (set confidence to 0 and clear enrichment)."""
    user.require_permission("ioc:delete")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    # AUTH-B1: scope check before mutation.
    inv = await _load_investigation_or_404(db, row.investigation_id)
    assert_can_access_ioc(user, row, investigation=inv, write=True)

    # Soft delete: zero out confidence and mark as deleted in context
    await ioc_service.update_ioc(
        db,
        ioc_id,
        confidence=0.0,
        context=f"[DELETED] {row.context}",
        enrichment={},
    )

    return None


# --------------------------------------------------------------------------- #
# Enrichment Endpoints
# --------------------------------------------------------------------------- #


@router.post("/{ioc_id}/enrich", status_code=202)
async def trigger_enrich(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger enrichment for a single IOC.

    Returns 202 Accepted with task metadata. The enrichment runs
    asynchronously and results are written to the IOC's enrichment column.
    """
    user.require_permission("ioc:enrich")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    # AUTH-B1: scope check before triggering enrichment (writes to the IOC).
    inv = await _load_investigation_or_404(db, row.investigation_id)
    assert_can_access_ioc(user, row, investigation=inv, write=True)

    result = await ioc_service.trigger_enrichment(db, ioc_id)

    return result


@router.post("/bulk-enrich", status_code=202)
async def trigger_bulk_enrich(
    body: BulkEnrichRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger enrichment for multiple IOCs.

    Returns 202 Accepted with task metadata. Each IOC is enriched
    asynchronously in the background.
    """
    user.require_permission("ioc:enrich")

    # AUTH-B1: every IOC ID in the list must be in-scope; reject the whole
    # request if any one is not. We treat partial-success as a leak (caller
    # would learn which IDs exist by elimination).
    for ioc_id in body.ioc_ids:
        row = await ioc_service.get_ioc(db, ioc_id)
        if row is None:
            raise HTTPException(status_code=404, detail="IOC not found")
        inv = await _load_investigation_or_404(db, row.investigation_id)
        assert_can_access_ioc(user, row, investigation=inv, write=True)

    result = await ioc_service.trigger_bulk_enrichment(db, body.ioc_ids)

    return result


# --------------------------------------------------------------------------- #
# STIX Import / Export
# --------------------------------------------------------------------------- #


@router.post("/import", status_code=201)
async def import_stix(
    body: STIXImportRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Import IOCs from a STIX 2.1 JSON bundle.

    Parses the bundle, converts indicators to BTagent IOCs, and creates
    them in the specified investigation.
    """
    user.require_permission("ioc:create")

    # AUTH-B1: validate caller can write to the target investigation before
    # importing — otherwise a STIX bundle is a back door for cross-tenant
    # IOC creation.
    inv = await _load_investigation_or_404(db, body.investigation_id)
    assert_can_access_investigation(user, inv, write=True)

    ioc_dicts = stix_service.stix_to_iocs(
        body.bundle,
        investigation_id=body.investigation_id,
        source="stix_import",
    )

    if not ioc_dicts:
        return {"imported": 0, "message": "No valid indicators found in STIX bundle"}

    _reject_if_over_bulk_cap(len(ioc_dicts))

    rows = await ioc_service.create_iocs_bulk(
        db,
        investigation_id=body.investigation_id,
        iocs=ioc_dicts,
        org_id=inv.org_id,
    )

    return {
        "imported": len(rows),
        "ioc_ids": [r.id for r in rows],
        "investigation_id": body.investigation_id,
    }


# Valid IOC types — kept in sync with the frontend ``IOCImportModal``
# preview parser. Anything outside this set is dropped from the import
# rather than failing the whole bundle.
_VALID_IOC_TYPES = frozenset(
    {
        "ip",
        "domain",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "url",
        "email",
        "cve",
        "file_path",
        "other",
    }
)


def _parse_csv_rows(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse the import-modal CSV format into ``create_iocs_bulk`` dicts.

    Header columns (case-insensitive): ``type,value,source,confidence,tags``.
    First line is treated as a header if it contains ``type``, ``value`` or
    ``ioc`` — matches ``parseCSVPreview`` in ``IOCImportModal.tsx``.

    Returns ``(rows, skipped)`` where ``skipped`` counts lines that were
    parseable but failed validation (bad type, empty value).
    """
    rows: list[dict[str, Any]] = []
    skipped = 0
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return rows, 0

    first_lower = lines[0].lower()
    has_header = "type" in first_lower or "value" in first_lower or "ioc" in first_lower
    data_lines = lines[1:] if has_header else lines

    for line in data_lines:
        parts = [p.strip().strip('"') for p in line.split(",")]
        ioc_type = (parts[0] if parts else "").lower()
        value = parts[1] if len(parts) > 1 else ""
        source = parts[2] if len(parts) > 2 and parts[2] else "csv_import"
        confidence_raw = parts[3] if len(parts) > 3 and parts[3] else "0.5"
        try:
            confidence = float(confidence_raw)
        except ValueError:
            confidence = 0.5
        if not value or ioc_type not in _VALID_IOC_TYPES:
            skipped += 1
            continue
        rows.append(
            {
                "type": ioc_type,
                "value": value,
                "source": source,
                "confidence": max(0.0, min(1.0, confidence)),
            }
        )
    return rows, skipped


@router.post("/import/csv", status_code=201)
async def import_csv(
    body: TextImportRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Import IOCs from a CSV body (analyst-friendly path).

    Companion to ``/import/stix``. Same scoping + RBAC contract: the
    caller must hold ``ioc:create`` *and* write access on the target
    investigation. The CSV column convention matches the frontend's
    ``IOCImportModal`` preview parser: ``type,value,source,confidence,tags``.
    """
    user.require_permission("ioc:create")

    inv = await _load_investigation_or_404(db, body.investigation_id)
    assert_can_access_investigation(user, inv, write=True)

    parsed, skipped = _parse_csv_rows(body.data)
    if not parsed:
        return {
            "imported": 0,
            "skipped": skipped,
            "message": "No valid rows in CSV",
        }

    _reject_if_over_bulk_cap(len(parsed))

    rows = await ioc_service.create_iocs_bulk(
        db,
        investigation_id=body.investigation_id,
        iocs=parsed,
        org_id=inv.org_id,
    )

    return {
        "imported": len(rows),
        "skipped": skipped,
        "ioc_ids": [r.id for r in rows],
        "investigation_id": body.investigation_id,
    }


@router.post("/import/stix", status_code=201)
async def import_stix_text(
    body: TextImportRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Import IOCs from a STIX 2.1 JSON *string* (frontend transport).

    Mirrors ``/import`` but accepts ``body.data`` as a raw JSON string
    (what the import modal posts) instead of a pre-parsed ``bundle``.
    """
    import json as _json

    user.require_permission("ioc:create")

    inv = await _load_investigation_or_404(db, body.investigation_id)
    assert_can_access_investigation(user, inv, write=True)

    try:
        bundle = _json.loads(body.data)
    except _json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid STIX JSON: {exc}") from exc

    ioc_dicts = stix_service.stix_to_iocs(
        bundle,
        investigation_id=body.investigation_id,
        source="stix_import",
    )
    if not ioc_dicts:
        return {"imported": 0, "message": "No valid indicators found in STIX bundle"}

    _reject_if_over_bulk_cap(len(ioc_dicts))

    rows = await ioc_service.create_iocs_bulk(
        db,
        investigation_id=body.investigation_id,
        iocs=ioc_dicts,
        org_id=inv.org_id,
    )

    return {
        "imported": len(rows),
        "ioc_ids": [r.id for r in rows],
        "investigation_id": body.investigation_id,
    }
