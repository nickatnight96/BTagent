"""Investigation CRUD and lifecycle endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models import InvestigationRow
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.types.config import TLP
from btagent_shared.utils.ids import generate_id

router = APIRouter(prefix="/investigations", tags=["investigations"])


class CreateInvestigationRequest(BaseModel):
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    tlp_level: TLP = TLP.GREEN
    template: str | None = None


class InvestigationResponse(BaseModel):
    id: str
    case_id: str | None
    title: str
    description: str
    status: str
    severity: str
    tlp_level: str
    assigned_to: str | None
    template: str | None
    created_at: str | None
    updated_at: str | None
    closed_at: str | None


class InvestigationListResponse(BaseModel):
    items: list[InvestigationResponse]
    total: int
    page: int
    page_size: int


def _to_response(row: InvestigationRow) -> InvestigationResponse:
    return InvestigationResponse(
        id=row.id,
        case_id=row.case_id,
        title=row.title,
        description=row.description,
        status=row.status,
        severity=row.severity,
        tlp_level=row.tlp_level,
        assigned_to=row.assigned_to,
        template=row.template,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        closed_at=row.closed_at.isoformat() if row.closed_at else None,
    )


@router.post("", response_model=InvestigationResponse, status_code=201)
async def create_investigation(
    body: CreateInvestigationRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create a new investigation and start the agent."""
    user.require_permission("investigation:create")

    inv = InvestigationRow(
        id=generate_id("inv"),
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        tlp_level=body.tlp_level.value,
        template=body.template,
        assigned_to=user.id,
        status=InvestigationStatus.PENDING.value,
    )
    db.add(inv)
    await db.flush()

    # TODO: Start agent via TaskManager
    # await task_manager.start_investigation(inv.id, config)

    return _to_response(inv)


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List investigations with pagination and optional status filter."""
    user.require_permission("investigation:view")

    query = select(InvestigationRow).order_by(InvestigationRow.created_at.desc())
    count_query = select(func.count(InvestigationRow.id))

    if status_filter:
        query = query.where(InvestigationRow.status == status_filter)
        count_query = count_query.where(InvestigationRow.status == status_filter)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    rows = result.scalars().all()

    return InvestigationListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get investigation detail."""
    user.require_permission("investigation:view")

    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return _to_response(inv)


@router.post("/{investigation_id}/pause", status_code=200)
async def pause_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Pause a running investigation."""
    user.require_permission("investigation:pause")

    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.status not in (InvestigationStatus.INVESTIGATING, InvestigationStatus.TRIAGING):
        raise HTTPException(status_code=400, detail=f"Cannot pause investigation in status: {inv.status}")

    inv.status = InvestigationStatus.PAUSED.value
    # TODO: Signal TaskManager to checkpoint and pause

    return {"status": "paused", "investigation_id": investigation_id}


@router.post("/{investigation_id}/resume", status_code=200)
async def resume_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Resume a paused investigation."""
    user.require_permission("investigation:resume")

    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.status not in (InvestigationStatus.PAUSED, InvestigationStatus.PAUSED_HITL):
        raise HTTPException(status_code=400, detail=f"Cannot resume investigation in status: {inv.status}")

    inv.status = InvestigationStatus.INVESTIGATING.value
    # TODO: Resume via TaskManager from LangGraph checkpoint

    return {"status": "resumed", "investigation_id": investigation_id}


@router.post("/{investigation_id}/stop", status_code=200)
async def stop_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Stop a running investigation."""
    user.require_permission("investigation:stop")

    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    inv.status = InvestigationStatus.CANCELLED.value
    inv.closed_at = datetime.now(timezone.utc)
    # TODO: Signal TaskManager to stop agent

    return {"status": "cancelled", "investigation_id": investigation_id}


class ChatRequest(BaseModel):
    message: str


@router.post("/{investigation_id}/chat", status_code=200)
async def chat(
    investigation_id: str,
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Send a message to the investigation's agent."""
    user.require_permission("investigation:chat")

    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # TODO: Forward message to TaskManager → LangGraph
    return {"status": "sent", "investigation_id": investigation_id, "message": body.message}
