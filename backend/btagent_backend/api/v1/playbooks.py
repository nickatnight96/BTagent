"""Playbook CRUD, validation, execution, and history endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_playbook import PlaybookExecutionRow, PlaybookRow
from btagent_backend.services.playbook_service import PlaybookService

logger = logging.getLogger("btagent.api.playbooks")

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

_service = PlaybookService()


# --------------------------------------------------------------------------- #
# Request / Response schemas
# --------------------------------------------------------------------------- #


class CreatePlaybookRequest(BaseModel):
    name: str
    yaml_content: str


class UpdatePlaybookRequest(BaseModel):
    yaml_content: str


class ValidatePlaybookRequest(BaseModel):
    yaml_content: str


class ExecutePlaybookRequest(BaseModel):
    trigger_data: dict[str, Any] = Field(default_factory=dict)
    investigation_id: str | None = None


class PlaybookResponse(BaseModel):
    id: str
    name: str
    version: str
    description: str
    trigger_type: str
    trigger_config: dict[str, Any]
    is_active: bool
    created_by: str | None
    created_at: str | None
    updated_at: str | None


class PlaybookDetailResponse(PlaybookResponse):
    yaml_content: str


class PlaybookListResponse(BaseModel):
    items: list[PlaybookResponse]
    total: int
    page: int
    page_size: int


class ValidationResponse(BaseModel):
    valid: bool
    errors: list[str]
    warnings: list[str]
    step_count: int


class ExecutionResponse(BaseModel):
    id: str
    playbook_id: str
    investigation_id: str | None
    status: str
    trigger_data: dict[str, Any]
    step_results: dict[str, Any]
    started_at: str | None
    completed_at: str | None
    error: str | None


class ExecutionListResponse(BaseModel):
    items: list[ExecutionResponse]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _to_playbook_response(row: PlaybookRow) -> PlaybookResponse:
    return PlaybookResponse(
        id=row.id,
        name=row.name,
        version=row.version,
        description=row.description,
        trigger_type=row.trigger_type,
        trigger_config=row.trigger_config or {},
        is_active=row.is_active,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _to_playbook_detail(row: PlaybookRow) -> PlaybookDetailResponse:
    return PlaybookDetailResponse(
        id=row.id,
        name=row.name,
        version=row.version,
        description=row.description,
        trigger_type=row.trigger_type,
        trigger_config=row.trigger_config or {},
        is_active=row.is_active,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        yaml_content=row.yaml_content,
    )


def _to_execution_response(row: PlaybookExecutionRow) -> ExecutionResponse:
    return ExecutionResponse(
        id=row.id,
        playbook_id=row.playbook_id,
        investigation_id=row.investigation_id,
        status=row.status,
        trigger_data=row.trigger_data or {},
        step_results=row.step_results or {},
        started_at=row.started_at.isoformat() if row.started_at else None,
        completed_at=(row.completed_at.isoformat() if row.completed_at else None),
        error=row.error,
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

# NOTE: /executions/{execution_id} must be registered BEFORE /{playbook_id}
# to avoid FastAPI matching "executions" as a playbook_id.


@router.get(
    "/executions/{execution_id}",
    response_model=ExecutionResponse,
)
async def get_execution_detail(
    execution_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get execution detail with step results."""
    user.require_permission("playbook:view")

    row = await _service.get_execution(db, execution_id)
    if not row:
        raise HTTPException(status_code=404, detail="Execution not found")

    return _to_execution_response(row)


@router.get("", response_model=PlaybookListResponse)
async def list_playbooks(
    active_only: bool = Query(True),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List playbooks with optional active filter and pagination."""
    user.require_permission("playbook:view")

    rows, total = await _service.list_playbooks(
        db, active_only=active_only, page=page, page_size=page_size
    )

    return PlaybookListResponse(
        items=[_to_playbook_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{playbook_id}", response_model=PlaybookDetailResponse)
async def get_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get playbook detail including YAML content."""
    user.require_permission("playbook:view")

    row = await _service.get_playbook(db, playbook_id)
    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return _to_playbook_detail(row)


@router.post("", response_model=PlaybookDetailResponse, status_code=201)
async def create_playbook(
    body: CreatePlaybookRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create a new playbook from name + YAML content.

    Requires playbook:create permission.
    """
    user.require_permission("playbook:create")

    try:
        row = await _service.create_playbook(
            db,
            name=body.name,
            yaml_str=body.yaml_content,
            user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return _to_playbook_detail(row)


@router.put("/{playbook_id}", response_model=PlaybookDetailResponse)
async def update_playbook(
    playbook_id: str,
    body: UpdatePlaybookRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update a playbook's YAML content."""
    user.require_permission("playbook:edit")

    try:
        row = await _service.update_playbook(db, playbook_id, body.yaml_content)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return _to_playbook_detail(row)


@router.delete(
    "/{playbook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Soft-delete (deactivate) a playbook."""
    user.require_permission("playbook:delete")

    deleted = await _service.deactivate_playbook(db, playbook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return None


@router.post(
    "/{playbook_id}/validate",
    response_model=ValidationResponse,
)
async def validate_playbook(
    playbook_id: str,
    body: ValidatePlaybookRequest,
    user: CurrentUser = Depends(get_current_user),
):
    """Validate YAML without saving. Returns validation result."""
    user.require_permission("playbook:view")

    result = _service.validate_playbook(body.yaml_content)

    return ValidationResponse(
        valid=result.valid,
        errors=result.errors,
        warnings=result.warnings,
        step_count=result.step_count,
    )


@router.post(
    "/{playbook_id}/execute",
    response_model=ExecutionResponse,
    status_code=201,
)
async def execute_playbook(
    playbook_id: str,
    body: ExecutePlaybookRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger a playbook execution.

    Requires playbook:execute permission.
    """
    user.require_permission("playbook:execute")

    try:
        execution = await _service.execute_playbook(
            db,
            playbook_id,
            trigger_data=body.trigger_data,
            investigation_id=body.investigation_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return _to_execution_response(execution)


@router.get(
    "/{playbook_id}/executions",
    response_model=ExecutionListResponse,
)
async def get_execution_history(
    playbook_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get execution history for a playbook."""
    user.require_permission("playbook:view")

    rows, total = await _service.get_execution_history(
        db, playbook_id, page=page, page_size=page_size
    )

    return ExecutionListResponse(
        items=[_to_execution_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
