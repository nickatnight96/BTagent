"""Workflow CRUD + version lifecycle API (Phase 2 v1).

The route layer is thin — input validation via Pydantic, RBAC + org
scoping, and translation of service-layer ``ValueError`` into 409. All
mutation flows through :mod:`btagent_backend.services.workflow_service`
so the single-published-version-per-workflow invariant lives in one
place.
"""

from __future__ import annotations

import logging

from btagent_shared.types.config import TLP
from btagent_shared.types.workflow import (
    CreateWorkflowRequest,
    CreateWorkflowVersionRequest,
    RunWorkflowRequest,
    UpdateWorkflowRequest,
    UpdateWorkflowVersionRequest,
    WorkflowListResponse,
    WorkflowResponse,
    WorkflowRunListResponse,
    WorkflowRunResponse,
    WorkflowRunStatus,
    WorkflowVersionListResponse,
    WorkflowVersionResponse,
    WorkflowVersionState,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow, WorkflowVersionRow
from btagent_backend.services import workflow_run_service, workflow_service
from btagent_backend.services.workflow_run_service import WorkflowNotExecutable

logger = logging.getLogger("btagent.api.workflows")

router = APIRouter(prefix="/workflows", tags=["workflows"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _to_workflow_response(row: WorkflowRow) -> WorkflowResponse:
    return WorkflowResponse(
        id=row.id,
        name=row.name,
        description=row.description,
        org_id=row.org_id,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _to_version_response(row: WorkflowVersionRow) -> WorkflowVersionResponse:
    return WorkflowVersionResponse(
        id=row.id,
        workflow_id=row.workflow_id,
        version_number=row.version_number,
        state=WorkflowVersionState(row.state),
        definition=row.definition or {},
        org_id=row.org_id,
        created_by=row.created_by,
        created_at=row.created_at,
        published_at=row.published_at,
        deprecated_at=row.deprecated_at,
    )


async def _load_workflow_scoped(
    db: AsyncSession, workflow_id: str, user: CurrentUser
) -> WorkflowRow:
    """Fetch a workflow and 404 if either missing or not in caller's org.

    Returning 404 (not 403) for the cross-tenant case is intentional —
    we don't want to confirm-by-status-code that a workflow id exists in
    another tenant (matches the IDOR-mitigation pattern used by the
    investigations / IOC endpoints).
    """
    wf = await workflow_service.get_workflow(db, workflow_id)
    if wf is None or wf.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf


async def _load_version_scoped(
    db: AsyncSession, workflow: WorkflowRow, version_number: int
) -> WorkflowVersionRow:
    version = await workflow_service.get_version(
        db, workflow_id=workflow.id, version_number=version_number
    )
    if version is None:
        raise HTTPException(status_code=404, detail="Workflow version not found")
    return version


def _to_run_response(row: WorkflowRunRow) -> WorkflowRunResponse:
    return WorkflowRunResponse(
        id=row.id,
        workflow_id=row.workflow_id,
        version_id=row.version_id,
        version_number=row.version_number,
        org_id=row.org_id,
        triggered_by=row.triggered_by,
        status=WorkflowRunStatus(row.status),
        trigger_payload=row.trigger_payload or {},
        outputs=row.outputs or {},
        final_output=row.final_output,
        nodes_executed=row.nodes_executed or [],
        evidence_chain=row.evidence_chain or [],
        error=row.error,
        created_at=row.created_at,
        completed_at=row.completed_at,
    )


# --------------------------------------------------------------------------- #
# Workflow CRUD
# --------------------------------------------------------------------------- #


@router.post("", response_model=WorkflowResponse, status_code=201)
async def create_workflow(
    body: CreateWorkflowRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create a new workflow + its initial draft version 1."""
    user.require_permission("workflow:create")

    wf, _version = await workflow_service.create_workflow(
        db,
        name=body.name,
        description=body.description,
        org_id=user.org_id,
        created_by=user.id,
        initial_definition=body.definition,
    )
    return _to_workflow_response(wf)


@router.get("", response_model=WorkflowListResponse)
async def list_workflows(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List workflows in the caller's org (newest first)."""
    user.require_permission("workflow:view")
    rows, total = await workflow_service.list_workflows(
        db, org_id=user.org_id, page=page, page_size=page_size
    )
    return WorkflowListResponse(
        items=[_to_workflow_response(r) for r in rows],
        total=total,
    )


@router.get("/{workflow_id}", response_model=WorkflowResponse)
async def get_workflow(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("workflow:view")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    return _to_workflow_response(wf)


@router.patch("/{workflow_id}", response_model=WorkflowResponse)
async def update_workflow(
    workflow_id: str,
    body: UpdateWorkflowRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Patch workflow metadata (name / description only). Definition lives on versions."""
    user.require_permission("workflow:edit")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    wf = await workflow_service.update_workflow_metadata(
        db, workflow=wf, name=body.name, description=body.description
    )
    return _to_workflow_response(wf)


# --------------------------------------------------------------------------- #
# Version CRUD
# --------------------------------------------------------------------------- #


@router.get("/{workflow_id}/versions", response_model=WorkflowVersionListResponse)
async def list_versions(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("workflow:view")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    rows = await workflow_service.list_versions(db, workflow_id=wf.id)
    return WorkflowVersionListResponse(
        items=[_to_version_response(r) for r in rows],
        total=len(rows),
    )


@router.get(
    "/{workflow_id}/versions/{version_number}",
    response_model=WorkflowVersionResponse,
)
async def get_version(
    workflow_id: str,
    version_number: int,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("workflow:view")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await _load_version_scoped(db, wf, version_number)
    return _to_version_response(version)


@router.post(
    "/{workflow_id}/versions",
    response_model=WorkflowVersionResponse,
    status_code=201,
)
async def create_version(
    workflow_id: str,
    body: CreateWorkflowVersionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Stage a new draft version of the workflow.

    Auto-assigned ``version_number = max(existing) + 1``.
    """
    user.require_permission("workflow:edit")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await workflow_service.create_version(
        db,
        workflow=wf,
        definition=body.definition,
        created_by=user.id,
    )
    return _to_version_response(version)


@router.patch(
    "/{workflow_id}/versions/{version_number}",
    response_model=WorkflowVersionResponse,
)
async def update_version(
    workflow_id: str,
    version_number: int,
    body: UpdateWorkflowVersionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Patch a draft version's definition. 409 if already published."""
    user.require_permission("workflow:edit")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await _load_version_scoped(db, wf, version_number)
    try:
        version = await workflow_service.update_version_definition(
            db, version=version, definition=body.definition
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_version_response(version)


# --------------------------------------------------------------------------- #
# Lifecycle transitions
# --------------------------------------------------------------------------- #


@router.post(
    "/{workflow_id}/versions/{version_number}/publish",
    response_model=WorkflowVersionResponse,
)
async def publish_version(
    workflow_id: str,
    version_number: int,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Promote a draft → published. Auto-deprecates the prior published version."""
    user.require_permission("workflow:publish")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await _load_version_scoped(db, wf, version_number)
    try:
        version = await workflow_service.publish_version(db, version=version)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_version_response(version)


@router.post(
    "/{workflow_id}/versions/{version_number}/deprecate",
    response_model=WorkflowVersionResponse,
)
async def deprecate_version(
    workflow_id: str,
    version_number: int,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Explicit deprecate (admin path). 409 if the version is still a draft."""
    user.require_permission("workflow:deprecate")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await _load_version_scoped(db, wf, version_number)
    try:
        version = await workflow_service.deprecate_version(db, version=version)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_version_response(version)


# --------------------------------------------------------------------------- #
# Execution + run history
# --------------------------------------------------------------------------- #


@router.post(
    "/{workflow_id}/versions/{version_number}/run",
    response_model=WorkflowRunResponse,
    status_code=201,
)
async def run_version(
    workflow_id: str,
    version_number: int,
    body: RunWorkflowRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Execute a workflow version and persist a run record (UC: run API).

    Runs synchronously and returns the terminal run (``succeeded`` /
    ``failed`` / ``paused``). A 201 is returned even for a ``failed`` run:
    the execution attempt produced a durable record. 422 is reserved for
    the case where the version isn't a runnable graph at all (empty /
    malformed definition).

    **TLP fail-closed:** when ``body.active_tlp`` is omitted we default to
    ``TLP.RED`` (most restrictive) so an unconfigured caller cannot bypass
    the per-capability egress gate by silence. Callers triggering a run
    from a classified investigation must pass that investigation's
    classification on the request body.
    """
    user.require_permission("workflow:run")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    version = await _load_version_scoped(db, wf, version_number)
    try:
        run = await workflow_run_service.execute_version(
            db,
            workflow=wf,
            version=version,
            trigger_payload=body.trigger_payload,
            triggered_by=user.id,
            active_tlp=body.active_tlp if body.active_tlp is not None else TLP.RED,
        )
    except WorkflowNotExecutable as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _to_run_response(run)


@router.get("/{workflow_id}/runs", response_model=WorkflowRunListResponse)
async def list_runs(
    workflow_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List execution history for a workflow (newest first)."""
    user.require_permission("workflow:view")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    rows, total = await workflow_run_service.list_runs(
        db, workflow_id=wf.id, page=page, page_size=page_size
    )
    return WorkflowRunListResponse(items=[_to_run_response(r) for r in rows], total=total)


@router.get("/{workflow_id}/runs/{run_id}", response_model=WorkflowRunResponse)
async def get_run(
    workflow_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Fetch a single run record."""
    user.require_permission("workflow:view")
    wf = await _load_workflow_scoped(db, workflow_id, user)
    run = await workflow_run_service.get_run(db, run_id=run_id)
    # 404 (not 403) on cross-workflow / cross-tenant access — same posture
    # as the workflow IDOR mitigation above.
    if run is None or run.workflow_id != wf.id or run.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Workflow run not found")
    return _to_run_response(run)
