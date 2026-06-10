"""Workflow service — CRUD + version lifecycle for the Phase 2 store.

Companion to :mod:`btagent_backend.db.models_workflow` and
:mod:`btagent_backend.api.v1.workflows`. This module is the *only* place
that mutates the ``workflows`` / ``workflow_versions`` tables — the API
routes call into the functions below, never into the ORM directly. That
discipline lets the version-publish lifecycle stay coherent (auto-
deprecate prior published version, single-version-published invariant)
without spreading the rule across N call sites.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from btagent_engine.compiler.workflow import Workflow as EngineWorkflow
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.types.workflow import WorkflowVersionState
from btagent_shared.utils.ids import generate_id
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_workflow import WorkflowRow, WorkflowVersionRow
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.services.workflow")


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Workflow (identity) CRUD
# --------------------------------------------------------------------------- #


async def create_workflow(
    db: AsyncSession,
    *,
    name: str,
    description: str,
    org_id: str,
    created_by: str | None,
    initial_definition: dict[str, Any] | None = None,
) -> tuple[WorkflowRow, WorkflowVersionRow]:
    """Create a new workflow + its first draft version (atomic).

    Returns the identity row and the freshly-minted ``version_number=1``
    draft. The caller can immediately ``PATCH`` the draft's definition or
    leave it empty until the author edits it on the canvas.
    """
    workflow_id = generate_id("wf")
    now = _utcnow()

    wf = WorkflowRow(
        id=workflow_id,
        name=name,
        description=description,
        org_id=org_id,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(wf)

    version = WorkflowVersionRow(
        id=generate_id("wfv"),
        workflow_id=workflow_id,
        version_number=1,
        state=WorkflowVersionState.DRAFT.value,
        definition=initial_definition or {},
        org_id=org_id,
        created_by=created_by,
        created_at=now,
    )
    db.add(version)
    await db.flush()
    return wf, version


async def get_workflow(db: AsyncSession, workflow_id: str) -> WorkflowRow | None:
    """Fetch a workflow identity row, no scoping check.

    Soft-deleted workflows are treated as gone: they return ``None`` here
    so every route that loads-then-scopes 404s them uniformly (list, get,
    versions, runs, lifecycle transitions). The row itself — and its
    versions / runs — stay in the DB as an audit trail, just unreachable
    through the API.
    """
    result = await db.execute(
        select(WorkflowRow).where(
            WorkflowRow.id == workflow_id,
            WorkflowRow.deleted_at.is_(None),
        )
    )
    return result.scalar_one_or_none()


async def list_workflows(
    db: AsyncSession,
    *,
    org_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[WorkflowRow], int]:
    """List workflows in the caller's org. Newest first. Excludes soft-deleted."""
    offset = (page - 1) * page_size

    count_q = (
        select(func.count())
        .select_from(WorkflowRow)
        .where(WorkflowRow.org_id == org_id, WorkflowRow.deleted_at.is_(None))
    )
    total = (await db.execute(count_q)).scalar_one() or 0

    rows_q = (
        select(WorkflowRow)
        .where(WorkflowRow.org_id == org_id, WorkflowRow.deleted_at.is_(None))
        .order_by(WorkflowRow.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).scalars().all()
    return list(rows), int(total)


async def update_workflow_metadata(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    name: str | None = None,
    description: str | None = None,
) -> WorkflowRow:
    """Patch a workflow's metadata. Caller has already scope-checked."""
    if name is not None:
        workflow.name = name
    if description is not None:
        workflow.description = description
    workflow.updated_at = _utcnow()
    await db.flush()
    return workflow


async def soft_delete_workflow(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    actor: str = "system",
) -> WorkflowRow:
    """Soft-delete a workflow (stamp ``deleted_at``). Caller has scope-checked.

    Versions and runs stay in the DB (audit trail) but become unreachable
    through the API — :func:`get_workflow` filters deleted rows, so every
    route that loads-then-scopes 404s the whole subtree. Recorded on the
    audit chain (category ``workflow`` / action ``delete``).
    """
    now = _utcnow()
    workflow.deleted_at = now
    workflow.updated_at = now
    await AuditTrail(db).record(
        actor=actor,
        category=AuditCategory.WORKFLOW,
        action="delete",
        resource=f"workflow:{workflow.id}",
        outcome=AuditOutcome.SUCCESS,
        details={"name": workflow.name, "org_id": workflow.org_id},
    )
    await db.flush()
    return workflow


# --------------------------------------------------------------------------- #
# Version CRUD
# --------------------------------------------------------------------------- #


async def get_version(
    db: AsyncSession, *, workflow_id: str, version_number: int
) -> WorkflowVersionRow | None:
    """Fetch a single version row."""
    result = await db.execute(
        select(WorkflowVersionRow).where(
            WorkflowVersionRow.workflow_id == workflow_id,
            WorkflowVersionRow.version_number == version_number,
        )
    )
    return result.scalar_one_or_none()


async def list_versions(
    db: AsyncSession,
    *,
    workflow_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[WorkflowVersionRow], int]:
    """Versions of a workflow, ordered oldest-first (version_number asc).

    Paginated like :func:`list_workflows`: returns ``(rows, total)`` where
    ``total`` is the full version count regardless of the page window.
    """
    offset = (page - 1) * page_size

    count_q = (
        select(func.count())
        .select_from(WorkflowVersionRow)
        .where(WorkflowVersionRow.workflow_id == workflow_id)
    )
    total = (await db.execute(count_q)).scalar_one() or 0

    rows_q = (
        select(WorkflowVersionRow)
        .where(WorkflowVersionRow.workflow_id == workflow_id)
        .order_by(WorkflowVersionRow.version_number.asc())
        .offset(offset)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).scalars().all()
    return list(rows), int(total)


async def _next_version_number(db: AsyncSession, workflow_id: str) -> int:
    """Read ``max(version_number) + 1`` for a workflow (race-prone by design;
    the DB unique constraint is the final arbiter — see :func:`create_version`)."""
    max_q = select(func.max(WorkflowVersionRow.version_number)).where(
        WorkflowVersionRow.workflow_id == workflow_id
    )
    current_max = (await db.execute(max_q)).scalar() or 0
    return int(current_max) + 1


async def _insert_version(
    db: AsyncSession,
    *,
    workflow_id: str,
    org_id: str,
    version_number: int,
    definition: dict[str, Any],
    created_by: str | None,
) -> WorkflowVersionRow:
    version = WorkflowVersionRow(
        id=generate_id("wfv"),
        workflow_id=workflow_id,
        version_number=version_number,
        state=WorkflowVersionState.DRAFT.value,
        definition=definition,
        org_id=org_id,
        created_by=created_by,
        created_at=_utcnow(),
    )
    db.add(version)
    await db.flush()
    return version


async def create_version(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    definition: dict[str, Any],
    created_by: str | None,
) -> WorkflowVersionRow:
    """Create a new draft version of an existing workflow.

    The next ``version_number`` is computed as ``max(existing) + 1``.
    Two concurrent writers can read the same max and collide on the
    ``uq_wfv_workflow_version`` unique constraint; the loser's insert
    raises :class:`IntegrityError`. Rather than surfacing that as a 500,
    we roll back and **auto-retry once** with a freshly-read number. If
    the retry collides too (pathological contention), raise
    :class:`ValueError` so the route returns 409 and the caller retries.
    """
    # Snapshot identity attrs up front: a mid-function rollback expires the
    # caller's ORM instance and lazy attribute refresh isn't await-safe here.
    workflow_id = workflow.id
    org_id = workflow.org_id

    next_number = await _next_version_number(db, workflow_id)
    try:
        version = await _insert_version(
            db,
            workflow_id=workflow_id,
            org_id=org_id,
            version_number=next_number,
            definition=definition,
            created_by=created_by,
        )
    except IntegrityError:
        # A concurrent writer claimed the slot between our max() read and the
        # flush. The session is poisoned after an IntegrityError — roll back
        # before retrying with a re-read number.
        await db.rollback()
        logger.info(
            "version_number race on workflow %s (lost slot %d); retrying once",
            workflow_id,
            next_number,
        )
        retry_number = await _next_version_number(db, workflow_id)
        try:
            version = await _insert_version(
                db,
                workflow_id=workflow_id,
                org_id=org_id,
                version_number=retry_number,
                definition=definition,
                created_by=created_by,
            )
        except IntegrityError as exc:
            await db.rollback()
            raise ValueError(
                f"Version number conflict on workflow {workflow_id}: another "
                f"writer is creating versions concurrently. Please retry."
            ) from exc

    # Re-fetch by id rather than touching the (possibly expired) caller
    # instance — safe in both the clean and the post-rollback path.
    wf_row = await db.get(WorkflowRow, workflow_id)
    if wf_row is not None:
        wf_row.updated_at = _utcnow()
    await db.flush()
    return version


async def update_version_definition(
    db: AsyncSession,
    *,
    version: WorkflowVersionRow,
    definition: dict[str, Any],
) -> WorkflowVersionRow:
    """Patch a draft version's definition. Published rows are immutable.

    Raises :class:`ValueError` if the version is not in the ``draft``
    state — the route layer surfaces this as 409 Conflict.
    """
    if version.state != WorkflowVersionState.DRAFT.value:
        raise ValueError(
            f"Version {version.version_number} is in state {version.state!r}; "
            f"only draft versions are editable."
        )
    version.definition = definition
    await db.flush()
    return version


# --------------------------------------------------------------------------- #
# Lifecycle transitions
# --------------------------------------------------------------------------- #


async def publish_version(
    db: AsyncSession,
    *,
    version: WorkflowVersionRow,
    actor: str = "system",
) -> WorkflowVersionRow:
    """Promote a draft to published.

    Maintains the *single-published-version-per-workflow* invariant:
    any previously published version of the same workflow is moved to
    ``deprecated`` with a stamped ``deprecated_at``. Raises
    :class:`ValueError` if the version is already published or already
    deprecated — the route layer surfaces this as 409.

    **Definition validation gates the publish transition** (and only the
    publish transition — drafts stay loose so authors can save partial
    canvas states): the JSONB ``definition`` must parse as an engine
    :class:`~btagent_engine.compiler.workflow.Workflow` or this raises
    :class:`ValueError` (→ 409 with the validation message).

    Both the publish and any implicit auto-deprecate of the prior
    published version are recorded on the audit chain (category
    ``workflow``, actions ``publish`` / ``auto_deprecate``).
    """
    if version.state == WorkflowVersionState.PUBLISHED.value:
        raise ValueError(f"Version {version.version_number} is already published.")
    if version.state == WorkflowVersionState.DEPRECATED.value:
        raise ValueError(
            f"Version {version.version_number} is deprecated; cannot republish. "
            f"Create a new draft instead."
        )

    # Gate: the definition must compile as an engine Workflow before it can
    # serve production traffic. ValidationError → ValueError → 409.
    try:
        EngineWorkflow.model_validate(version.definition or {})
    except ValidationError as exc:
        raise ValueError(
            f"Version {version.version_number} definition failed engine Workflow validation: {exc}"
        ) from exc

    now = _utcnow()
    trail = AuditTrail(db)

    # Move the current PUBLISHED version (if any) to DEPRECATED.
    prior_q = select(WorkflowVersionRow).where(
        WorkflowVersionRow.workflow_id == version.workflow_id,
        WorkflowVersionRow.state == WorkflowVersionState.PUBLISHED.value,
    )
    prior_rows = (await db.execute(prior_q)).scalars().all()
    for row in prior_rows:
        row.state = WorkflowVersionState.DEPRECATED.value
        row.deprecated_at = now
        await trail.record(
            actor=actor,
            category=AuditCategory.WORKFLOW,
            action="auto_deprecate",
            resource=f"workflow:{row.workflow_id}",
            outcome=AuditOutcome.SUCCESS,
            details={
                "version_number": row.version_number,
                "version_id": row.id,
                "superseded_by_version": version.version_number,
            },
        )

    version.state = WorkflowVersionState.PUBLISHED.value
    version.published_at = now
    await trail.record(
        actor=actor,
        category=AuditCategory.WORKFLOW,
        action="publish",
        resource=f"workflow:{version.workflow_id}",
        outcome=AuditOutcome.SUCCESS,
        details={"version_number": version.version_number, "version_id": version.id},
    )
    await db.flush()
    return version


async def deprecate_version(
    db: AsyncSession,
    *,
    version: WorkflowVersionRow,
    actor: str = "system",
) -> WorkflowVersionRow:
    """Explicit deprecate (admin path).

    Most deprecation happens implicitly on the next publish; this is the
    rarer manual case where an operator wants to retire a published
    version *without* promoting a new draft. Idempotent on already-
    deprecated rows; raises :class:`ValueError` if the version is still
    a draft (drafts are deleted, not deprecated). Recorded on the audit
    chain (category ``workflow``, action ``deprecate``).
    """
    if version.state == WorkflowVersionState.DRAFT.value:
        raise ValueError(f"Version {version.version_number} is a draft; delete it instead.")
    if version.state == WorkflowVersionState.DEPRECATED.value:
        return version  # idempotent

    version.state = WorkflowVersionState.DEPRECATED.value
    version.deprecated_at = _utcnow()
    await AuditTrail(db).record(
        actor=actor,
        category=AuditCategory.WORKFLOW,
        action="deprecate",
        resource=f"workflow:{version.workflow_id}",
        outcome=AuditOutcome.SUCCESS,
        details={"version_number": version.version_number, "version_id": version.id},
    )
    await db.flush()
    return version


async def get_published_version(db: AsyncSession, *, workflow_id: str) -> WorkflowVersionRow | None:
    """Fetch the single currently-published version of a workflow, if any."""
    result = await db.execute(
        select(WorkflowVersionRow).where(
            WorkflowVersionRow.workflow_id == workflow_id,
            WorkflowVersionRow.state == WorkflowVersionState.PUBLISHED.value,
        )
    )
    return result.scalar_one_or_none()
