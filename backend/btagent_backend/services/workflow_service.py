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

from btagent_shared.types.workflow import WorkflowVersionState
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_workflow import WorkflowRow, WorkflowVersionRow

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
    """Fetch a workflow identity row, no scoping check."""
    result = await db.execute(select(WorkflowRow).where(WorkflowRow.id == workflow_id))
    return result.scalar_one_or_none()


async def list_workflows(
    db: AsyncSession,
    *,
    org_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[WorkflowRow], int]:
    """List workflows in the caller's org. Newest first."""
    offset = (page - 1) * page_size

    count_q = select(func.count()).select_from(WorkflowRow).where(WorkflowRow.org_id == org_id)
    total = (await db.execute(count_q)).scalar_one() or 0

    rows_q = (
        select(WorkflowRow)
        .where(WorkflowRow.org_id == org_id)
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


async def list_versions(db: AsyncSession, *, workflow_id: str) -> list[WorkflowVersionRow]:
    """All versions of a workflow, ordered oldest-first (version_number asc)."""
    rows = await db.execute(
        select(WorkflowVersionRow)
        .where(WorkflowVersionRow.workflow_id == workflow_id)
        .order_by(WorkflowVersionRow.version_number.asc())
    )
    return list(rows.scalars().all())


async def create_version(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    definition: dict[str, Any],
    created_by: str | None,
) -> WorkflowVersionRow:
    """Create a new draft version of an existing workflow.

    The next ``version_number`` is computed as ``max(existing) + 1``.
    The DB unique constraint ``(workflow_id, version_number)`` is the
    final tiebreaker if two writers race.
    """
    max_q = select(func.max(WorkflowVersionRow.version_number)).where(
        WorkflowVersionRow.workflow_id == workflow.id
    )
    current_max = (await db.execute(max_q)).scalar() or 0
    next_number = int(current_max) + 1

    version = WorkflowVersionRow(
        id=generate_id("wfv"),
        workflow_id=workflow.id,
        version_number=next_number,
        state=WorkflowVersionState.DRAFT.value,
        definition=definition,
        org_id=workflow.org_id,
        created_by=created_by,
        created_at=_utcnow(),
    )
    db.add(version)
    workflow.updated_at = _utcnow()
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
) -> WorkflowVersionRow:
    """Promote a draft to published.

    Maintains the *single-published-version-per-workflow* invariant:
    any previously published version of the same workflow is moved to
    ``deprecated`` with a stamped ``deprecated_at``. Raises
    :class:`ValueError` if the version is already published or already
    deprecated — the route layer surfaces this as 409.
    """
    if version.state == WorkflowVersionState.PUBLISHED.value:
        raise ValueError(f"Version {version.version_number} is already published.")
    if version.state == WorkflowVersionState.DEPRECATED.value:
        raise ValueError(
            f"Version {version.version_number} is deprecated; cannot republish. "
            f"Create a new draft instead."
        )

    now = _utcnow()

    # Move the current PUBLISHED version (if any) to DEPRECATED.
    prior_q = select(WorkflowVersionRow).where(
        WorkflowVersionRow.workflow_id == version.workflow_id,
        WorkflowVersionRow.state == WorkflowVersionState.PUBLISHED.value,
    )
    prior_rows = (await db.execute(prior_q)).scalars().all()
    for row in prior_rows:
        row.state = WorkflowVersionState.DEPRECATED.value
        row.deprecated_at = now

    version.state = WorkflowVersionState.PUBLISHED.value
    version.published_at = now
    await db.flush()
    return version


async def deprecate_version(
    db: AsyncSession,
    *,
    version: WorkflowVersionRow,
) -> WorkflowVersionRow:
    """Explicit deprecate (admin path).

    Most deprecation happens implicitly on the next publish; this is the
    rarer manual case where an operator wants to retire a published
    version *without* promoting a new draft. Idempotent on already-
    deprecated rows; raises :class:`ValueError` if the version is still
    a draft (drafts are deleted, not deprecated).
    """
    if version.state == WorkflowVersionState.DRAFT.value:
        raise ValueError(f"Version {version.version_number} is a draft; delete it instead.")
    if version.state == WorkflowVersionState.DEPRECATED.value:
        return version  # idempotent

    version.state = WorkflowVersionState.DEPRECATED.value
    version.deprecated_at = _utcnow()
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
