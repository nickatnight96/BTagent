"""Pydantic schemas for the workflow CRUD store (Phase 2 v1).

These mirror :class:`btagent_backend.db.models_workflow.{WorkflowRow,WorkflowVersionRow}`
and are the request/response shapes for ``/api/v1/workflows``.

The *engine*'s :class:`btagent_engine.compiler.workflow.Workflow` is the
canonical *compiled* representation — it's what the runtime walks. We
persist its ``.model_dump()`` JSON in ``WorkflowVersionRow.definition``
and the API surfaces it back through the ``definition`` field on
:class:`WorkflowVersion`.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkflowVersionState(StrEnum):
    """Lifecycle state of a single :class:`WorkflowVersion` row.

    Transitions are one-way:

    * ``DRAFT`` → ``PUBLISHED`` via ``POST /workflows/{id}/versions/{n}/publish``.
      Exactly one version per workflow may sit in ``PUBLISHED`` at a time
      — publishing a new draft moves the previous one to ``DEPRECATED``.
    * ``PUBLISHED`` → ``DEPRECATED`` either by the auto-deprecate above or
      via ``POST /workflows/{id}/versions/{n}/deprecate`` (admin path).
    * ``DRAFT`` may be edited in place (PATCH) until it's published; once
      published the row is immutable.
    """

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


# --------------------------------------------------------------------------- #
# Request payloads
# --------------------------------------------------------------------------- #


class CreateWorkflowRequest(BaseModel):
    """Body for ``POST /workflows``.

    Creates a new workflow + its initial empty draft version. The caller
    typically follows up with a ``PATCH /workflows/{id}/versions/1`` to
    populate the definition before publishing.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=4096)
    # Optional starting definition. When omitted, the initial draft is
    # ``{}`` and the engine compiler will reject it on publish until the
    # author edits it into shape.
    definition: dict[str, Any] = Field(default_factory=dict)


class UpdateWorkflowRequest(BaseModel):
    """Body for ``PATCH /workflows/{id}`` (name/description metadata only).

    The definition lives on versions and is updated via the version
    endpoints.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=4096)


class CreateWorkflowVersionRequest(BaseModel):
    """Body for ``POST /workflows/{id}/versions`` (new draft).

    The service auto-assigns ``version_number`` as ``max(existing) + 1``
    so the caller can't race two parallel writes onto the same slot.
    """

    model_config = ConfigDict(extra="forbid")

    definition: dict[str, Any] = Field(default_factory=dict)


class UpdateWorkflowVersionRequest(BaseModel):
    """Body for ``PATCH /workflows/{id}/versions/{n}`` — draft-only edits."""

    model_config = ConfigDict(extra="forbid")

    definition: dict[str, Any]


# --------------------------------------------------------------------------- #
# Response payloads
# --------------------------------------------------------------------------- #


class WorkflowResponse(BaseModel):
    """Identity row only — fetch versions separately."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    org_id: str
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class WorkflowVersionResponse(BaseModel):
    """Full version row including the engine definition JSON."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workflow_id: str
    version_number: int
    state: WorkflowVersionState
    definition: dict[str, Any]
    org_id: str
    created_by: str | None
    created_at: datetime
    published_at: datetime | None
    deprecated_at: datetime | None


class WorkflowListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[WorkflowResponse]
    total: int


class WorkflowVersionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[WorkflowVersionResponse]
    total: int
