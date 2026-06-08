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

from btagent_shared.types.config import TLP


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


# --------------------------------------------------------------------------- #
# Execution / run history (Phase 2 — workflow run API)
# --------------------------------------------------------------------------- #


class WorkflowRunStatus(StrEnum):
    """Terminal (or, for the async follow-up, transitional) state of a run.

    The synchronous v1 API only ever persists the three terminal states;
    ``PENDING`` / ``RUNNING`` are reserved for the async/checkpoint path.

    * ``SUCCEEDED`` — the executor walked to a terminal leaf without error.
    * ``FAILED`` — a structural or node error stopped the walk.
    * ``PAUSED`` — a HITL gate suspended the run pending human approval
      (resume is a later sprint).
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PAUSED = "paused"


class RunWorkflowRequest(BaseModel):
    """Body for ``POST /workflows/{id}/versions/{n}/run``.

    ``trigger_payload`` is the workflow's input arguments — it flows into
    the entry node and is referenceable from any step's ``{{ ... }}``
    templates throughout the graph.

    ``active_tlp`` is the classification context the run executes under.
    It drives :class:`ConnectorPolicyMiddleware`'s TLP egress check —
    e.g. a capability declared ``tlp_egress=AMBER`` can only run when
    the active context is AMBER or lower. **Fail-closed default:** if a
    caller omits this field the route defaults it to ``TLP.RED`` so
    AMBER-only cloud lookups (GreyNoise, VirusTotal, …) are refused
    rather than silently allowed under an inferred GREEN. Callers
    triggering a run from a classified investigation must pass the
    investigation's classification here.
    """

    model_config = ConfigDict(extra="forbid")

    trigger_payload: dict[str, Any] = Field(default_factory=dict)
    active_tlp: TLP | None = Field(
        default=None,
        description=(
            "Classification context for the run. Precedence: this field "
            "(if set) -> the originating investigation's tlp_level (if "
            "``investigation_id`` is set) -> TLP.RED (fail-closed)."
        ),
    )
    investigation_id: str | None = Field(
        default=None,
        description=(
            "Originating investigation. When set, the run inherits the "
            "investigation's classification (unless ``active_tlp`` is also "
            "set, which wins), and the link is persisted on the run row so "
            "the analyst can pivot from history back to the investigation. "
            "The route org-scopes this id: cross-tenant lookups return 404."
        ),
    )


class WorkflowRunResponse(BaseModel):
    """A single execution record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workflow_id: str
    version_id: str
    version_number: int
    org_id: str
    triggered_by: str | None
    # Investigation the run was launched from, or null for an ad-hoc launch.
    investigation_id: str | None = None
    status: WorkflowRunStatus
    trigger_payload: dict[str, Any]
    outputs: dict[str, Any]
    final_output: dict[str, Any] | None
    nodes_executed: list[str]
    # Hash-linked audit trail (one entry per successful node run). Each
    # entry is the JSON form of an engine ``EvidenceRecord``.
    evidence_chain: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None
    created_at: datetime
    completed_at: datetime | None


class WorkflowRunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[WorkflowRunResponse]
    total: int


# --------------------------------------------------------------------------- #
# Node catalog (drives the canvas authoring palette)
# --------------------------------------------------------------------------- #


class NodeCatalogEntry(BaseModel):
    """One entry in the canvas-palette node catalog.

    Mirrors :class:`btagent_engine.node.NodeMeta` -- one item per Node class
    registered on the backend's ``NodeRegistry``. The canvas palette renders
    one card per entry so the analyst drags a real, resolvable ``node_id``
    onto the graph (no drift between a frontend hardcoded list and the
    backend registry).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="NodeRegistry id, e.g. 'integration.greynoise.lookup_ip'.")
    name: str = Field(..., description="Human-readable canvas label.")
    version: str
    category: str = Field(
        ...,
        description=(
            "Node category enum value: trigger / integration / reasoning / "
            "knowledge / decision / data / output."
        ),
    )
    description: str = ""


class NodeCatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[NodeCatalogEntry]
    total: int
