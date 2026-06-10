"""SQLAlchemy ORM models for the workflow CRUD store (Phase 2 v1).

The engine's :class:`btagent_engine.compiler.workflow.Workflow` is the
canonical *compiled* shape; this module persists the user-facing
**versioned** form of a workflow: a stable identity row plus an ordered
sequence of draft → published → deprecated definitions.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class WorkflowRow(Base):
    """A workflow's stable identity: name, description, ownership.

    The actual definition (DAG of nodes/edges + trigger) lives on the
    related :class:`WorkflowVersionRow` rows so authors can stage a new
    draft while a published version keeps serving production traffic.
    """

    __tablename__ = "workflows"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    # AUTH-B1: tenant scoping (matches investigations/iocs/evidence).
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    # Soft-delete marker (Phase 2 v2). NULL = live. Set rows are filtered out
    # of every API read path (list/get/versions/runs) but the row — and its
    # version/run children — stays in the DB as an audit trail.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_workflows_org_id", "org_id"),
        Index("idx_workflows_created_at", "created_at"),
        Index("idx_workflows_deleted_at", "deleted_at"),
    )


class WorkflowVersionRow(Base):
    """A specific version of a workflow's definition + its lifecycle state."""

    __tablename__ = "workflow_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # ``draft`` / ``published`` / ``deprecated`` — see
    # :class:`btagent_shared.types.workflow.WorkflowVersionState`.
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    # Engine ``Workflow`` Pydantic model, serialised via ``.model_dump()``.
    definition: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("workflow_id", "version_number", name="uq_wfv_workflow_version"),
        Index("idx_wfv_workflow_id", "workflow_id"),
        Index("idx_wfv_org_id", "org_id"),
        Index("idx_wfv_state", "state"),
    )


class WorkflowRunRow(Base):
    """One execution of a specific workflow version + its terminal outcome.

    Runs are synchronous in this first cut (the API executes the engine
    :class:`WorkflowExecutor` inline and persists a terminal row), so a
    row is written ``succeeded`` / ``failed`` / ``paused`` rather than
    transitioning through ``running``. The ``running`` status is reserved
    for the async/checkpoint follow-up.
    """

    __tablename__ = "workflow_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workflow_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    triggered_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Originating investigation, when the run was launched from one. Drives
    # active-TLP inheritance at the API layer and lets the analyst pivot
    # from a run row back to the investigation. NULL for ad-hoc launches.
    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    # ``pending`` / ``running`` / ``succeeded`` / ``failed`` / ``paused`` —
    # see :class:`btagent_shared.types.workflow.WorkflowRunStatus`.
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # Classification context the run executed under (drives ConnectorPolicy
    # TLP gating). Persisted so a resume reuses the same posture. Nullable for
    # rows created before the resume feature landed.
    active_tlp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Agent autonomy the run executed under ("L0".."L4", drives the HITL
    # gate). Inherited from the originating investigation at create time and
    # persisted so a resume reuses the same posture. Nullable for rows
    # created before autonomy inheritance landed (treated as L2).
    agent_autonomy: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # When status=paused, the step id the run is paused at (the node awaiting
    # approval). Cleared when the run reaches a terminal state.
    paused_node_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Step ids a human has approved across resume cycles; their HITL /
    # connector-policy gate is bypassed on subsequent executions.
    approved_steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    trigger_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Per-step output map (step_id -> JSON of that node's output model).
    outputs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Terminal leaf output (the last node with no outgoing edge), or null.
    final_output: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # In-order step ids the executor ran (replay / audit trail).
    nodes_executed: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Hash-linked audit trail per successful node run (one entry per step).
    # Each entry mirrors :class:`EvidenceRecord.model_dump(mode="json")`.
    evidence_chain: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_wfr_workflow_id", "workflow_id"),
        Index("idx_wfr_org_id", "org_id"),
        Index("idx_wfr_status", "status"),
        Index("idx_wfr_created_at", "created_at"),
        Index("idx_wfr_investigation_id", "investigation_id"),
    )
