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

    __table_args__ = (
        Index("idx_workflows_org_id", "org_id"),
        Index("idx_workflows_created_at", "created_at"),
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
