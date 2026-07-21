"""SQLAlchemy ORM model for detection-validation run history (#118).

One table, ``detection_validation_runs`` — one row per persisted
``ValidationReport`` (the deterministic coverage report produced by
:func:`btagent_backend.services.validation_service.run_validation`). Analysts
diff coverage over time from this history; the report shape is otherwise a
transient return value.

The full per-technique ``coverage_by_technique`` payload is stored as JSONB so
the row is self-contained, while the summary pivots (``detected_pct``,
``total_techniques``, ``gaps``) are denormalised into columns so
history/trend queries never parse JSONB. Mirrors the ``plan_runs`` /
``hunt_pack_runs`` history-table convention.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class DetectionValidationRunRow(Base):
    """History of one detection-validation run (#118)."""

    __tablename__ = "detection_validation_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The report's own run identifier (``valrun_...``) — not unique per row on
    # its own (a caller could re-persist), so it is a queryable column, not a PK.
    run_id: Mapped[str] = mapped_column(String(200), nullable=False)
    # Builtin pack names the run validated against.
    packs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    scenarios_run: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Denormalised summary pivots (also inside coverage_by_technique / summary).
    total_techniques: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detected_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Technique IDs with at least one expected-to-fire event that was missed.
    gaps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Full per-technique CoverageResult payload (serialised list[dict]).
    coverage_by_technique: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # When the report was generated (report.generated_at) vs. when it landed.
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        # History lists are org-scoped and newest-first.
        Index("idx_detection_validation_runs_org_created", "org_id", "created_at"),
        Index("idx_detection_validation_runs_run_id", "org_id", "run_id"),
    )
